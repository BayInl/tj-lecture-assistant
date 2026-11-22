#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
server_app.py —— 同济高等讲堂·抢讲座 常驻服务
  · Flask WebUI : 看实时日志 / 配置(校级·院级 分别 监听+自动抢) / 校级列表手动抢 / 上传cookie / 测试钉钉
  · 后台引擎    : 校级默认只监听+钉钉提醒(不自动抢, 上 WebUI 手动选); 院级本院自动抢;
                  发现即锁定, 到各自 TimeSigningUp 猛攻; 院级"发布即开报/状态1"立即抢
  · keep-alive  : 每 keepalive_sec 轻量 ping(StudentInfo) 续命+探活; 检测 token.json 变化自动热加载
  · 钉钉推送    : 报名成功 / cookie失效 / 发现新目标 / 抢失败 (见 tj_config.json notify_events)

服务器(容器无 systemd, 用 ctl.sh watchdog 常驻):  bash ctl.sh start
本地试跑:              python server_app.py     然后浏览器开 http://127.0.0.1:8848
"""
import sys
import os
import copy
import json
import time
import hmac
import base64
import hashlib
import secrets
import getpass
import threading
import collections
import datetime as dt
import subprocess

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import lecture_grabber as g          # 复用全部逆向好的 API / 抢报逻辑
import notify as notify_mod          # 钉钉加签推送
from flask import Flask, request, jsonify, Response, make_response

BUNDLE_DIR = getattr(sys, "_MEIPASS", HERE)
DATA_DIR = os.path.abspath(
    os.environ.get("TJ_DATA_DIR")
    or (os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else HERE)
)
os.makedirs(DATA_DIR, exist_ok=True)

CFG_PATH = os.path.join(DATA_DIR, "tj_config.json")
TOKEN_PATH = os.path.join(DATA_DIR, "token.json")
WEBUI_PATH = os.path.join(BUNDLE_DIR, "webui.html")
LOGIN_PATH = os.path.join(BUNDLE_DIR, "login.html")
PICKED_PATH = os.path.join(DATA_DIR, "picked.json")   # 手选待抢清单持久化(重启不丢)
IGNORED_PATH = os.path.join(DATA_DIR, "ignored.json")  # 已移除忽略清单(移除的不再被引擎自动加回)
WON_PATH = os.path.join(DATA_DIR, "won.json")          # 已抢到的讲座(战利品), 供"已选到"卡片展示, 重启不丢

STOP = threading.Event()
LOCK = threading.RLock()

DEFAULT_CFG = {
    "dingtalk": {"webhook": "", "secret": "", "prefix": "【同济高等讲堂】",
                 "notify_events": ["success", "cookie_dead", "new_target", "grab_fail"]},
    "webui": {"host": "0.0.0.0", "port": 8848},
    "auth": {
        "enabled": True,
        "username": "",
        "password_hash": "",
        "session_secret": "",
        "session_ttl_sec": 604800,
        "session_version": 1,
        "api_token": "",
    },
    "keepalive_sec": 300,
    "grab": {"xiao_watch": True, "xiao_auto": False, "xiao_campus": "",
             "yuan_watch": True, "yuan_auto": True, "yuan_college_only": True,
             "yuan_campus": "",
             "keywords": [], "interval_sec": 30, "force": False},
}


def nowstr():
    return dt.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def _atomic_write_json(path, data, indent=2):
    """线程安全的原子写 JSON: 唯一临时文件 + flush/fsync + os.replace, 避免并发读到半截文件。"""
    tmp = "%s.tmp.%d.%d" % (path, os.getpid(), threading.get_ident())
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=indent)
            f.flush()
            try:
                os.fsync(f.fileno())
            except Exception:
                pass
        os.replace(tmp, path)
    finally:
        if os.path.exists(tmp):
            try:
                os.remove(tmp)
            except Exception:
                pass


# ==================== 配置 ====================
_CFG_CACHE_LOCK = threading.Lock()
_CFG_CACHE = {"sig": None, "data": None}


def _normalize_cfg(c):
    if not isinstance(c, dict):
        c = {}
    for k, v in DEFAULT_CFG.items():          # 轻量补齐缺省
        if k not in c:
            c[k] = copy.deepcopy(v)
        elif isinstance(v, dict):
            for kk, vv in v.items():
                c[k].setdefault(kk, copy.deepcopy(vv) if isinstance(vv, (dict, list)) else vv)
    return c


def load_cfg(readonly=False):
    try:
        st = os.stat(CFG_PATH)
        sig = (st.st_mtime_ns, st.st_size)
    except OSError:
        sig = None
    with _CFG_CACHE_LOCK:
        if sig is not None and _CFG_CACHE["sig"] == sig and _CFG_CACHE["data"] is not None:
            return _CFG_CACHE["data"] if readonly else copy.deepcopy(_CFG_CACHE["data"])
    try:
        with open(CFG_PATH, encoding="utf-8") as f:
            raw = json.load(f)
    except Exception:
        raw = {}
    c = _normalize_cfg(raw)
    with _CFG_CACHE_LOCK:
        if sig is not None:
            _CFG_CACHE["sig"] = sig
            _CFG_CACHE["data"] = c
    return c if readonly else copy.deepcopy(c)


def save_cfg(c):
    _atomic_write_json(CFG_PATH, c, indent=2)
    try:
        st = os.stat(CFG_PATH)
        sig = (st.st_mtime_ns, st.st_size)
    except OSError:
        sig = None
    with _CFG_CACHE_LOCK:
        _CFG_CACHE["sig"] = sig
        _CFG_CACHE["data"] = copy.deepcopy(c)


# ==================== 日志环形缓冲 + stdout Tee ====================
class LogBuf:
    def __init__(self, maxlen=4000):
        self.q = collections.deque(maxlen=maxlen)
        self.lock = threading.Lock()
        self.seq = 0

    def add(self, line):
        with self.lock:
            self.seq += 1
            self.q.append({"seq": self.seq,
                           "t": dt.datetime.now().strftime("%m-%d %H:%M:%S"),
                           "m": line})

    def since(self, seq=0, limit=1500):
        with self.lock:
            diff = self.seq - seq
            if diff <= 0 or not self.q:
                return []
            take = min(len(self.q), diff, limit)
            start = len(self.q) - take
            return [self.q[i] for i in range(start, len(self.q))]


LOGBUF = LogBuf()


class Tee:
    """把 stdout 同时写到真实控制台(systemd journal) 和内存环形缓冲(WebUI)。"""

    def __init__(self, orig):
        self.orig = orig

    def write(self, s):
        if isinstance(s, (bytes, bytearray)):      # werkzeug 有时写 bytes 到 stdout
            try:
                s = bytes(s).decode("utf-8", "replace")
            except Exception:
                s = str(s)
        try:
            self.orig.write(s)
            self.orig.flush()
        except Exception:
            pass
        try:
            for ln in str(s).splitlines():
                if ln.strip():
                    LOGBUF.add(ln)
        except Exception:
            pass

    def flush(self):
        try:
            self.orig.flush()
        except Exception:
            pass


def log(msg):
    print(msg)          # 经 Tee -> 环形缓冲 + journal


# ==================== 运行状态 ====================
STATE = {
    "started_at": nowstr(),
    "cookie": {"present": False, "session_id": "", "captured_at": "", "valid": None,
               "last_check": "", "age_sec": None, "student": {}},
    "engine": {"running": False, "round": 0, "last_scan": "", "offset": 0.0,
               "scanned": 0, "locked": {}, "fired": [], "candidates": [], "ignored": [], "won": []},
    "college": {"code": "", "name": ""},
    "events": [],
    "token_file_mtime": 0,
}
_DEAD = {"notified": False, "streak": 0}
DEAD_STREAK = 2          # 连续 N 次"明确失效"才告警(单次网络抖动/state非success 不误报)
MAX_GRAB_RETRY = 4       # 硬拦截(无资格/人脸)重试上限: 达上限标 failed; 名额已满/超时不计入此上限


# ==================== WebUI 认证 & 防撞库 ====================
SESSION_COOKIE_NAME = "tj_session"
PBKDF2_ITERS = 260000
_REVOKED_JTIS = {}       # jti -> exp_ts (退出登录立即吊销)
_REVOKED_LOCK = threading.Lock()


def _hash_password(password, salt_bytes=None):
    salt = salt_bytes if salt_bytes is not None else secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", str(password).encode("utf-8"), salt, PBKDF2_ITERS)
    return "pbkdf2_sha256$%d$%s$%s" % (PBKDF2_ITERS, salt.hex(), dk.hex())


def _verify_password(password, stored):
    try:
        algo, iters_s, salt_hex, hash_hex = str(stored or "").split("$", 3)
        if algo != "pbkdf2_sha256":
            raise ValueError("unsupported algo")
        iters = int(iters_s)
        salt = bytes.fromhex(salt_hex)
        expected = bytes.fromhex(hash_hex)
        actual = hashlib.pbkdf2_hmac("sha256", str(password).encode("utf-8"), salt, iters)
        return hmac.compare_digest(actual, expected)
    except Exception:
        # 无论是否已配置/格式错误，都执行一次等价哈希，避免时间侧信道泄露
        hashlib.pbkdf2_hmac("sha256", str(password).encode("utf-8"), b"dummy-salt-00000", PBKDF2_ITERS)
        return False


def _ensure_session_secret(cfg):
    auth = cfg.setdefault("auth", {})
    if not auth.get("session_secret"):
        auth["session_secret"] = secrets.token_hex(32)
        try:
            save_cfg(cfg)
        except Exception as e:
            log("[auth] 保存 session_secret 失败: %s" % e)
    return auth["session_secret"]


def _b64u_enc(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64u_dec(s):
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _make_session_token(username, cfg):
    auth = cfg.get("auth") or {}
    secret = _ensure_session_secret(cfg).encode("utf-8")
    ttl = max(300, int(auth.get("session_ttl_sec", 604800) or 604800))
    payload = {
        "u": username,
        "exp": int(time.time()) + ttl,
        "v": int(auth.get("session_version", 1) or 1),
        "jti": secrets.token_hex(8),
    }
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    p_b64 = _b64u_enc(raw)
    sig = hmac.new(secret, p_b64.encode("ascii"), hashlib.sha256).digest()
    return "%s.%s" % (p_b64, _b64u_enc(sig)), ttl


def _parse_session_token(token, cfg):
    if not token or "." not in token:
        return None
    auth = cfg.get("auth") or {}
    secret = str(auth.get("session_secret") or "")
    if not secret:
        return None
    p_b64, s_b64 = token.split(".", 1)
    try:
        expected = _b64u_enc(hmac.new(secret.encode("utf-8"), p_b64.encode("ascii"), hashlib.sha256).digest())
        if not hmac.compare_digest(s_b64, expected):
            return None
        payload = json.loads(_b64u_dec(p_b64).decode("utf-8"))
    except Exception:
        return None
    now = int(time.time())
    if int(payload.get("exp", 0)) <= now:
        return None
    if int(payload.get("v", -1)) != int(auth.get("session_version", 1) or 1):
        return None
    if not hmac.compare_digest(str(payload.get("u", "")).encode("utf-8"),
                                str(auth.get("username", "")).encode("utf-8")):
        return None
    jti = str(payload.get("jti", ""))
    with _REVOKED_LOCK:
        for k in [kk for kk, exp in _REVOKED_JTIS.items() if exp <= now]:
            del _REVOKED_JTIS[k]
        if jti in _REVOKED_JTIS:
            return None
    return payload


def _revoke_session_token(token, cfg):
    payload = _parse_session_token(token, cfg)
    if not payload:
        return
    jti = str(payload.get("jti", ""))
    exp = int(payload.get("exp", 0))
    if jti:
        with _REVOKED_LOCK:
            _REVOKED_JTIS[jti] = exp


class _AuthGuard:
    """登录/API令牌防撞库保护: 单 IP 递增冷却 + 全局短时熔断。"""
    def __init__(self):
        self._lock = threading.Lock()
        self._ips = {}
        self._global_fails = collections.deque()
        self._global_lock_until = 0.0

    def _prune(self, now):
        if len(self._ips) > 1000:
            stale = [ip for ip, st in self._ips.items()
                     if now - st["last_fail"] > 3600 and st["lock_until"] <= now]
            for ip in stale:
                del self._ips[ip]
        while self._global_fails and now - self._global_fails[0] > 60:
            self._global_fails.popleft()

    def check_allowed(self, ip):
        now = time.time()
        with self._lock:
            self._prune(now)
            wait = 0.0
            if self._global_lock_until > now:
                wait = max(wait, self._global_lock_until - now)
            st = self._ips.get(ip)
            if st and st["lock_until"] > now:
                wait = max(wait, st["lock_until"] - now)
            if wait > 0:
                return False, max(1, int(wait + 0.99))
            return True, 0

    def record_failure(self, ip):
        now = time.time()
        with self._lock:
            self._prune(now)
            st = self._ips.get(ip)
            if not st or (now - st["last_fail"] > 900):
                st = {"count": 0, "last_fail": now, "lock_until": 0.0}
            st["count"] += 1
            st["last_fail"] = now
            cnt = st["count"]
            lock_sec = 0
            if cnt >= 12:
                lock_sec = 900
            elif cnt >= 8:
                lock_sec = 300
            elif cnt >= 5:
                lock_sec = 60
            if lock_sec > 0:
                st["lock_until"] = max(st["lock_until"], now + lock_sec)
            self._ips[ip] = st

            self._global_fails.append(now)
            if len(self._global_fails) >= 15:
                self._global_lock_until = max(self._global_lock_until, now + 60)
                lock_sec = max(lock_sec, 60)
            return cnt, lock_sec

    def record_success(self, ip):
        with self._lock:
            self._ips.pop(ip, None)


_AUTH_GUARD = _AuthGuard()


def _client_ip():
    return request.remote_addr or "unknown"


def _auth_configured(cfg):
    auth = cfg.get("auth") or {}
    return bool(auth.get("username") and auth.get("password_hash"))


def _public_cfg(cfg):
    c = {k: v for k, v in cfg.items() if k != "auth"}
    auth = cfg.get("auth")
    if isinstance(auth, dict):
        c["auth"] = {
            "enabled": bool(auth.get("enabled", True)),
            "username": auth.get("username", ""),
            "configured": bool(auth.get("username") and auth.get("password_hash")),
            "has_api_token": bool(auth.get("api_token")),
        }
    return c


def _check_request_auth(cfg):
    """校验请求认证态。返回 (ok: bool, err_code: int, err_msg: str, retry_after: int)。"""
    auth = cfg.get("auth") or {}
    if not auth.get("enabled", True):
        return True, 200, "", 0
    if not _auth_configured(cfg):
        return False, 401, "尚未配置登录账号密码，请先设置", 0

    tok = request.cookies.get(SESSION_COOKIE_NAME, "")
    if tok and _parse_session_token(tok, cfg):
        return True, 200, "", 0

    api_tok = str(auth.get("api_token") or "")
    hdr_tok = request.headers.get("X-API-Token", "")
    if not hdr_tok:
        auth_hdr = request.headers.get("Authorization", "")
        if auth_hdr.startswith("Bearer "):
            hdr_tok = auth_hdr[7:].strip()
    if hdr_tok:
        ip = _client_ip()
        allowed, wait_sec = _AUTH_GUARD.check_allowed(ip)
        if not allowed:
            return False, 429, "尝试过于频繁，请 %d 秒后再试" % wait_sec, wait_sec
        if api_tok and hmac.compare_digest(hdr_tok.encode("utf-8"), api_tok.encode("utf-8")):
            _AUTH_GUARD.record_success(ip)
            return True, 200, "", 0
        cnt, lock_sec = _AUTH_GUARD.record_failure(ip)
        log("[auth] API Token 校验失败 ip=%s (连续第%d次)" % (ip, cnt))
        if lock_sec:
            return False, 429, "尝试过于频繁，请 %d 秒后再试" % lock_sec, lock_sec

    return False, 401, "未登录或会话已过期", 0


# ==================== 钉钉 ====================
def _push(event, text, at_all=False):
    with LOCK:
        STATE["events"].insert(0, {"t": nowstr(), "event": event, "text": text})
        STATE["events"] = STATE["events"][:60]
    cfg = load_cfg(readonly=True)
    # macOS 本地通知: 抢到/失效等事件即时弹窗(不依赖钉钉配置)
    try:
        if sys.platform == "darwin":
            events = (cfg.get("dingtalk") or {}).get("notify_events") or []
            if (not events) or (event in events):
                body = str(text).replace("\\", "\\\\").replace('"', '\\"')[:220]
                subprocess.run(["osascript", "-e",
                                'display notification "%s" with title "同济抢讲座" sound name "Glass"' % body],
                               capture_output=True, timeout=10)
                log("[通知] 本地通知已弹: %s" % event)
    except Exception:
        pass
    if ((cfg.get("dingtalk") or {}).get("webhook")):
        def _send_dt():
            try:
                res = notify_mod.notify(event, text, cfg=cfg, at_all=at_all)
                if res is not None:
                    log("[钉钉] %s -> %s" % (event, res.get("errmsg") if isinstance(res, dict) else res))
            except Exception as e:
                log("[钉钉] 推送异常 %s" % e)
        threading.Thread(target=_send_dt, daemon=True).start()


# ==================== cookie ====================
def _parse_cookie_ids(cookie):
    sid = wid = ""
    for part in (cookie or "").split(";"):
        part = part.strip()
        if part.startswith("PG.ASP.Session.ID="):
            sid = part.split("=", 1)[1]
        elif part.startswith("PG.ASP.WeiXinCode.ID="):
            wid = part.split("=", 1)[1]
    return sid, wid


def read_token_file():
    try:
        with open(TOKEN_PATH, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_picked():
    """把手选(manual)目标持久化到 picked.json, 服务重启后可恢复。"""
    try:
        with LOCK:
            data = {d: dict(v) for d, v in STATE["engine"]["locked"].items() if v.get("manual")}
        _atomic_write_json(PICKED_PATH, data, indent=2)
    except Exception as e:
        log("[picked] 保存失败 %s" % e)


def _save_ignored():
    """持久化忽略清单(ignored.json): 被移除的 did 不再被引擎自动发现/加回。"""
    try:
        with LOCK:
            data = list(STATE["engine"].get("ignored", []))
        _atomic_write_json(IGNORED_PATH, data, indent=None)
    except Exception as e:
        log("[ignored] 保存失败 %s" % e)


def _load_ignored():
    try:
        with open(IGNORED_PATH, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            with LOCK:
                STATE["engine"]["ignored"] = [str(d) for d in data]
            log("[ignored] 恢复忽略清单 %d 项" % len(data))
    except Exception:
        pass


def _save_won():
    """持久化已抢到的讲座(won.json), 供"已选到"卡片重启不丢。"""
    try:
        with LOCK:
            data = [dict(w) for w in STATE["engine"].get("won", [])]
        _atomic_write_json(WON_PATH, data, indent=2)
    except Exception as e:
        log("[won] 保存失败 %s" % e)


def _load_won():
    try:
        with open(WON_PATH, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            with LOCK:
                STATE["engine"]["won"] = data[:50]
            log("[won] 恢复已选到讲座 %d 项" % len(data))
    except Exception:
        pass


def _won_signed_state(did):
    """核对已抢到讲座当前是否仍在官方报名名单。
    权威信号 = 详情 XSSigningUp(我的报名时间): 报上即非空且长期保留, 官方取消后立即清空
    (实测对照: 未取消的 9/18 报上多日仍非空; 已取消的当天即变 None)。
    GetSginInTime 不可信: 取消后仍保留旧 state=1/signUpTime, 会假阳性。
    True=在报; False=详情成功且 XSSigningUp 已空=确认已取消; None=详情拉取失败, 不下结论。"""
    try:
        d = (g.api_hall(did).get("data") or {})
        if d:
            return bool(d.get("XSSigningUp"))
    except Exception:
        pass
    return None


_ENDED_WON_DIDS = set()


def _won_remind_check():
    """已抢到的讲座: 距开讲 <=2 小时 -> 提醒一次(防错过)。
    只提醒一次(标记 reminded 持久化到 won.json); 已开讲的(remain<=0)缓存跳过避免每轮 strptime。"""
    if not g.COOKIE:
        return
    now = time.time()
    pending = []
    with LOCK:
        for w in STATE["engine"].get("won", []):
            did = str(w.get("did") or "")
            if w.get("reminded") or w.get("cancelled") or (did and did in _ENDED_WON_DIDS):
                continue
            lt = str(w.get("ltime") or "")
            try:
                start = dt.datetime.strptime(lt.split("~")[0].strip(), "%Y-%m-%d %H:%M").timestamp()
            except Exception:
                continue
            diff = start - now
            if diff <= 0:
                if did:
                    _ENDED_WON_DIDS.add(did)
                continue
            if diff <= 7200:
                pending.append(w)
    for w in pending:
        venue = ""
        try:
            dd = (g.api_hall(w.get("did")).get("data") or {})
            venue = str(dd.get("Venue") or "")
        except Exception:
            pass
        _push("lecture_soon", "⏰ 讲座提醒(还有不到 2 小时):\n《%s》\n时间: %s\n地点: %s\n已为你报名成功, 记得参加!" % (
            str(w.get("title"))[:50], str(w.get("ltime") or "").replace("~", " 至 "), venue or "(见系统)"))
        with LOCK:
            for e in STATE["engine"]["won"]:
                if e.get("did") == w.get("did"):
                    e["reminded"] = True
        _save_won()
        log("[提醒] 已发开讲提醒: 《%s》" % str(w.get("title"))[:30])


def _lecture_ended(w, now_ts=None):
    """判断已抢到讲座是否已结束(按 ltime 解析结束时间, 无需再轮询核对是否退订)。"""
    lt = str(w.get("ltime") or "").strip()
    if not lt:
        return False
    now_ts = now_ts if now_ts is not None else time.time()
    try:
        if "~" in lt:
            start_s, end_part = lt.split("~", 1)
            start_dt = dt.datetime.strptime(start_s.strip(), "%Y-%m-%d %H:%M")
            end_part = end_part.strip()
            if len(end_part) <= 5 and ":" in end_part:
                hh, mm = map(int, end_part.split(":", 1))
                end_dt = start_dt.replace(hour=hh, minute=mm)
                if end_dt < start_dt:
                    end_dt += dt.timedelta(days=1)
            else:
                end_dt = dt.datetime.strptime(end_part, "%Y-%m-%d %H:%M")
            return now_ts > end_dt.timestamp()
        start_dt = dt.datetime.strptime(lt, "%Y-%m-%d %H:%M")
        return now_ts > (start_dt.timestamp() + 10800)
    except Exception:
        return False


def _won_verify():
    """定期核对已抢到清单: 仅核对未开讲/未结束的场次, 官方已查不到报名则标 cancelled。
    标记后: 列表"已抢到"变「续抢」按钮, 且引擎绝不自动重抢/捡漏, 直到用户主动点「续抢」。"""
    if not g.COOKIE:
        return
    try:
        with LOCK:
            won = [dict(w) for w in STATE["engine"].get("won", [])]
        now_ts = time.time()
        changed = False
        for w in won:
            did = str(w.get("did") or "")
            if not did or w.get("cancelled") or _lecture_ended(w, now_ts):
                continue
            stt = _won_signed_state(did)
            if stt is False:
                with LOCK:
                    for e in STATE["engine"]["won"]:
                        if e.get("did") == did:
                            e["cancelled"] = True
                            e["cancelled_at"] = nowstr()
                changed = True
                log("[won] ⚠️ 官方已无报名记录(疑似手动取消): 《%s》— 已标记, 不会自动重抢; 需要请在讲座列表点「续抢」"
                    % str(w.get("title"))[:30])
            elif stt is None:
                log("[won] 暂无法核对(网络抖动), 下轮重试: 《%s》" % str(w.get("title"))[:24])
        if changed:
            _save_won()
    except Exception as e:
        log("[won] 核对异常 %s" % e)


def _load_picked():
    """boot: 恢复手选待抢清单; 有 cookie 时立即重新武装临点场次, 无 cookie 时置 waiting 等上传后再抢。"""
    try:
        with open(PICKED_PATH, encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return
    if not isinstance(data, dict) or not data:
        return
    off = 0.0
    if g.COOKIE:
        try:
            off = g.server_offset()
        except Exception:
            pass
    now = g.srv_now(off)
    force = bool(load_cfg().get("grab", {}).get("force", False))
    rearmed = 0
    to_fire = []
    with LOCK:
        locked = STATE["engine"]["locked"]
        fired = STATE["engine"]["fired"]
        for did, v in data.items():
            if not isinstance(v, dict):
                continue
            v = dict(v)
            v.setdefault("manual", True)
            v.setdefault("auto", True)
            tgt = v.get("tgt") or now
            # 1) 先保留终态(success/failed/expired), 不被"报名窗口已久"覆盖(修复: 已报上的场被误标过期)
            if v.get("status") in ("success", "failed", "expired"):
                locked[did] = v
                continue
            # 2) 讲座时间已过 -> 过期退出(与引擎退出条件一致, 而非用报名开始时间)
            lts_e = v.get("lts_epoch") or 0
            if lts_e and now > lts_e + g.GRACE_PAST:
                v["status"] = "expired"
                locked[did] = v
                continue
            # 3) 仅在已有 cookie 且报名窗口仍新时立即开火; 无 cookie 时一律置 waiting 等待上传后由引擎接管
            if g.COOKIE and (tgt - now) <= g.LEAD + 1 and tgt >= now - g.GRACE_PAST:
                v["status"] = "grabbing"
                if did not in fired:
                    fired.append(did)
                to_fire.append((did, v.get("title", did)))
                rearmed += 1
            else:
                v["status"] = "waiting"
                if did in fired:
                    fired.remove(did)
            locked[did] = v
    for did, title in to_fire:
        threading.Thread(target=_grab_wrapper, args=(did, off, force, title), daemon=True).start()
    log("[picked] 恢复手选清单 %d 项(立即重新开火 %d 项)" % (len(data), rearmed))


def refresh_cookie_state(reload_disk=True):
    d = read_token_file() if reload_disk else {}
    with LOCK:
        cap = d.get("captured_at") or STATE["cookie"].get("captured_at", "")
        cookie = d.get("cookie", "") or g.COOKIE
    sid, _ = _parse_cookie_ids(cookie)
    age = None
    if cap:
        try:
            t0 = dt.datetime.strptime(cap, "%Y-%m-%d %H:%M:%S")
            age = round((dt.datetime.now() - t0).total_seconds())
        except Exception:
            pass
    with LOCK:
        STATE["cookie"].update(present=bool(cookie), session_id=sid, captured_at=cap, age_sec=age)
        if d.get("student") and not STATE["cookie"].get("student"):    # 心跳会用带 Name 的接口数据覆盖, 此处只在空时兜底
            STATE["cookie"]["student"] = d.get("student") or {}


def apply_cookie(cookie, meta=None, source="manual"):
    """先校验候选 Cookie 有效性再原子替换全局状态与 token.json, 防止无效串顶掉存活会话。"""
    cookie = (cookie or "").strip()
    if not cookie:
        return False, "空 cookie"
    sid, wid = _parse_cookie_ids(cookie)
    if not sid:
        return False, "Cookie 格式无效(缺少 PG.ASP.Session.ID)"
    meta = meta or {}
    try:
        r = g.api_student_info(cookie=cookie)
        alive = g.token_alive(r) and isinstance(r, dict) and r.get("state") == "success"
    except Exception as e:
        alive, r = False, {"state": "error", "msg": "校验异常 %s" % e}

    if not alive:
        with LOCK:
            had_valid = bool(g.COOKIE) and (STATE["cookie"].get("valid") is True)
            STATE["cookie"]["last_check"] = nowstr()
        msg = (r.get("msg") if isinstance(r, dict) else str(r)) or "校验未通过"
        if had_valid:
            log("[cookie] 新 cookie 校验失败(%s), 保留原有效会话 source=%s" % (msg, source))
        else:
            log("[cookie] 应用新 cookie source=%s 校验=无效 (%s)" % (source, msg))
        return False, msg

    d = read_token_file()
    d.update({"cookie": cookie, "session_id": sid, "weixin_code_id": wid,
              "captured_at": meta.get("captured_at") or nowstr(),
              "source": source, "host": "lecture.tongji.edu.cn"})
    if isinstance(r.get("data"), dict):
        d["student"] = r["data"]
    elif meta.get("student"):
        d["student"] = meta["student"]

    g.COOKIE = cookie
    g.reset_student_cache()
    try:
        _atomic_write_json(TOKEN_PATH, d, indent=2)
        mtime = os.path.getmtime(TOKEN_PATH)
    except Exception as e:
        mtime = 0
        log("[cookie] 写 token.json 失败: %s" % e)

    with LOCK:
        if mtime:
            STATE["token_file_mtime"] = mtime
        STATE["cookie"]["valid"] = True
        STATE["cookie"]["last_check"] = nowstr()
        if isinstance(r.get("data"), dict):
            STATE["cookie"]["student"] = r["data"]
        _DEAD["streak"] = 0
        _DEAD["notified"] = False
    refresh_cookie_state()
    log("[cookie] 应用新 cookie source=%s 校验=有效" % source)
    return True, r.get("data")


def watch_token_file():
    """检测 token.json 变化(如本地同步/上传) -> 热加载, 无需重启。"""
    try:
        m = os.path.getmtime(TOKEN_PATH)
    except Exception:
        return
    with LOCK:
        prev_m = STATE["token_file_mtime"]
    if m and m != prev_m:
        with LOCK:
            STATE["token_file_mtime"] = m
        d = read_token_file()
        ck = d.get("cookie", "")
        if ck and ck != g.COOKIE:
            log("[cookie] 检测到 token.json 变化, 热加载中…")
            apply_cookie(ck, meta=d, source="sync")


def _record_alive():
    with LOCK:
        _DEAD["streak"] = 0
        _DEAD["notified"] = False
        STATE["cookie"]["valid"] = True


def _record_dead_candidate(reason, source="keepalive"):
    with LOCK:
        _DEAD["streak"] = int(_DEAD.get("streak", 0)) + 1
        streak = _DEAD["streak"]
    log("[%s] 明确失效(%d/%d): %s" % (source, streak, DEAD_STREAK, reason))
    if streak >= DEAD_STREAK:
        _mark_dead("连续%d次判定失效: %s" % (streak, reason))


def _mark_dead(reason):
    should_notify = False
    with LOCK:
        STATE["cookie"]["valid"] = False
        STATE["cookie"]["last_check"] = nowstr()
        if not _DEAD["notified"]:
            _DEAD["notified"] = True
            should_notify = True
    log("[!!] Cookie 失效: %s" % reason)
    if should_notify:
        _push("cookie_dead", "会话 Cookie 已失效(%s)! 请在本地重抓后同步, 或在 WebUI 上传。" % reason)


# ==================== keep-alive ====================
def _sleep(sec):
    STOP.wait(max(1.0, float(sec)))


def _probe_cookie(retries=2):
    """探测 cookie: 'alive'=有效 / 'dead'=服务端明确判失效 / 'unknown'=网络抖动等非失效。
    只有 token_alive=False(服务端回'未登录/超时/40001')才算 dead;
    请求异常/超时/state 非 success 一律归 unknown(不改状态、不告警), 并短隔重试。"""
    for i in range(retries + 1):
        try:
            r = g.api_student_info()
        except Exception as e:
            log("[keepalive] 心跳请求异常(%d/%d): %s" % (i + 1, retries + 1, e))
            if i < retries:
                _sleep(3)
            continue
        if not g.token_alive(r):                       # 服务端明确判失效
            return "dead", (r.get("msg") if isinstance(r, dict) else "失效")
        if isinstance(r, dict) and r.get("state") == "success":
            with LOCK:
                if isinstance(r.get("data"), dict):
                    STATE["cookie"]["student"] = r["data"]
            return "alive", r.get("data")
        log("[keepalive] 心跳返回非 success(%d/%d): state=%s msg=%s" % (
            i + 1, retries + 1, (r.get("state") if isinstance(r, dict) else "?"),
            str(r.get("msg") if isinstance(r, dict) else r)[:60]))
        if i < retries:
            _sleep(3)
    return "unknown", "网络/服务端异常"


def keepalive_loop():
    log("[keepalive] 启动")
    while not STOP.is_set():
        cfg = load_cfg(readonly=True)
        ka = int(cfg.get("keepalive_sec", 300) or 300)
        try:
            watch_token_file()
        except Exception as e:
            log("[keepalive] watch_token_file 异常 %s" % e)
        if g.COOKIE:
            verdict, info = _probe_cookie()
            with LOCK:
                STATE["cookie"]["last_check"] = nowstr()
            if verdict == "alive":
                _record_alive()
            elif verdict == "dead":
                _record_dead_candidate(info, source="keepalive")
            else:                                      # unknown: 不改 valid, 不告警
                log("[keepalive] 心跳未知(网络/服务端抖动), 不计入失效、不改状态")
        else:
            with LOCK:
                _DEAD["streak"] = 0
                STATE["cookie"].update(valid=False, present=False)
        refresh_cookie_state(reload_disk=False)
        _sleep(ka)
    log("[keepalive] 已停止")


# ==================== 抢报包装(带钉钉) ====================
def _grab_wrapper(did, off, force, title):
    tag = "[%s] " % str(did)[:6]
    ok = False
    reason = "full_or_timeout"

    def _cancelled():
        """预调度等待期间, 目标被用户移除/状态异常 -> 终止等待, 不开火。"""
        with LOCK:
            vv = STATE["engine"]["locked"].get(did)
            return vv is None or vv.get("status") not in ("waiting", "grabbing")

    try:
        ok, reason = g.grab_one(did, off, force=force, tag=tag, cancel_check=_cancelled, return_reason=True)
    except Exception as e:
        log("%s抢报异常: %s" % (tag, e))
        reason = "full_or_timeout"
    hard_retry = False
    soft_retry = False
    fc_out = 0
    full_cnt = 0
    with LOCK:
        v = STATE["engine"]["locked"].get(did)
        if v is not None:
            if ok:
                v["status"] = "success"
                won = STATE["engine"].setdefault("won", [])
                if not any(w.get("did") == did for w in won):
                    won.insert(0, {"did": did, "title": v.get("title", title), "lvl": v.get("lvl", ""),
                                   "ltime": v.get("ltime", ""), "tsu": v.get("tsu", ""), "won_at": nowstr()})
                    STATE["engine"]["won"] = won[:50]
            elif reason == "expired":
                v["status"] = "expired"
                if did in STATE["engine"]["fired"]:
                    STATE["engine"]["fired"].remove(did)
            elif reason == "cancelled":
                if did in STATE["engine"]["fired"]:
                    STATE["engine"]["fired"].remove(did)
            elif reason == "hard_fail":
                fc_out = int(v.get("fail_count", 0)) + 1
                v["fail_count"] = fc_out
                if fc_out >= MAX_GRAB_RETRY:
                    v["status"] = "failed"          # 多次硬拦截(多为资格/人脸), 停止捡漏
                else:
                    v["status"] = "waiting"
                    hard_retry = True
                    if did in STATE["engine"]["fired"]:
                        STATE["engine"]["fired"].remove(did)
            else:
                # full_or_timeout / cookie_dead: 名额已满或超时抖动, 不计入硬失败上限, 持续监测捡漏
                full_cnt = int(v.get("full_retries", 0)) + 1
                v["full_retries"] = full_cnt
                v["status"] = "waiting"
                soft_retry = True
                if did in STATE["engine"]["fired"]:
                    STATE["engine"]["fired"].remove(did)
    _save_picked()
    if ok:
        _save_won()
        _push("success", "🎉 报名成功: %s (%s)" % (str(title)[:40], str(did)[:8]))
    elif reason == "cookie_dead":
        _record_dead_candidate("抢报接口返回登录失效", source="grab")
    elif hard_retry:
        log("%s硬拦截未成功(第%d/%d次), 暂挂起等待下轮" % (tag, fc_out, MAX_GRAB_RETRY))
    elif soft_retry:
        log("%s名额已满/超时(累计%d次), 继续挂起监测捡漏" % (tag, full_cnt))
    elif reason == "hard_fail":
        _push("grab_fail", "抢报未成功: %s (%s) — 多次触发资格/人脸拦截, 已停止" % (str(title)[:40], str(did)[:8]))


# ==================== 讲座详情(钉钉/日志用) ====================
def _fmt_ltime(x, lts):
    """讲座举办时间(起~止), 供列表展示。lts=LectureTimeStart, x 含 LectureTimeEnd。"""
    t = str(lts or "").replace("T", " ")[:16]              # 2026-09-19 18:30
    lte = str(x.get("LectureTimeEnd") or "").replace("T", " ")
    if lte and len(lte) >= 16:
        t += "~" + lte[11:16]                              # ~20:00
    return t


def _speaker(x):
    """从 _UploadUpload 海报文件名尽力提取主讲人(如 '2-汪品先（海洋）四平.jpg' -> '汪品先（海洋）')。"""
    try:
        arr = json.loads(x.get("_UploadUpload") or "[]")
        nm = arr[0].get("name", "") if arr else ""
    except Exception:
        nm = ""
    if not nm:
        return ""
    nm = nm.rsplit(".", 1)[0]
    if "-" in nm:
        nm = nm.split("-", 1)[1]
    for tail in ("四平", "嘉定", "沪西", "彰武", "微信图片"):
        nm = nm.replace(tail, "")
    return nm.strip()


_CAMPUS_BY_DID = {}          # did -> CampusCodeName(可能为空串=详情确实无此字段): 列表行无校区, 拉一次详情缓存
_CAMPUS_FAILS = {}           # did -> 连续拉详情失败次数(>=3 暂停重试, 避免死循环打详情)
_CAMPUS_WORDS = ("四平路", "嘉定", "沪西", "彰武", "沪北", "南区", "北区")   # Venue 兜底用校区词


def _hall_campus(did):
    """讲座校区(如 '嘉定校区'/'四平路校区'/'沪西校区'): 需拉详情(GetLectureHall)一次。
    命中缓存直接返回(含空值=详情确实无此字段, 不再重试); 拉取失败返回 ''(下轮重试, 连败3次暂停)。"""
    with LOCK:
        if did in _CAMPUS_BY_DID:
            return _CAMPUS_BY_DID[did]
        if _CAMPUS_FAILS.get(did, 0) >= 3:
            return ""
    try:
        d = (g.api_hall(did).get("data") or {})
        cp = str(d.get("CampusCodeName") or "")
        with LOCK:
            _CAMPUS_BY_DID[did] = cp         # 空也缓存: 详情确实没有, 不反复打
        return cp
    except Exception:
        with LOCK:
            _CAMPUS_FAILS[did] = _CAMPUS_FAILS.get(did, 0) + 1
        return ""


def _campus_display(did, x):
    """讲座列表展示用校区短名(如 '嘉定'): 权威 CampusCodeName 优先, 无则按 Venue 猜, 都没有返回 ''。"""
    with LOCK:
        cp = _CAMPUS_BY_DID.get(did) or ""
    if cp:
        return cp.replace("校区", "")
    venue = str(x.get("Venue") or "")
    for c in _CAMPUS_WORDS:
        if c in venue:
            return c
    return ""


def _campus_filler(uniq, k=6):
    """后台补齐校区缓存: 每次扫描最多 k 场未缓存的, 未结束(st!=4)优先。daemon 线程里跑。"""
    with LOCK:
        cands = [x for x in uniq if g._row_fields(x)[0]
                 and g._row_fields(x)[0] not in _CAMPUS_BY_DID
                 and _CAMPUS_FAILS.get(g._row_fields(x)[0], 0) < 3]
    cands.sort(key=lambda x: 0 if g._row_fields(x)[1] != 4 else 1)
    for x in cands[:max(1, k)]:
        try:
            _hall_campus(g._row_fields(x)[0])
        except Exception:
            pass


def _campus_ok(x, want):
    """场次校区是否匹配 want(如 '嘉定'/'四平路' 子串; 支持逗号分隔多校区 '嘉定,四平')。校级/院级统一走此逻辑:
    权威依据=详情 CampusCodeName(经 _hall_campus 缓存), Venue 仅作兜底(防个别详情字段缺失/误包含)。
    want 为空 -> 不限(True); 详情暂未取到且 Venue 也判不出校区 -> 严格不放行(避免误抢), 下轮重试。"""
    if not want:
        return True
    wants = [w.strip() for w in str(want).split(",") if w.strip()]
    if not wants:
        return True
    did = g._row_fields(x)[0]
    cp = _hall_campus(did)
    venue = str(x.get("Venue") or "")
    if cp:
        if any(w in cp for w in wants):
            return True
        if any(w in venue for w in wants):        # 兜底: CampusCodeName 未命中但 Venue 命中(防个别详情字段异常)
            return True
        return False
    # 详情取不到: 退回 Venue 判断; 判不出校区 -> 严格不放行(宁缺毋滥, 防止误抢四平/沪西等)
    if any(c in venue for c in _CAMPUS_WORDS + ("校区",)):
        return any(w in venue for w in wants)
    return False


def _lecture_brief(x):
    """讲座详细信息(多行), 用于钉钉推送与日志。"""
    did, st, title, tsu, lts, lvl = g._row_fields(x)
    cap = x.get("Capacity"); sign = x.get("SignupNum")
    left = (cap - sign) if (isinstance(cap, int) and isinstance(sign, int)) else None
    spk = _speaker(x); ven = x.get("Venue") or ""; lte = x.get("LectureTimeEnd") or ""
    t = str(lts).replace("T", " ")
    if lte:
        t += " ~ " + str(lte).replace("T", " ")[11:16]
    lines = ["《%s》 · %s" % (str(title)[:44], g.status_name(x))]
    if spk:
        lines.append("主讲: %s" % spk)
    if ven:
        lines.append("地点: %s" % ven)
    lines.append("报名开始: %s" % str(tsu).replace("T", " "))
    lines.append("讲座时间: %s" % t)
    if left is not None:
        lines.append("余位: %d / 容量 %d" % (left, cap))
    return "\n".join(lines)


# ==================== 引擎 ====================
def engine_loop():
    log("[engine] 启动")
    with LOCK:
        STATE["engine"]["running"] = True
    off = 0.0
    try:
        off = g.server_offset()
        log("[engine] 服务器时钟偏移 %.3fs" % off)
    except Exception as e:
        log("[engine] 时钟同步失败 %s" % e)
    with LOCK:
        STATE["engine"]["offset"] = off
    rnd = 0
    while not STOP.is_set():
        rnd += 1
        cfg = load_cfg(readonly=True)
        grab = cfg.get("grab", {})
        interval = int(grab.get("interval_sec", 30) or 30)
        force = bool(grab.get("force", False))
        kws = [k for k in (grab.get("keywords") or []) if str(k).strip()]
        xiao_watch = bool(grab.get("xiao_watch", True)); xiao_auto = bool(grab.get("xiao_auto", False))
        xiao_campus = str(grab.get("xiao_campus", "") or "").strip()   # 校级监听校区(空=不限)
        yuan_watch = bool(grab.get("yuan_watch", True)); yuan_auto = bool(grab.get("yuan_auto", True))
        yuan_only = bool(grab.get("yuan_college_only", True))
        yuan_campus = str(grab.get("yuan_campus", "") or "").strip()   # 院级监听校区(空=不限; 靠详情 CampusCodeName 判定)
        watch_levels = ([("校级", xiao_auto)] if xiao_watch else []) + ([("院级", yuan_auto)] if yuan_watch else [])
        auto_levels = {lvl for lvl, a in watch_levels if a}
        watch_set = {lvl for lvl, _a in watch_levels}
        with LOCK:
            STATE["engine"]["round"] = rnd
        if not g.COOKIE:
            if rnd == 1 or rnd % 20 == 0:
                log("[engine] 尚无 cookie, 等待本地 push_cookie.py 或 WebUI 上传…")
            _sleep(min(interval, 10))
            continue
        if not watch_set:
            if rnd == 1 or rnd % 20 == 0:
                log("[engine] 校级/院级监听均已关闭, 空转等待…")
            _sleep(min(interval, 10))
            continue
        if rnd % 10 == 0:
            try:
                off = g.server_offset(samples=3)
                with LOCK:
                    STATE["engine"]["offset"] = off
            except Exception:
                pass
        mc, mn = "", ""
        try:
            mc, mn = g.my_college()
        except Exception:
            pass
        with LOCK:
            STATE["college"] = {"code": mc, "name": mn}
        try:
            scan_st, scan_msg, uniq = g.scan_lectures_ex(statuses=(0,), max_pages=3, page_size=50, stop_when_ended=True)
        except Exception as e:
            scan_st, scan_msg, uniq = "error", str(e), None
        with LOCK:
            STATE["engine"]["last_scan"] = nowstr()
        if scan_st == "dead":
            _record_dead_candidate("扫描返回失效(%s)" % scan_msg, source="engine")
            _sleep(interval)
            continue
        if scan_st != "ok" or uniq is None:
            log("[engine] 扫描网络/服务端抖动(不计入失效): %s" % scan_msg)
            _sleep(interval)
            continue
        _record_alive()
        with LOCK:
            STATE["engine"]["scanned"] = len(uniq)
            won_ids = {w.get("did") for w in STATE["engine"].get("won", [])}
        now = g.srv_now(off)
        targets = {}
        for lvl in watch_set:
            use_college = mc if (yuan_only and lvl == "院级") else ""
            for kw in ([None] if not kws else kws):
                try:
                    cs = g._candidates(uniq, off, level=lvl, keyword=kw, my_college=use_college)
                except Exception:
                    cs = []
                for x, tgt, _delta in cs:
                    did = g._row_fields(x)[0]
                    if not did or did in won_ids:
                        continue                      # 已抢到(含被官方手动取消待续抢)的不再自动锁定/捡漏
                    _want = xiao_campus if lvl == "校级" else (yuan_campus if lvl == "院级" else "")
                    if not _campus_ok(x, _want):
                        continue                      # 校级/院级统一: 校区不符不监听
                    targets.setdefault(did, {"x": x, "tgt": tgt})
        for x in uniq:                                     # 已可报名(有余位)立即纳入
            did, st, title, tsu, lts, lvl = g._row_fields(x)
            if not did or st != 1 or lvl not in watch_set:
                continue
            if yuan_only and lvl == "院级" and mc and str(x.get("CollegeCode")) != str(mc):
                continue
            if kws and not any(k.lower() in str(title).lower() for k in kws):
                continue
            if did in won_ids:
                continue                              # 同上: 已抢到的不再自动纳入
            _want = xiao_campus if lvl == "校级" else (yuan_campus if lvl == "院级" else "")
            if not _campus_ok(x, _want):
                continue                              # 校区筛选统一(同上)
            targets.setdefault(did, {"x": x, "tgt": now})

        # ---- 新发现 -> 锁定 + 钉钉(校级提示手动选择) ----
        newly_locked = []
        for did, info in targets.items():
            x = info["x"]
            _, st, title, tsu, lts, lvl = g._row_fields(x)
            brief = _lecture_brief(x)
            already_open = (info["tgt"] - now) <= 0
            campus_nm = _hall_campus(did) if (xiao_campus or yuan_campus) else ""
            with LOCK:
                locked = STATE["engine"]["locked"]
                fired_set = set(STATE["engine"]["fired"])
                ignored_set = set(STATE["engine"].get("ignored", []))
                if did in fired_set or did in locked or did in ignored_set:
                    continue
                if not campus_nm:
                    campus_nm = _CAMPUS_BY_DID.get(did, "")
                locked[did] = {"title": str(title)[:60], "tsu": tsu, "lvl": lvl,
                               "tgt": info["tgt"], "locked_at": nowstr(),
                               "brief": brief, "open_notified": already_open,
                               "ltime": _fmt_ltime(x, lts), "lts_epoch": g.parse_cn_epoch(lts) or 0,
                               "manual": False, "auto": (lvl in auto_levels), "status": "waiting",
                               "campus": campus_nm}
            newly_locked.append((did, lvl, brief))
        for did, lvl, brief in newly_locked:
            log("[%s] [新发现·%s] %s" % (nowstr(), lvl, brief.replace("\n", " | ")))
            if lvl == "校级" and lvl not in auto_levels:
                _push("new_target", "🏫 新校级讲座(不自动抢, 请上 WebUI 手动选择):\n%s" % brief)
            else:
                _push("new_target", "🎯 发现新目标[%s]%s\n%s" % (
                    lvl, " · 将自动抢" if lvl in auto_levels else "", brief))

        # ---- 过期自动退出 + 到点自动抢 / 已开放监测捡漏 ----
        byid = {}
        for x in uniq:
            d0 = g._row_fields(x)[0]
            if d0:
                byid[d0] = x
        now2 = g.srv_now(off)
        with LOCK:
            locked_snap = {d: dict(v) for d, v in STATE["engine"]["locked"].items()}
            fired_snap = set(STATE["engine"]["fired"])
            STATE["engine"]["candidates"] = [
                {"did": d, "title": v["title"], "lvl": v["lvl"], "tsu": v["tsu"],
                 "ltime": v.get("ltime", ""), "campus": v.get("campus", ""),
                 "auto": v.get("auto", v["lvl"] in auto_levels), "manual": v.get("manual", False),
                 "status": v.get("status", "waiting"),
                 "countdown": round(v["tgt"] - now2)}
                for d, v in locked_snap.items() if v.get("status", "waiting") in ("waiting", "grabbing")]

        due = []
        for did, v in locked_snap.items():
            if v.get("status", "waiting") != "waiting" or did in fired_snap:
                continue
            x = byid.get(did)
            st = g._row_fields(x)[1] if x is not None else None
            lts_e = v.get("lts_epoch") or (g.parse_cn_epoch(g._row_fields(x)[4]) if x is not None else 0)
            # 过期: 已结束(st4) 或 讲座开始时间已过 -> 退出待抢清单
            if st == 4 or (lts_e and now2 > lts_e + g.GRACE_PAST):
                expired_now = False
                pruned = False
                ref_ts = lts_e or v.get("tgt") or now2
                stale_auto = (not v.get("manual")) and (now2 - ref_ts > 86400)
                with LOCK:
                    vv = STATE["engine"]["locked"].get(did)
                    if vv and vv.get("status") == "waiting":
                        if stale_auto:
                            del STATE["engine"]["locked"][did]
                            pruned = True
                        else:
                            vv["status"] = "expired"
                        expired_now = True
                    elif vv and vv.get("status") == "expired" and stale_auto:
                        del STATE["engine"]["locked"][did]
                        pruned = True
                if expired_now and not pruned:
                    log("[%s] [过期退出] %s %s (已结束/讲座时间已过)" % (nowstr(), str(did)[:8], str(v.get("title", ""))[:24]))
                continue
            if v.get("status") == "expired":
                ref_ts = (v.get("lts_epoch") or v.get("tgt") or now2)
                if not v.get("manual") and (now2 - ref_ts > 86400):
                    with LOCK:
                        STATE["engine"]["locked"].pop(did, None)
                continue
            remain_s = v["tgt"] - now2
            will_fire = bool(v.get("auto")) or (not v.get("manual") and v.get("lvl") in auto_levels)
            if remain_s > g.LEAD + 1:
                # 临点预调度: 距开抢 <= prearm 且会自动抢的目标提前交给 grab_one
                prearm = max(45, interval + 15)
                if not (will_fire and remain_s <= prearm):
                    continue
            if st == 2:                            # 已开放但列表显示已满 -> 监测捡漏, 本轮不抢(等他人退订)
                continue
            if st is None and (now2 - (v.get("tgt") or now2)) > g.GRACE_PAST:
                continue
            due.append(did)                        # 到点/已开放且有余位(或列表未刷新且仍在开报窗口) -> 抢

        for did in due:
            fire_title = ""
            fire_lvl = ""
            fire_manual = False
            notify_brief = ""
            action = None
            with LOCK:
                vv = STATE["engine"]["locked"].get(did)
                if not vv or vv.get("status", "waiting") != "waiting" or did in STATE["engine"]["fired"]:
                    continue
                fire_lvl = vv.get("lvl", "")
                fire_title = vv.get("title", "")
                fire_manual = bool(vv.get("manual"))
                if vv.get("auto") or (not fire_manual and fire_lvl in auto_levels):
                    STATE["engine"]["fired"].append(did)
                    vv["status"] = "grabbing"
                    action = "fire"
                elif not vv.get("open_notified"):
                    vv["open_notified"] = True
                    notify_brief = vv.get("brief") or fire_title
                    action = "notify"
            if action == "fire":
                log("\n[%s] >>> 到点自动开抢 [%s]%s %s %s" % (
                    nowstr(), fire_lvl, "(手选)" if fire_manual else "", str(did)[:8], str(fire_title)[:26]))
                threading.Thread(target=_grab_wrapper, args=(did, off, force, fire_title), daemon=True).start()
            elif action == "notify":
                log("\n[%s] ⏰ 校级已开报(不自动抢): %s — 请在 WebUI 校级列表点\"抢\"" % (nowstr(), str(fire_title)[:30]))
                _push("new_target", "⏰ 校级讲座已开报, 名额有限快去抢:\n%s\n(WebUI 校级列表点\"抢\", 或 python3 lecture_grabber.py grab %s)" % (notify_brief, did))

        if rnd % 5 == 1 or due:
            with LOCK:
                locked_cnt = len(STATE["engine"]["locked"])
                fired_set = set(STATE["engine"]["fired"])
                pend_cnt = sum(1 for d in STATE["engine"]["locked"] if d not in fired_set)
            log("[%s] 第%d轮: 扫描%d场 命中%d 锁定%d 待处理%d 自动抢=%s 校级校区=%s 院级校区=%s 偏移%.3fs" % (
                nowstr(), rnd, len(uniq), len(targets), locked_cnt, pend_cnt,
                (",".join(sorted(auto_levels)) or "无(全手动)"), (xiao_campus or "全部"),
                (yuan_campus or "全部"), off))
        _won_remind_check()                           # 每轮: 已抢到场次开讲前<=2h 提醒一次(防错过)
        if rnd % 10 == 0:
            _won_verify()                             # 定期核对已抢到清单(检测官方手动取消)
        _sleep(interval)
    with LOCK:
        STATE["engine"]["running"] = False
    log("[engine] 已停止")


# ==================== Flask ====================
app = Flask(__name__)


@app.before_request
def _auth_guard():
    if request.path in ("/", "/api/login", "/api/logout"):
        return None
    cfg = load_cfg(readonly=True)
    ok, code, msg, retry_after = _check_request_auth(cfg)
    if ok:
        return None
    if request.path.startswith("/api/") or request.headers.get("X-Requested-With") == "XMLHttpRequest":
        body = {"ok": False, "auth_required": True, "msg": msg}
        if retry_after:
            body["retry_after"] = retry_after
        resp = make_response(jsonify(body), code)
        if retry_after:
            resp.headers["Retry-After"] = str(retry_after)
        return resp
    return make_response("Unauthorized", code)


@app.route("/")
def index():
    cfg = load_cfg(readonly=True)
    ok, _, _, _ = _check_request_auth(cfg)
    if not ok:
        try:
            with open(LOGIN_PATH, encoding="utf-8") as f:
                return Response(f.read(), mimetype="text/html")
        except Exception:
            return "<h1>login.html 缺失</h1><p>请确认与 server_app.py 同目录。</p>", 500
    try:
        with open(WEBUI_PATH, encoding="utf-8") as f:
            return Response(f.read(), mimetype="text/html")
    except Exception:
        return "<h1>webui.html 缺失</h1><p>请确认与 server_app.py 同目录。</p>", 500


@app.route("/api/login", methods=["POST"])
def api_login():
    cfg = load_cfg(readonly=True)
    auth = cfg.get("auth") or {}
    if auth.get("enabled", True) and not _auth_configured(cfg):
        return jsonify({"ok": False, "not_configured": True,
                        "msg": "尚未配置登录账号密码，请先设置后再登录"}), 503

    ip = _client_ip()
    allowed, wait_sec = _AUTH_GUARD.check_allowed(ip)
    if not allowed:
        resp = make_response(jsonify({"ok": False, "retry_after": wait_sec,
                                      "msg": "尝试过于频繁，请 %d 秒后再试" % wait_sec}), 429)
        resp.headers["Retry-After"] = str(wait_sec)
        return resp

    data = request.get_json(silent=True) or {}
    user = str(data.get("username") or "").strip()
    pwd = str(data.get("password") or "")
    expected_user = str(auth.get("username") or "")
    expected_hash = str(auth.get("password_hash") or "")

    user_ok = bool(user) and hmac.compare_digest(user.encode("utf-8"), expected_user.encode("utf-8"))
    pwd_ok = _verify_password(pwd, expected_hash)
    if not (user_ok and pwd_ok):
        time.sleep(0.35)
        cnt, lock_sec = _AUTH_GUARD.record_failure(ip)
        log("[auth] 登录失败 ip=%s user=%s (连续第%d次%s)" % (
            ip, user or "-", cnt, (", 锁定 %ds" % lock_sec) if lock_sec else ""))
        if lock_sec:
            resp = make_response(jsonify({"ok": False, "retry_after": lock_sec,
                                          "msg": "尝试过于频繁，请 %d 秒后再试" % lock_sec}), 429)
            resp.headers["Retry-After"] = str(lock_sec)
            return resp
        return jsonify({"ok": False, "msg": "账号或密码错误"}), 401

    _AUTH_GUARD.record_success(ip)
    tok, ttl = _make_session_token(expected_user, cfg)
    is_https = request.is_secure or (request.headers.get("X-Forwarded-Proto", "").lower() == "https")
    resp = make_response(jsonify({"ok": True}))
    resp.set_cookie(SESSION_COOKIE_NAME, tok, max_age=ttl, httponly=True, samesite="Lax", secure=is_https)
    log("[auth] 登录成功 ip=%s user=%s" % (ip, expected_user))
    return resp


@app.route("/api/logout", methods=["POST"])
def api_logout():
    cfg = load_cfg(readonly=True)
    tok = request.cookies.get(SESSION_COOKIE_NAME, "")
    if tok:
        _revoke_session_token(tok, cfg)
    resp = make_response(jsonify({"ok": True}))
    resp.set_cookie(SESSION_COOKIE_NAME, "", max_age=0, httponly=True, samesite="Lax")
    return resp


@app.route("/api/status")
def api_status():
    with LOCK:
        ck = STATE["cookie"]
        eng = STATE["engine"]
        off = eng.get("offset") or 0.0
        now = g.srv_now(off)
        cands = [
            {"did": d, "title": v.get("title", ""), "lvl": v.get("lvl", ""), "tsu": v.get("tsu", ""),
             "ltime": v.get("ltime", ""),
             "auto": v.get("auto", False), "manual": v.get("manual", False),
             "status": v.get("status", "waiting"), "countdown": round((v.get("tgt") or now) - now)}
            for d, v in eng["locked"].items()
            if v.get("status", "waiting") in ("waiting", "grabbing")
        ]
        st = {
            "started_at": STATE["started_at"],
            "cookie": {
                "present": ck.get("present", False),
                "session_id": ck.get("session_id", ""),
                "captured_at": ck.get("captured_at", ""),
                "valid": ck.get("valid"),
                "last_check": ck.get("last_check", ""),
                "age_sec": ck.get("age_sec"),
                "student": dict(ck.get("student") or {}),
            },
            "engine": {
                "running": eng.get("running", False),
                "round": eng.get("round", 0),
                "last_scan": eng.get("last_scan", ""),
                "offset": off,
                "scanned": eng.get("scanned", 0),
                "fired": list(eng.get("fired") or []),
                "candidates": cands,
                "won": [dict(w) for w in (eng.get("won") or [])],
            },
            "college": dict(STATE["college"]),
            "events": [dict(e) for e in (STATE["events"] or [])],
        }
    st["cfg"] = _public_cfg(load_cfg(readonly=True))
    st["now"] = nowstr()
    return jsonify(st)


@app.route("/api/logs")
def api_logs():
    try:
        seq = int(request.args.get("since", 0) or 0)
    except ValueError:
        seq = 0
    lines = LOGBUF.since(seq)
    return jsonify({"lines": lines, "seq": (lines[-1]["seq"] if lines else seq)})


@app.route("/api/config", methods=["GET", "POST"])
def api_config():
    if request.method == "GET":
        return jsonify(_public_cfg(load_cfg(readonly=True)))
    c = load_cfg()
    data = request.get_json(silent=True) or {}
    grab = data.get("grab")
    if isinstance(grab, dict):
        for k in ("xiao_watch", "xiao_auto", "xiao_campus", "yuan_watch", "yuan_auto",
                  "yuan_college_only", "yuan_campus", "keywords", "interval_sec", "force"):
            if k in grab:
                c.setdefault("grab", {})[k] = grab[k]
        c.setdefault("grab", {}).pop("levels", None)      # 清理旧结构遗留键
        c["grab"].pop("auto", None)
    if "keepalive_sec" in data:
        c["keepalive_sec"] = int(data["keepalive_sec"])
    d = data.get("dingtalk")
    if isinstance(d, dict):
        for k in ("notify_events", "prefix", "webhook", "secret"):
            if k in d:
                c.setdefault("dingtalk", {})[k] = d[k]
    save_cfg(c)
    log("[config] 已更新 grab=%s keepalive=%s" % (json.dumps(c.get("grab"), ensure_ascii=False), c.get("keepalive_sec")))
    return jsonify({"ok": True, "cfg": _public_cfg(c)})


@app.route("/api/cookie", methods=["POST"])
def api_cookie():
    data = request.get_json(silent=True) or {}
    cookie = data.get("cookie", "")
    if not cookie and data.get("session_id"):
        cookie = "PG.ASP.Session.ID=%s; PG.ASP.WeiXinCode.ID=%s" % (
            data.get("session_id"), data.get("weixin_code_id", ""))
    meta = {"captured_at": data.get("captured_at"), "student": data.get("student")}
    alive, res = apply_cookie(cookie, meta=meta, source=data.get("source", "webui"))
    return jsonify({"ok": alive, "valid": alive, "result": res})


@app.route("/api/reload-cookie", methods=["POST"])
def api_reload():
    d = read_token_file()
    ck = d.get("cookie", "")
    if not ck:
        return jsonify({"ok": False, "valid": False, "msg": "token.json 无 cookie"})
    alive, res = apply_cookie(ck, meta=d, source="reload")
    return jsonify({"ok": alive, "valid": alive})


@app.route("/api/scan", methods=["POST"])
def api_scan():
    if not g.COOKIE:
        return jsonify({"ok": False, "msg": "无 cookie"})
    body = request.get_json(silent=True) or {}
    lvl_filter = str(body.get("level", "") or "").strip()      # 可选: 只看 校级/院级
    scan_st, scan_msg, uniq = g.scan_lectures_ex(statuses=(0,), max_pages=3, page_size=50)
    if scan_st == "dead":
        return jsonify({"ok": False, "msg": "cookie 失效(%s)" % scan_msg})
    if scan_st != "ok" or uniq is None:
        return jsonify({"ok": False, "msg": "扫描请求异常(%s)" % scan_msg})
    mc, _ = g.my_college()
    with LOCK:
        active = {d for d, v in STATE["engine"]["locked"].items()
                  if v.get("status") in ("waiting", "grabbing")}
        won_list = list(STATE["engine"].get("won", []))
        won_dids = {w.get("did") for w in won_list}
    won_map = {w.get("did"): w for w in won_list}
    rows = []
    for x in uniq:
        did, st, title, tsu, lts, lvl = g._row_fields(x)
        if lvl_filter and lvl != lvl_filter:
            continue
        cap = x.get("Capacity"); sign = x.get("SignupNum")
        left = (cap - sign) if (isinstance(cap, int) and isinstance(sign, int)) else None
        rows.append({"did": did, "st": st, "stn": g.status_name(x), "title": str(title)[:60],
                     "tsu": str(tsu).replace("T", " "), "lts": str(lts).replace("T", " "),
                     "ltime": _fmt_ltime(x, lts),
                     "lvl": lvl, "college": x.get("CollegeCode"),
                     "mine": (str(x.get("CollegeCode")) == str(mc)) if mc else False,
                     "venue": x.get("Venue") or "", "speaker": _speaker(x),
                     "cap": cap, "sign": sign, "left": left,
                     "campus": _campus_display(did, x),
                     "in_list": did in active, "won": did in won_dids,
                     "won_cancelled": bool((won_map.get(did) or {}).get("cancelled"))})
    rows.sort(key=lambda r: (r["st"] == 4, r["st"] == 2, str(r["tsu"])))   # 未结束优先, 可报名再先
    threading.Thread(target=_campus_filler, args=(uniq,), daemon=True).start()   # 后台补校区缓存
    with LOCK:
        STATE["engine"]["last_scan"] = nowstr()
        STATE["engine"]["scanned"] = len(uniq)
    return jsonify({"ok": True, "count": len(uniq), "shown": len(rows), "rows": rows[:200]})


def _arm_grab(did, title, tsu, lvl, force, ltime=""):
    """加入/更新待抢并视时机开火(手选「抢」与「续抢」共用):
    已开放(报名开始时刻已到)->立即开火; 未到点->加入待抢清单, 到点引擎自动开火。"""
    tgt = g.parse_cn_epoch(tsu) if tsu else None
    with LOCK:
        off = STATE["engine"].get("offset") or 0.0
        now = g.srv_now(off)
        if tgt is None:
            tgt = now
        locked = STATE["engine"]["locked"]
        fired = STATE["engine"]["fired"]
        ign = STATE["engine"].setdefault("ignored", [])
        if did in ign:
            ign.remove(did)                  # 手动抢 -> 移出忽略清单
        v = locked.get(did) or {}
        v.update({"title": title or v.get("title") or did, "tsu": tsu or v.get("tsu", ""),
                  "lvl": lvl or v.get("lvl", "校级"), "tgt": tgt, "manual": True, "auto": True,
                  "locked_at": v.get("locked_at") or nowstr(), "brief": v.get("brief", ""),
                  "ltime": ltime or v.get("ltime", ""), "open_notified": True})
        immediate = (tgt - now) <= g.LEAD + 1
        if immediate:
            v["status"] = "grabbing"
            if did not in fired:
                fired.append(did)
        else:
            v["status"] = "waiting"
            if did in fired:
                fired.remove(did)          # 重新武装(之前可能已开火/结束)
        locked[did] = v
        vt = v["title"]
    _save_picked()
    if immediate:
        log("[抢报] 已开放, 立即开火 did=%s title=%s force=%s" % (did[:8], vt, force))
        threading.Thread(target=_grab_wrapper, args=(did, off, force, vt), daemon=True).start()
        return {"ok": True, "mode": "立即抢报", "msg": "已开放, 立即开火, 结果见待抢清单/钉钉"}
    log("[抢报] 加入待抢清单, 到点自动开火 did=%s tgt=%s" % (did[:8], tsu))
    return {"ok": True, "mode": "到点自动抢", "msg": "已加入待抢清单, 到 %s 自动开火" % (tsu or "点")}


@app.route("/api/grab", methods=["POST"])
def api_grab():
    """手选抢报(WebUI 讲座列表点"抢"): 已开放->立即开火; 未来开报->加入待抢清单, 到点引擎自动开火。"""
    data = request.get_json(silent=True) or {}
    did = str(data.get("did", "") or "").strip()
    if not did:
        return jsonify({"ok": False, "msg": "缺少 did"})
    if not g.COOKIE:
        return jsonify({"ok": False, "msg": "无 cookie, 请先同步"})
    return jsonify(_arm_grab(did, str(data.get("title", "") or "")[:60], str(data.get("tsu", "") or ""),
                             str(data.get("lvl", "") or "校级"),
                             bool(data.get("force", load_cfg().get("grab", {}).get("force", False))),
                             ltime=str(data.get("ltime", "") or "")))


@app.route("/api/won", methods=["POST"])
def api_won():
    """已抢到清单操作:
       action=rearm  续抢: 官方已手动取消的讲座, 移出已抢到并重新武装(立即抢/监测捡漏), 恢复自动
       action=remove 移除: 仅从"已抢到"卡片清掉该条(不影响官方报名)"""
    data = request.get_json(silent=True) or {}
    act = str(data.get("action", "") or "")
    did = str(data.get("did", "") or "").strip()
    if not did:
        return jsonify({"ok": False, "msg": "缺少 did"})
    with LOCK:
        won = STATE["engine"].setdefault("won", [])
        entry = next((w for w in won if w.get("did") == did), None)
        if not entry:
            return jsonify({"ok": False, "msg": "不在已抢到清单"})
        won.remove(entry)
    _save_won()
    if act == "remove":
        log("[won] 已移除卡片: 《%s》" % str(entry.get("title"))[:30])
        return jsonify({"ok": True, "msg": "已移除"})
    if act == "rearm":
        if not g.COOKIE:
            with LOCK:                     # 无 cookie 抢不了, 放回去避免误删
                STATE["engine"].setdefault("won", []).insert(0, entry)
            _save_won()
            return jsonify({"ok": False, "msg": "无 cookie, 请先同步"})
        log("[续抢] 重新武装: 《%s》" % str(entry.get("title"))[:30])
        return jsonify(_arm_grab(did, str(entry.get("title", ""))[:60], str(entry.get("tsu", "") or ""),
                                 str(entry.get("lvl", "") or "校级"),
                                 bool(load_cfg().get("grab", {}).get("force", False)),
                                 ltime=str(entry.get("ltime", "") or "")))
    with LOCK:                             # 未知操作也放回
        STATE["engine"].setdefault("won", []).insert(0, entry)
    _save_won()
    return jsonify({"ok": False, "msg": "未知操作"})


@app.route("/api/pick", methods=["POST"])
def api_pick():
    """手选待抢清单管理:
       action=add    讲座列表点"抢"->预选加入待抢清单(绝不当场开火); 未到点->到点自动抢, 已开放->监测捡漏(有名额自动抢)
       action=remove 取消单项(除"正在抢报中"外都可移除, 取消后重归讲座列表可再点)
       action=clear  清空全部手选待抢项"""
    data = request.get_json(silent=True) or {}
    act = str(data.get("action", "remove"))
    did = str(data.get("did", "") or "").strip()

    if act == "add":                         # 讲座列表「加入待抢」: 只预选入清单, 绝不当场开火
        if not did:
            return jsonify({"ok": False, "msg": "缺少 did"})
        if not g.COOKIE:
            return jsonify({"ok": False, "msg": "无 cookie, 请先同步"})
        title = str(data.get("title", "") or "")[:60]
        tsu = str(data.get("tsu", "") or "")
        lvl = str(data.get("lvl", "") or "校级")
        ltime = str(data.get("ltime", "") or "")
        lts = str(data.get("lts", "") or "")
        tgt = g.parse_cn_epoch(tsu) if tsu else None
        with LOCK:
            off = STATE["engine"].get("offset") or 0.0
            now = g.srv_now(off)
            if tgt is None:
                tgt = now
            locked = STATE["engine"]["locked"]
            fired = STATE["engine"]["fired"]
            ign = STATE["engine"].setdefault("ignored", [])
            if did in ign:
                ign.remove(did)              # 重新纳入 -> 移出忽略
            already_open = (tgt - now) <= g.LEAD + 1
            v = locked.get(did) or {}
            keep = v.get("status") if v.get("status") in ("grabbing", "success") else "waiting"
            v.update({"title": title or v.get("title") or did, "tsu": tsu or v.get("tsu", ""),
                      "lvl": lvl or v.get("lvl", "校级"), "tgt": tgt, "manual": True,
                      # 未到点->到点自动抢; 已开放->监测捡漏(有余位自动抢, 满了等他人退订)
                      "auto": True,
                      "locked_at": v.get("locked_at") or nowstr(), "brief": v.get("brief", ""),
                      "ltime": ltime or v.get("ltime", ""),
                      "lts_epoch": g.parse_cn_epoch(lts) or v.get("lts_epoch", 0),
                      "open_notified": True, "status": keep})
            if keep == "waiting":
                v["fail_count"] = 0          # 重新加入 -> 清零捡漏失败计数
                if did in fired:
                    fired.remove(did)        # 重新武装
            locked[did] = v
            vt, vs = v["title"], v["status"]
        _save_picked()
        if vs != "waiting":
            return jsonify({"ok": True, "mode": "已在清单", "msg": "该项已在待抢清单(%s)" % vs})
        if already_open:
            log("[待抢] 加入清单(已开放, 监测捡漏) did=%s title=%s" % (did[:8], vt))
            return jsonify({"ok": True, "mode": "已加入待抢", "msg": "已开放报名, 已加入待抢清单监测捡漏(有名额自动抢)"})
        log("[待抢] 加入清单(未到点, 到点自动抢) did=%s tgt=%s" % (did[:8], tsu))
        return jsonify({"ok": True, "mode": "已加入待抢", "msg": "已加入待抢清单, 到 %s 自动开火; 可随时取消" % (tsu or "点")})

    with LOCK:
        locked = STATE["engine"]["locked"]
        fired = STATE["engine"]["fired"]
        if act == "clear":
            rm = [d for d, v in locked.items() if v.get("manual") and v.get("status") != "grabbing"]
            ign = STATE["engine"].setdefault("ignored", [])
            for d in rm:
                del locked[d]
                if d in fired:
                    fired.remove(d)
                if d not in ign:
                    ign.append(d)
            _save_picked()
            _save_ignored()
            return jsonify({"ok": True, "removed": len(rm)})
        if act == "remove":
            v = locked.get(did)
            if not v:
                return jsonify({"ok": False, "msg": "不在待抢清单"})
            if v.get("status") == "grabbing":
                return jsonify({"ok": False, "msg": "正在抢报中, 请稍候再取消"})
            del locked[did]
            if did in fired:
                fired.remove(did)
            ign = STATE["engine"].setdefault("ignored", [])
            if did not in ign:
                ign.append(did)              # 忽略: 引擎不再自动发现/加回
            _save_picked()
            _save_ignored()
            log("[待抢] 已取消 did=%s (加入忽略, 不再自动加回)" % did[:8])
            return jsonify({"ok": True})
    return jsonify({"ok": False, "msg": "未知 action"})


@app.route("/api/test-notify", methods=["POST"])
def api_test_notify():
    n = notify_mod.get_notifier(load_cfg(readonly=True))
    if not n:
        return jsonify({"ok": False, "msg": "未配置 dingtalk.webhook"})
    res = n.text("WebUI 测试推送 ✅ (%s)" % nowstr())
    return jsonify({"ok": res.get("errcode") == 0, "result": res})


@app.route("/api/engine", methods=["POST"])
def api_engine():
    data = request.get_json(silent=True) or {}
    act = data.get("action")
    if act == "reset":                       # 清空锁定/开火/手选记录(换 cookie 或重来)
        with LOCK:
            STATE["engine"]["locked"] = {}
            STATE["engine"]["fired"] = []
            STATE["engine"]["candidates"] = []
            STATE["engine"]["ignored"] = []
        _save_picked()
        _save_ignored()
        log("[engine] 已重置锁定/开火/手选/忽略清单")
        return jsonify({"ok": True})
    return jsonify({"ok": False, "msg": "未知 action"})


def _cli_set_auth(args):
    """命令行配置 WebUI 登录账号密码: python3 server_app.py --set-auth <username> [password]"""
    idx = args.index("--set-auth")
    rest = args[idx + 1:]
    username = rest[0].strip() if len(rest) >= 1 else input("WebUI 登录账号: ").strip()
    if not username:
        print("[!] 账号不能为空")
        sys.exit(2)
    if len(rest) >= 2:
        password = rest[1]
    else:
        p1 = getpass.getpass("WebUI 登录密码: ")
        p2 = getpass.getpass("再次输入确认密码: ")
        if p1 != p2:
            print("[!] 两次密码不一致")
            sys.exit(2)
        password = p1
    if len(password) < 6:
        print("[!] 密码长度至少 6 位")
        sys.exit(2)
    cfg = load_cfg()
    auth = cfg.setdefault("auth", {})
    auth["enabled"] = True
    auth["username"] = username
    auth["password_hash"] = _hash_password(password)
    auth["session_version"] = int(auth.get("session_version", 1) or 1) + 1
    if not auth.get("session_secret"):
        auth["session_secret"] = secrets.token_hex(32)
    if not auth.get("api_token"):
        auth["api_token"] = secrets.token_hex(24)
    save_cfg(cfg)
    print("[✓] 已更新 WebUI 登录凭据: username=%s (已加盐 PBKDF2-SHA256 哈希写入 %s)" % (username, CFG_PATH))
    print("[i] 脚本调用 api_token=%s (可用于 auto_regrab.sh / sync_events.sh 请求头 X-API-Token)" % auth["api_token"])


def main():
    if "--set-auth" in sys.argv[1:]:
        _cli_set_auth(sys.argv[1:])
        return
    cfg = load_cfg()
    if not _auth_configured(cfg) and os.environ.get("TJ_BOOTSTRAP_API_TOKEN"):
        auth = cfg.setdefault("auth", {})
        auth["enabled"] = True
        auth["username"] = (os.environ.get("TJ_BOOTSTRAP_USER") or "admin").strip()
        boot_pw = os.environ.get("TJ_BOOTSTRAP_PASSWORD") or secrets.token_hex(8)
        auth["password_hash"] = _hash_password(boot_pw)
        auth["api_token"] = os.environ["TJ_BOOTSTRAP_API_TOKEN"].strip()
        auth["session_secret"] = auth.get("session_secret") or secrets.token_hex(32)
        auth["session_version"] = int(auth.get("session_version", 1) or 1)
        save_cfg(cfg)
    _ensure_session_secret(cfg)
    sys.stdout = Tee(sys.__stdout__)          # 之后所有 print(含 lecture_grabber) 都进环形缓冲
    d = read_token_file()
    if d.get("cookie") and not g.COOKIE:
        g.COOKIE = d["cookie"]
    refresh_cookie_state()
    try:
        mtime = os.path.getmtime(TOKEN_PATH) if os.path.exists(TOKEN_PATH) else 0
        with LOCK:
            STATE["token_file_mtime"] = mtime
    except Exception:
        pass
    log("=" * 62)
    log("[boot] 同济高等讲堂·抢讲座服务启动  %s" % nowstr())
    log("[boot] 数据目录=%s  cookie %s  session=%s  学院=%s  WebUI鉴权=%s" % (
        DATA_DIR,
        "已加载" if g.COOKIE else "缺失(等待同步)",
        STATE["cookie"]["session_id"] or "-",
        (STATE["cookie"]["student"] or {}).get("FacultyNmae", "-"),
        "已配置" if _auth_configured(cfg) else "未设置(请先 --set-auth)"))
    # 无条件恢复持久化状态: 避免无 cookie 启动后热上传 cookie 导致 won/ignored/picked 丢失或被空列表覆盖
    try:
        _load_ignored()
        _load_won()
        _load_picked()
    except Exception as e:
        log("[boot] 恢复持久化清单异常 %s" % e)
    threading.Thread(target=keepalive_loop, daemon=True).start()
    threading.Thread(target=engine_loop, daemon=True).start()
    host = (os.environ.get("TJ_HOST") or cfg.get("webui", {}).get("host", "0.0.0.0")).strip()
    port = int(os.environ.get("TJ_PORT") or cfg.get("webui", {}).get("port", 8848))
    log("[boot] WebUI 监听 http://%s:%d  (本地访问可能需要 SSH 隧道)" % (host, port))
    log("=" * 62)
    try:
        from werkzeug.serving import WSGIRequestHandler
        WSGIRequestHandler.protocol_version = "HTTP/1.1"
        WSGIRequestHandler.timeout = 75
    except Exception:
        pass
    try:
        app.run(host=host, port=port, debug=False, use_reloader=False, threaded=True)
    finally:
        STOP.set()


if __name__ == "__main__":
    main()
