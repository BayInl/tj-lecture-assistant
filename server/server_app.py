#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
server_app.py —— 同济高等讲堂·抢讲座 常驻服务（单端口原生多用户版）
  · 单端口 WebUI & API : 默认监听 :8848，支持管理员开号 / 邀请码注册，按登录态与 X-API-Token 路由至独立用户上下文
  · 共享扫描 + 隔离抢报 : 后台每轮共享一次全校列表扫描与校区缓存，按每人各自策略/Cookie/学院隔离锁定并并发抢报
  · 完全向后兼容       : 主管理员账号自动沿用根目录 tj_config.json / token.json / won.json / picked.json / ignored.json
"""
import sys
import os
import re
import copy
import json
import time
import hmac
import base64
import shutil
import hashlib
import secrets
import getpass
import threading
import collections
import datetime as dt
import subprocess
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

HERE = os.path.dirname(os.path.abspath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

import lecture_grabber as g
import notify as notify_mod
from flask import Flask, request, jsonify, Response, make_response, g as flask_g

BUNDLE_DIR = getattr(sys, "_MEIPASS", HERE)
DATA_DIR = os.path.abspath(
    os.environ.get("TJ_DATA_DIR")
    or (os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else HERE)
)
os.makedirs(DATA_DIR, exist_ok=True)

CFG_PATH = os.path.join(DATA_DIR, "tj_config.json")
USERS_PATH = os.path.join(DATA_DIR, "users.json")
USERS_DIR = os.path.join(DATA_DIR, "users")
WEBUI_PATH = os.path.join(BUNDLE_DIR, "webui.html")
LOGIN_PATH = os.path.join(BUNDLE_DIR, "login.html")

STOP = threading.Event()
DEAD_STREAK = 2          # 连续 N 次"明确失效"才告警
MAX_GRAB_RETRY = 4       # 硬拦截(无资格/人脸)重试上限
USERNAME_RE = re.compile(r"^[a-zA-Z0-9_-]{2,24}$")

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
        "proxy_url": "",
    },
    "multi_user": {
        "allow_register": False,
        "invite_code": "",
        "cofire_throttle": True,
        "admin_priority": True,
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
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
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


def _normalize_cfg(raw):
    c = raw if isinstance(raw, dict) else {}
    for k, v in DEFAULT_CFG.items():
        if k not in c:
            c[k] = copy.deepcopy(v)
        elif isinstance(v, dict):
            if not isinstance(c[k], dict):
                c[k] = copy.deepcopy(v)
            else:
                for kk, vv in v.items():
                    c[k].setdefault(kk, copy.deepcopy(vv) if isinstance(vv, (dict, list)) else vv)
    return c


class _CachedJsonConfig:
    """按文件 (mtime_ns, size) 缓存 JSON 配置，热路径 readonly=True 零磁盘 I/O。"""
    def __init__(self, path, normalizer=_normalize_cfg):
        self.path = path
        self.normalizer = normalizer
        self._lock = threading.Lock()
        self._sig = None
        self._data = None

    def load(self, readonly=False):
        try:
            st = os.stat(self.path)
            sig = (st.st_mtime_ns, st.st_size)
        except OSError:
            sig = None
        with self._lock:
            if sig is not None and self._sig == sig and self._data is not None:
                return self._data if readonly else copy.deepcopy(self._data)
        try:
            with open(self.path, encoding="utf-8") as f:
                raw = json.load(f)
        except Exception:
            raw = {}
        c = self.normalizer(raw)
        with self._lock:
            if sig is not None:
                self._sig = sig
                self._data = c
        return c if readonly else copy.deepcopy(c)

    def save(self, c):
        _atomic_write_json(self.path, c, indent=2)
        try:
            st = os.stat(self.path)
            sig = (st.st_mtime_ns, st.st_size)
        except OSError:
            sig = None
        with self._lock:
            self._sig = sig
            self._data = copy.deepcopy(c)


_ROOT_CFG_STORE = _CachedJsonConfig(CFG_PATH)


def load_cfg(readonly=False):
    return _ROOT_CFG_STORE.load(readonly=readonly)


def save_cfg(c):
    _ROOT_CFG_STORE.save(c)


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
    def __init__(self, orig):
        self.orig = orig

    def write(self, s):
        if isinstance(s, (bytes, bytearray)):
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
    print(msg)


# ==================== 全局共享状态 & 校区缓存 ====================
GLOBAL_LOCK = threading.RLock()
GLOBAL_STATE = {
    "running": False,
    "round": 0,
    "last_scan": "",
    "offset": 0.0,
    "scanned": 0,
}

_CAMPUS_LOCK = threading.Lock()
_CAMPUS_BY_DID = {}
_CAMPUS_FAILS = {}
_CAMPUS_WORDS = ("四平路", "嘉定", "沪西", "彰武", "沪北", "南区", "北区")


def _parse_cookie_ids(cookie):
    sid = wid = ""
    for part in (cookie or "").split(";"):
        part = part.strip()
        if part.startswith("PG.ASP.Session.ID="):
            sid = part.split("=", 1)[1]
        elif part.startswith("PG.ASP.WeiXinCode.ID="):
            wid = part.split("=", 1)[1]
    return sid, wid


def _fmt_ltime(x, lts):
    t = str(lts or "").replace("T", " ")[:16]
    lte = str(x.get("LectureTimeEnd") or "").replace("T", " ")
    if lte and len(lte) >= 16:
        t += "~" + lte[11:16]
    return t


def _speaker(x):
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


def _hall_campus(did, client):
    with _CAMPUS_LOCK:
        if did in _CAMPUS_BY_DID:
            return _CAMPUS_BY_DID[did]
        if _CAMPUS_FAILS.get(did, 0) >= 3:
            return ""
    try:
        d = (client.api_hall(did).get("data") or {})
        cp = str(d.get("CampusCodeName") or "")
        with _CAMPUS_LOCK:
            _CAMPUS_BY_DID[did] = cp
        return cp
    except Exception:
        with _CAMPUS_LOCK:
            _CAMPUS_FAILS[did] = _CAMPUS_FAILS.get(did, 0) + 1
        return ""


def _campus_display(did, x):
    with _CAMPUS_LOCK:
        cp = _CAMPUS_BY_DID.get(did) or ""
    if cp:
        return cp.replace("校区", "")
    venue = str(x.get("Venue") or "")
    for c in _CAMPUS_WORDS:
        if c in venue:
            return c
    return ""


def _campus_filler(uniq, client, k=6):
    if not client or not client.cookie:
        return
    with _CAMPUS_LOCK:
        cands = [x for x in uniq if g._row_fields(x)[0]
                 and g._row_fields(x)[0] not in _CAMPUS_BY_DID
                 and _CAMPUS_FAILS.get(g._row_fields(x)[0], 0) < 3]
    cands.sort(key=lambda x: 0 if g._row_fields(x)[1] != 4 else 1)
    for x in cands[:max(1, k)]:
        try:
            _hall_campus(g._row_fields(x)[0], client)
        except Exception:
            pass


def _campus_ok(x, want, client):
    if not want:
        return True
    wants = [w.strip() for w in str(want).split(",") if w.strip()]
    if not wants:
        return True
    did = g._row_fields(x)[0]
    cp = _hall_campus(did, client)
    venue = str(x.get("Venue") or "")
    if cp:
        if any(w in cp for w in wants) or any(w in venue for w in wants):
            return True
        return False
    if any(c in venue for c in _CAMPUS_WORDS + ("校区",)):
        return any(w in venue for w in wants)
    return False


def _lecture_brief(x):
    did, st, title, tsu, lts, lvl = g._row_fields(x)
    cap = x.get("Capacity")
    sign = x.get("SignupNum")
    left = (cap - sign) if (isinstance(cap, int) and isinstance(sign, int)) else None
    spk = _speaker(x)
    ven = x.get("Venue") or ""
    lte = x.get("LectureTimeEnd") or ""
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


def _lecture_ended(w, now_ts=None):
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


# ==================== 用户运行时上下文 ====================
class UserRuntime:
    """单个用户的完全隔离状态、配置、Cookie、会话、日志与抢课引擎视图。"""

    def __init__(self, username, role="user", is_primary=False, data_dir=None):
        self.username = username
        self.role = role
        self.is_primary = is_primary
        self.data_dir = data_dir or (DATA_DIR if is_primary else os.path.join(USERS_DIR, username))
        os.makedirs(self.data_dir, exist_ok=True)

        self.cfg_path = CFG_PATH if is_primary else os.path.join(self.data_dir, "config.json")
        self.token_path = os.path.join(self.data_dir, "token.json")
        self.picked_path = os.path.join(self.data_dir, "picked.json")
        self.ignored_path = os.path.join(self.data_dir, "ignored.json")
        self.won_path = os.path.join(self.data_dir, "won.json")

        self._cfg_store = _ROOT_CFG_STORE if is_primary else _CachedJsonConfig(self.cfg_path)
        self.lock = threading.RLock()
        self.client = g.TongjiClient(pool_connections=8, pool_maxsize=32)
        self.proxy_url = ""
        self.logs = LogBuf(maxlen=1500)
        self.state = {
            "started_at": nowstr(),
            "cookie": {"present": False, "session_id": "", "captured_at": "", "valid": None,
                       "last_check": "", "age_sec": None, "student": {}},
            "engine": {"locked": {}, "fired": [], "candidates": [], "ignored": [], "won": []},
            "college": {"code": "", "name": ""},
            "events": [],
            "token_file_mtime": 0,
        }
        self._dead = {"notified": False, "streak": 0}
        self._ended_won_dids = set()

    def log(self, msg):
        line = str(msg)
        if self.is_primary:
            print(line)
        else:
            self.logs.add(line)
            print("[%s] %s" % (self.username, line))

    def load_cfg(self, readonly=False):
        return self._cfg_store.load(readonly=readonly)

    def save_cfg(self, c):
        self._cfg_store.save(c)

    def set_proxy(self, proxy_url=""):
        p = str(proxy_url or "").strip()
        self.proxy_url = p
        self.client.set_proxy(p)

    def push(self, event, text, at_all=False):
        with self.lock:
            self.state["events"].insert(0, {"t": nowstr(), "event": event, "text": text})
            self.state["events"] = self.state["events"][:60]
        cfg = self.load_cfg(readonly=True)
        try:
            if sys.platform == "darwin" and self.is_primary:
                events = (cfg.get("dingtalk") or {}).get("notify_events") or []
                if (not events) or (event in events):
                    body = str(text).replace("\\", "\\\\").replace('"', '\\"')[:220]
                    subprocess.run(["osascript", "-e",
                                    'display notification "%s" with title "同济抢讲座" sound name "Glass"' % body],
                                   capture_output=True, timeout=10)
        except Exception:
            pass
        if (cfg.get("dingtalk") or {}).get("webhook"):
            def _send_dt():
                try:
                    res = notify_mod.notify(event, text, cfg=cfg, at_all=at_all)
                    if res is not None:
                        self.log("[钉钉] %s -> %s" % (event, res.get("errmsg") if isinstance(res, dict) else res))
                except Exception as e:
                    self.log("[钉钉] 推送异常 %s" % e)
            threading.Thread(target=_send_dt, daemon=True).start()

    def read_token_file(self):
        try:
            with open(self.token_path, encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return {}

    def boot(self):
        d = self.read_token_file()
        if d.get("cookie") and not self.client.cookie:
            self.client.set_cookie(d["cookie"], d.get("token", ""))
        self.refresh_cookie_state(reload_disk=True)
        try:
            mtime = os.path.getmtime(self.token_path) if os.path.exists(self.token_path) else 0
            with self.lock:
                self.state["token_file_mtime"] = mtime
        except Exception:
            pass
        try:
            self.load_ignored()
            self.load_won()
            self.load_picked()
        except Exception as e:
            self.log("[boot] 恢复持久化清单异常 %s" % e)

    def refresh_cookie_state(self, reload_disk=True):
        d = self.read_token_file() if reload_disk else {}
        with self.lock:
            cap = d.get("captured_at") or self.state["cookie"].get("captured_at", "")
            cookie = d.get("cookie", "") or self.client.cookie
        sid, _ = _parse_cookie_ids(cookie)
        age = None
        if cap:
            try:
                t0 = dt.datetime.strptime(cap, "%Y-%m-%d %H:%M:%S")
                age = round((dt.datetime.now() - t0).total_seconds())
            except Exception:
                pass
        with self.lock:
            self.state["cookie"].update(present=bool(cookie), session_id=sid, captured_at=cap, age_sec=age)
            if d.get("student") and not self.state["cookie"].get("student"):
                self.state["cookie"]["student"] = d.get("student") or {}

    def apply_cookie(self, cookie, meta=None, source="manual"):
        cookie = (cookie or "").strip()
        if not cookie:
            return False, "空 cookie"
        sid, wid = _parse_cookie_ids(cookie)
        if not sid:
            return False, "Cookie 格式无效(缺少 PG.ASP.Session.ID)"
        meta = meta or {}
        try:
            r = self.client.api_student_info(cookie=cookie)
            alive = g.token_alive(r) and isinstance(r, dict) and r.get("state") == "success"
        except Exception as e:
            alive, r = False, {"state": "error", "msg": "校验异常 %s" % e}

        if not alive:
            with self.lock:
                had_valid = bool(self.client.cookie) and (self.state["cookie"].get("valid") is True)
                self.state["cookie"]["last_check"] = nowstr()
            msg = (r.get("msg") if isinstance(r, dict) else str(r)) or "校验未通过"
            if had_valid:
                self.log("[cookie] 新 cookie 校验失败(%s), 保留原有效会话 source=%s" % (msg, source))
            else:
                self.log("[cookie] 应用新 cookie source=%s 校验=无效 (%s)" % (source, msg))
            return False, msg

        d = self.read_token_file()
        d.update({"cookie": cookie, "session_id": sid, "weixin_code_id": wid,
                  "captured_at": meta.get("captured_at") or nowstr(),
                  "source": source, "host": "lecture.tongji.edu.cn"})
        if isinstance(r.get("data"), dict):
            d["student"] = r["data"]
        elif meta.get("student"):
            d["student"] = meta["student"]

        self.client.set_cookie(cookie)
        if self.is_primary:
            g.COOKIE = cookie
            g.reset_student_cache()
        try:
            _atomic_write_json(self.token_path, d, indent=2)
            mtime = os.path.getmtime(self.token_path)
        except Exception as e:
            mtime = 0
            self.log("[cookie] 写 token.json 失败: %s" % e)

        with self.lock:
            if mtime:
                self.state["token_file_mtime"] = mtime
            self.state["cookie"]["valid"] = True
            self.state["cookie"]["last_check"] = nowstr()
            if isinstance(r.get("data"), dict):
                self.state["cookie"]["student"] = r["data"]
            self._dead["streak"] = 0
            self._dead["notified"] = False
        self.refresh_cookie_state(reload_disk=True)
        self.log("[cookie] 应用新 cookie source=%s 校验=有效" % source)
        return True, r.get("data")

    def watch_token_file(self):
        try:
            m = os.path.getmtime(self.token_path)
        except Exception:
            return
        with self.lock:
            prev_m = self.state["token_file_mtime"]
        if m and m != prev_m:
            with self.lock:
                self.state["token_file_mtime"] = m
            d = self.read_token_file()
            ck = d.get("cookie", "")
            if ck and ck != self.client.cookie:
                self.log("[cookie] 检测到 token.json 变化, 热加载中…")
                self.apply_cookie(ck, meta=d, source="sync")

    def record_alive(self):
        with self.lock:
            self._dead["streak"] = 0
            self._dead["notified"] = False
            self.state["cookie"]["valid"] = True

    def record_dead_candidate(self, reason, source="keepalive"):
        with self.lock:
            self._dead["streak"] = int(self._dead.get("streak", 0)) + 1
            streak = self._dead["streak"]
        self.log("[%s] 明确失效(%d/%d): %s" % (source, streak, DEAD_STREAK, reason))
        if streak >= DEAD_STREAK:
            self.mark_dead("连续%d次判定失效: %s" % (streak, reason))

    def mark_dead(self, reason):
        should_notify = False
        with self.lock:
            self.state["cookie"]["valid"] = False
            self.state["cookie"]["last_check"] = nowstr()
            if not self._dead["notified"]:
                self._dead["notified"] = True
                should_notify = True
        self.log("[!!] Cookie 失效: %s" % reason)
        if should_notify:
            self.push("cookie_dead", "会话 Cookie 已失效(%s)! 请重抓或上传新 Cookie。" % reason)

    def probe_cookie(self, retries=2):
        for i in range(retries + 1):
            if STOP.is_set():
                return "unknown", "stopping"
            try:
                r = self.client.api_student_info()
            except Exception as e:
                self.log("[keepalive] 心跳请求异常(%d/%d): %s" % (i + 1, retries + 1, e))
                if i < retries:
                    STOP.wait(3.0)
                continue
            if not g.token_alive(r):
                return "dead", (r.get("msg") if isinstance(r, dict) else "失效")
            if isinstance(r, dict) and r.get("state") == "success":
                with self.lock:
                    if isinstance(r.get("data"), dict):
                        self.state["cookie"]["student"] = r["data"]
                return "alive", r.get("data")
            if i < retries:
                STOP.wait(3.0)
        return "unknown", "网络/服务端异常"

    def save_picked(self):
        try:
            with self.lock:
                data = {d: dict(v) for d, v in self.state["engine"]["locked"].items() if v.get("manual")}
            _atomic_write_json(self.picked_path, data, indent=2)
        except Exception as e:
            self.log("[picked] 保存失败 %s" % e)

    def save_ignored(self):
        try:
            with self.lock:
                data = list(self.state["engine"].get("ignored", []))
            _atomic_write_json(self.ignored_path, data, indent=None)
        except Exception as e:
            self.log("[ignored] 保存失败 %s" % e)

    def load_ignored(self):
        try:
            with open(self.ignored_path, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                with self.lock:
                    self.state["engine"]["ignored"] = [str(d) for d in data]
                self.log("[ignored] 恢复忽略清单 %d 项" % len(data))
        except Exception:
            pass

    def save_won(self):
        try:
            with self.lock:
                data = [dict(w) for w in self.state["engine"].get("won", [])]
            _atomic_write_json(self.won_path, data, indent=2)
        except Exception as e:
            self.log("[won] 保存失败 %s" % e)

    def load_won(self):
        try:
            with open(self.won_path, encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                with self.lock:
                    self.state["engine"]["won"] = data[:50]
                self.log("[won] 恢复已选到讲座 %d 项" % len(data))
        except Exception:
            pass

    def load_picked(self):
        try:
            with open(self.picked_path, encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            return
        if not isinstance(data, dict) or not data:
            return
        with GLOBAL_LOCK:
            off = GLOBAL_STATE.get("offset") or 0.0
        now = g.srv_now(off)
        force = bool(self.load_cfg(readonly=True).get("grab", {}).get("force", False))
        rearmed = 0
        to_fire = []
        with self.lock:
            locked = self.state["engine"]["locked"]
            fired = self.state["engine"]["fired"]
            for did, v in data.items():
                if not isinstance(v, dict):
                    continue
                v = dict(v)
                v.setdefault("manual", True)
                v.setdefault("auto", True)
                tgt = v.get("tgt") or now
                if v.get("status") in ("success", "failed", "expired"):
                    locked[did] = v
                    continue
                lts_e = v.get("lts_epoch") or 0
                if lts_e and now > lts_e + g.GRACE_PAST:
                    v["status"] = "expired"
                    locked[did] = v
                    continue
                if self.client.cookie and (tgt - now) <= g.LEAD + 1 and tgt >= now - g.GRACE_PAST:
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
            threading.Thread(target=self.grab_wrapper, args=(did, off, force, title), daemon=True).start()
        self.log("[picked] 恢复手选清单 %d 项(立即重新开火 %d 项)" % (len(data), rearmed))

    def won_signed_state(self, did):
        try:
            d = (self.client.api_hall(did).get("data") or {})
            if d:
                return bool(d.get("XSSigningUp"))
        except Exception:
            pass
        return None

    def won_remind_check(self):
        if not self.client.cookie:
            return
        now = time.time()
        pending = []
        with self.lock:
            for w in self.state["engine"].get("won", []):
                did = str(w.get("did") or "")
                if w.get("reminded") or w.get("cancelled") or (did and did in self._ended_won_dids):
                    continue
                lt = str(w.get("ltime") or "")
                try:
                    start = dt.datetime.strptime(lt.split("~")[0].strip(), "%Y-%m-%d %H:%M").timestamp()
                except Exception:
                    continue
                diff = start - now
                if diff <= 0:
                    if did:
                        self._ended_won_dids.add(did)
                    continue
                if diff <= 7200:
                    pending.append(w)
        for w in pending:
            venue = ""
            try:
                dd = (self.client.api_hall(w.get("did")).get("data") or {})
                venue = str(dd.get("Venue") or "")
            except Exception:
                pass
            self.push("lecture_soon", "⏰ 讲座提醒(还有不到 2 小时):\n《%s》\n时间: %s\n地点: %s\n已为你报名成功, 记得参加!" % (
                str(w.get("title"))[:50], str(w.get("ltime") or "").replace("~", " 至 "), venue or "(见系统)"))
            with self.lock:
                for e in self.state["engine"]["won"]:
                    if e.get("did") == w.get("did"):
                        e["reminded"] = True
            self.save_won()
            self.log("[提醒] 已发开讲提醒: 《%s》" % str(w.get("title"))[:30])

    def won_verify(self):
        if not self.client.cookie:
            return
        try:
            with self.lock:
                won = [dict(w) for w in self.state["engine"].get("won", [])]
            now_ts = time.time()
            changed = False
            for w in won:
                did = str(w.get("did") or "")
                if not did or w.get("cancelled") or _lecture_ended(w, now_ts):
                    continue
                stt = self.won_signed_state(did)
                if stt is False:
                    with self.lock:
                        for e in self.state["engine"]["won"]:
                            if e.get("did") == did:
                                e["cancelled"] = True
                                e["cancelled_at"] = nowstr()
                    changed = True
                    self.log("[won] ⚠️ 官方已无报名记录(疑似手动取消): 《%s》— 已标记, 不会自动重抢" % str(w.get("title"))[:30])
            if changed:
                self.save_won()
        except Exception as e:
            self.log("[won] 核对异常 %s" % e)

    def grab_wrapper(self, did, off, force, title):
        tag = "[%s] " % str(did)[:6]
        ok = False
        reason = "full_or_timeout"

        def _cancelled():
            with self.lock:
                vv = self.state["engine"]["locked"].get(did)
                return vv is None or vv.get("status") not in ("waiting", "grabbing")

        prof = _register_and_plan_grab(self, did, off)
        self.log("%s%s" % (tag, prof["note"]))
        try:
            ok, reason = self.client.grab_one(
                did, off, force=force, tag=tag, cancel_check=_cancelled,
                return_reason=True, log_fn=self.log,
                burst=prof["burst"], volley_interval=prof["volley_interval"], lead=prof["lead"],
            )
        except Exception as e:
            self.log("%s抢报异常: %s" % (tag, e))
            reason = "full_or_timeout"
        finally:
            _unregister_active_grab(self.username, did)

        hard_retry = False
        soft_retry = False
        fc_out = 0
        full_cnt = 0
        with self.lock:
            v = self.state["engine"]["locked"].get(did)
            if v is not None:
                if ok:
                    v["status"] = "success"
                    won = self.state["engine"].setdefault("won", [])
                    if not any(w.get("did") == did for w in won):
                        won.insert(0, {"did": did, "title": v.get("title", title), "lvl": v.get("lvl", ""),
                                       "ltime": v.get("ltime", ""), "tsu": v.get("tsu", ""), "won_at": nowstr()})
                        self.state["engine"]["won"] = won[:50]
                elif reason == "expired":
                    v["status"] = "expired"
                    if did in self.state["engine"]["fired"]:
                        self.state["engine"]["fired"].remove(did)
                elif reason == "cancelled":
                    if did in self.state["engine"]["fired"]:
                        self.state["engine"]["fired"].remove(did)
                elif reason == "hard_fail":
                    fc_out = int(v.get("fail_count", 0)) + 1
                    v["fail_count"] = fc_out
                    if fc_out >= MAX_GRAB_RETRY:
                        v["status"] = "failed"
                    else:
                        v["status"] = "waiting"
                        hard_retry = True
                        if did in self.state["engine"]["fired"]:
                            self.state["engine"]["fired"].remove(did)
                else:
                    full_cnt = int(v.get("full_retries", 0)) + 1
                    v["full_retries"] = full_cnt
                    v["status"] = "waiting"
                    soft_retry = True
                    if did in self.state["engine"]["fired"]:
                        self.state["engine"]["fired"].remove(did)
        self.save_picked()
        if ok:
            self.save_won()
            self.push("success", "🎉 报名成功: %s (%s)" % (str(title)[:40], str(did)[:8]))
        elif reason == "cookie_dead":
            self.record_dead_candidate("抢报接口返回登录失效", source="grab")
        elif hard_retry:
            self.log("%s硬拦截未成功(第%d/%d次), 暂挂起等待下轮" % (tag, fc_out, MAX_GRAB_RETRY))
        elif soft_retry:
            self.log("%s名额已满/超时(累计%d次), 继续挂起监测捡漏" % (tag, full_cnt))
        elif reason == "hard_fail":
            self.push("grab_fail", "抢报未成功: %s (%s) — 多次触发资格/人脸拦截, 已停止" % (str(title)[:40], str(did)[:8]))

    def arm_grab(self, did, title, tsu, lvl, force, ltime=""):
        tgt = g.parse_cn_epoch(tsu) if tsu else None
        with GLOBAL_LOCK:
            off = GLOBAL_STATE.get("offset") or 0.0
        now = g.srv_now(off)
        if tgt is None:
            tgt = now
        with self.lock:
            locked = self.state["engine"]["locked"]
            fired = self.state["engine"]["fired"]
            ign = self.state["engine"].setdefault("ignored", [])
            if did in ign:
                ign.remove(did)
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
                    fired.remove(did)
            locked[did] = v
            vt = v["title"]
        self.save_picked()
        if immediate:
            self.log("[抢报] 已开放, 立即开火 did=%s title=%s force=%s" % (did[:8], vt, force))
            threading.Thread(target=self.grab_wrapper, args=(did, off, force, vt), daemon=True).start()
            return {"ok": True, "mode": "立即抢报", "msg": "已开放, 立即开火, 结果见待抢清单/通知"}
        self.log("[抢报] 加入待抢清单, 到点自动开火 did=%s tgt=%s" % (did[:8], tsu))
        return {"ok": True, "mode": "到点自动抢", "msg": "已加入待抢清单, 到 %s 自动开火" % (tsu or "点")}

    def process_scan_rows(self, uniq, off, rnd):
        if not self.client.cookie:
            return
        cfg = self.load_cfg(readonly=True)
        grab = cfg.get("grab", {})
        interval = int(grab.get("interval_sec", 30) or 30)
        force = bool(grab.get("force", False))
        kws = [k for k in (grab.get("keywords") or []) if str(k).strip()]
        xiao_watch = bool(grab.get("xiao_watch", True))
        xiao_auto = bool(grab.get("xiao_auto", False))
        xiao_campus = str(grab.get("xiao_campus", "") or "").strip()
        yuan_watch = bool(grab.get("yuan_watch", True))
        yuan_auto = bool(grab.get("yuan_auto", True))
        yuan_only = bool(grab.get("yuan_college_only", True))
        yuan_campus = str(grab.get("yuan_campus", "") or "").strip()
        watch_levels = ([("校级", xiao_auto)] if xiao_watch else []) + ([("院级", yuan_auto)] if yuan_watch else [])
        auto_levels = {lvl for lvl, a in watch_levels if a}
        watch_set = {lvl for lvl, _a in watch_levels}
        if not watch_set:
            return

        mc, mn = "", ""
        try:
            mc, mn = self.client.my_college()
        except Exception:
            pass
        with self.lock:
            self.state["college"] = {"code": mc, "name": mn}
            won_ids = {w.get("did") for w in self.state["engine"].get("won", [])}

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
                        continue
                    want = xiao_campus if lvl == "校级" else (yuan_campus if lvl == "院级" else "")
                    if not _campus_ok(x, want, self.client):
                        continue
                    targets.setdefault(did, {"x": x, "tgt": tgt})

        for x in uniq:
            did, st, title, tsu, lts, lvl = g._row_fields(x)
            if not did or st != 1 or lvl not in watch_set:
                continue
            if yuan_only and lvl == "院级" and mc and str(x.get("CollegeCode")) != str(mc):
                continue
            if kws and not any(k.lower() in str(title).lower() for k in kws):
                continue
            if did in won_ids:
                continue
            want = xiao_campus if lvl == "校级" else (yuan_campus if lvl == "院级" else "")
            if not _campus_ok(x, want, self.client):
                continue
            targets.setdefault(did, {"x": x, "tgt": now})

        newly_locked = []
        for did, info in targets.items():
            x = info["x"]
            _, st, title, tsu, lts, lvl = g._row_fields(x)
            brief = _lecture_brief(x)
            already_open = (info["tgt"] - now) <= 0
            campus_nm = _hall_campus(did, self.client) if (xiao_campus or yuan_campus) else ""
            with self.lock:
                locked = self.state["engine"]["locked"]
                fired_set = set(self.state["engine"]["fired"])
                ignored_set = set(self.state["engine"].get("ignored", []))
                if did in fired_set or did in locked or did in ignored_set:
                    continue
                if not campus_nm:
                    with _CAMPUS_LOCK:
                        campus_nm = _CAMPUS_BY_DID.get(did, "")
                locked[did] = {"title": str(title)[:60], "tsu": tsu, "lvl": lvl,
                               "tgt": info["tgt"], "locked_at": nowstr(),
                               "brief": brief, "open_notified": already_open,
                               "ltime": _fmt_ltime(x, lts), "lts_epoch": g.parse_cn_epoch(lts) or 0,
                               "manual": False, "auto": (lvl in auto_levels), "status": "waiting",
                               "campus": campus_nm}
            newly_locked.append((did, lvl, brief))

        for did, lvl, brief in newly_locked:
            self.log("[%s] [新发现·%s] %s" % (nowstr(), lvl, brief.replace("\n", " | ")))
            if lvl == "校级" and lvl not in auto_levels:
                self.push("new_target", "🏫 新校级讲座(不自动抢, 请上 WebUI 手动选择):\n%s" % brief)
            else:
                self.push("new_target", "🎯 发现新目标[%s]%s\n%s" % (
                    lvl, " · 将自动抢" if lvl in auto_levels else "", brief))

        byid = {}
        for x in uniq:
            d0 = g._row_fields(x)[0]
            if d0:
                byid[d0] = x
        now2 = g.srv_now(off)
        with self.lock:
            locked_snap = {d: dict(v) for d, v in self.state["engine"]["locked"].items()}
            fired_snap = set(self.state["engine"]["fired"])
            self.state["engine"]["candidates"] = [
                {"did": d, "title": v["title"], "lvl": v["lvl"], "tsu": v["tsu"],
                 "ltime": v.get("ltime", ""), "campus": v.get("campus", ""),
                 "auto": v.get("auto", v["lvl"] in auto_levels), "manual": v.get("manual", False),
                 "status": v.get("status", "waiting"),
                 "countdown": round(v["tgt"] - now2)}
                for d, v in locked_snap.items() if v.get("status", "waiting") in ("waiting", "grabbing")
            ]

        due = []
        for did, v in locked_snap.items():
            if v.get("status", "waiting") != "waiting" or did in fired_snap:
                continue
            x = byid.get(did)
            st = g._row_fields(x)[1] if x is not None else None
            lts_e = v.get("lts_epoch") or (g.parse_cn_epoch(g._row_fields(x)[4]) if x is not None else 0)
            if st == 4 or (lts_e and now2 > lts_e + g.GRACE_PAST):
                expired_now = False
                pruned = False
                ref_ts = lts_e or v.get("tgt") or now2
                stale_auto = (not v.get("manual")) and (now2 - ref_ts > 86400)
                with self.lock:
                    vv = self.state["engine"]["locked"].get(did)
                    if vv and vv.get("status") == "waiting":
                        if stale_auto:
                            del self.state["engine"]["locked"][did]
                            pruned = True
                        else:
                            vv["status"] = "expired"
                        expired_now = True
                    elif vv and vv.get("status") == "expired" and stale_auto:
                        del self.state["engine"]["locked"][did]
                        pruned = True
                if expired_now and not pruned:
                    self.log("[%s] [过期退出] %s %s (已结束/讲座时间已过)" % (nowstr(), str(did)[:8], str(v.get("title", ""))[:24]))
                continue
            if v.get("status") == "expired":
                ref_ts = (v.get("lts_epoch") or v.get("tgt") or now2)
                if not v.get("manual") and (now2 - ref_ts > 86400):
                    with self.lock:
                        self.state["engine"]["locked"].pop(did, None)
                continue
            remain_s = v["tgt"] - now2
            will_fire = bool(v.get("auto")) or (not v.get("manual") and v.get("lvl") in auto_levels)
            if remain_s > g.LEAD + 1:
                prearm = max(45, interval + 15)
                if not (will_fire and remain_s <= prearm):
                    continue
            if st == 2:
                continue
            if st is None and (now2 - (v.get("tgt") or now2)) > g.GRACE_PAST:
                continue
            due.append(did)

        for did in due:
            fire_title = ""
            fire_lvl = ""
            fire_manual = False
            notify_brief = ""
            action = None
            with self.lock:
                vv = self.state["engine"]["locked"].get(did)
                if not vv or vv.get("status", "waiting") != "waiting" or did in self.state["engine"]["fired"]:
                    continue
                fire_lvl = vv.get("lvl", "")
                fire_title = vv.get("title", "")
                fire_manual = bool(vv.get("manual"))
                if vv.get("auto") or (not fire_manual and fire_lvl in auto_levels):
                    self.state["engine"]["fired"].append(did)
                    vv["status"] = "grabbing"
                    action = "fire"
                elif not vv.get("open_notified"):
                    vv["open_notified"] = True
                    notify_brief = vv.get("brief") or fire_title
                    action = "notify"
            if action == "fire":
                self.log("\n[%s] >>> 到点自动开抢 [%s]%s %s %s" % (
                    nowstr(), fire_lvl, "(手选)" if fire_manual else "", str(did)[:8], str(fire_title)[:26]))
                threading.Thread(target=self.grab_wrapper, args=(did, off, force, fire_title), daemon=True).start()
            elif action == "notify":
                self.log("\n[%s] ⏰ 校级已开报(不自动抢): %s" % (nowstr(), str(fire_title)[:30]))
                self.push("new_target", "⏰ 校级讲座已开报, 名额有限快去抢:\n%s" % notify_brief)

        if rnd % 5 == 1 or due:
            with self.lock:
                locked_cnt = len(self.state["engine"]["locked"])
                fired_set = set(self.state["engine"]["fired"])
                pend_cnt = sum(1 for d in self.state["engine"]["locked"] if d not in fired_set)
            self.log("[%s] 第%d轮: 扫描%d场 命中%d 锁定%d 待处理%d 自动抢=%s 偏移%.3fs" % (
                nowstr(), rnd, len(uniq), len(targets), locked_cnt, pend_cnt,
                (",".join(sorted(auto_levels)) or "无(全手动)"), off))

        self.won_remind_check()
        if rnd % 10 == 0:
            self.won_verify()


# ==================== 多用户管理 & 认证 ====================
USERS_LOCK = threading.RLock()
USER_RUNTIMES = {}      # username -> UserRuntime
USERS_META = {}         # username -> record in users.json (non-primary users)
_ACTIVE_GRABS_LOCK = threading.Lock()
_ACTIVE_GRABS = set()   # (username, did) 目前正处于 grab_wrapper 执行中的并发抢报

SESSION_COOKIE_NAME = "tj_session"
PBKDF2_ITERS = 260000
_REVOKED_JTIS = {}
_REVOKED_LOCK = threading.Lock()


def _normalize_proxy_url(raw):
    s = str(raw or "").strip()
    if not s:
        return True, ""
    try:
        u = urlparse(s)
    except Exception:
        return False, "代理地址格式无效"
    scheme = (u.scheme or "").lower()
    if scheme not in ("http", "https", "socks5", "socks5h"):
        return False, "仅支持 http:// / https:// / socks5:// / socks5h:// 代理 (mihomo 推荐 http://127.0.0.1:端口)"
    if not u.hostname or not u.port:
        return False, "代理地址缺少主机或端口 (例如 http://127.0.0.1:7891)"
    if scheme.startswith("socks"):
        try:
            import socks  # noqa: F401
        except ImportError:
            return False, "当前环境未安装 PySocks，无法使用 socks5；请改填 mihomo HTTP/Mixed 端口 (如 http://127.0.0.1:7891)"
    return True, s


def _rt_prearm_window(rt):
    cfg = rt.load_cfg(readonly=True)
    grab = cfg.get("grab") or {}
    interval = int(grab.get("interval_sec", 30) or 30)
    xiao_auto = bool(grab.get("xiao_auto", False))
    yuan_auto = bool(grab.get("yuan_auto", True))
    auto_levels = set()
    if grab.get("xiao_watch", True) and xiao_auto:
        auto_levels.add("校级")
    if grab.get("yuan_watch", True) and yuan_auto:
        auto_levels.add("院级")
    return auto_levels, max(45, interval + 15) + 5


def _shared_exit_peers_for_did(u, did, off):
    exit_key = (u.proxy_url or "").strip()
    now = g.srv_now(off)
    with _ACTIVE_GRABS_LOCK:
        active_snap = set(_ACTIVE_GRABS)
    peers = []
    seen = set()
    for rt in _all_runtimes():
        if (rt.proxy_url or "").strip() != exit_key:
            continue
        matched = (rt.username == u.username) or ((rt.username, did) in active_snap)
        if not matched:
            auto_levels, prearm = _rt_prearm_window(rt)
            with rt.lock:
                v = rt.state["engine"]["locked"].get(did)
                if v:
                    st = v.get("status", "waiting")
                    if st == "grabbing":
                        matched = True
                    elif st == "waiting":
                        will_fire = bool(v.get("auto")) or (not v.get("manual") and v.get("lvl") in auto_levels)
                        tgt = v.get("tgt") or now
                        if will_fire and (tgt - now) <= prearm:
                            matched = True
        if matched and rt.username not in seen:
            seen.add(rt.username)
            peers.append(rt)
    return peers


def _plan_grab_profile(u, did, off):
    root_cfg = load_cfg(readonly=True)
    mu = root_cfg.get("multi_user") or {}
    throttle_on = mu.get("cofire_throttle", True)
    admin_prio = mu.get("admin_priority", True)
    exit_key = (u.proxy_url or "").strip()
    peers = _shared_exit_peers_for_did(u, did, off)
    n_peers = len(peers)

    if (not throttle_on) or n_peers <= 1:
        route = ("代理 %s" % exit_key) if exit_key else "直连"
        return {
            "burst": g.BURST,
            "volley_interval": g.VOLLEY_INTERVAL,
            "lead": g.LEAD,
            "peers": n_peers,
            "note": "[并发策略] %s · 独享出口满速 burst=%d interval=%.2fs lead=%.2fs" % (
                route, g.BURST, g.VOLLEY_INTERVAL, g.LEAD),
        }

    is_admin = bool(u.role == "admin" or u.is_primary)
    route = exit_key or "直连"
    if admin_prio and is_admin:
        burst = g.BURST if n_peers <= 3 else max(3, g.BURST - 1)
        interval = g.VOLLEY_INTERVAL
        lead = max(g.LEAD, 0.44)
        return {
            "burst": burst,
            "volley_interval": interval,
            "lead": lead,
            "peers": n_peers,
            "note": "[协同流控] 同出口(%s)共%d人抢此场: 管理员优先满速 burst=%d interval=%.2fs lead=%.2fs" % (
                route, n_peers, burst, interval, lead),
        }

    throttled_peers = sorted(
        p.username for p in peers
        if not (admin_prio and (p.role == "admin" or p.is_primary))
    )
    idx = throttled_peers.index(u.username) if u.username in throttled_peers else 0
    burst = 2 if n_peers == 2 else 1
    interval = round(min(0.45, 0.16 + 0.08 * (n_peers - 1)), 2)
    lead = round(max(0.05, 0.30 - 0.12 * (idx + 1)), 2)
    return {
        "burst": burst,
        "volley_interval": interval,
        "lead": lead,
        "peers": n_peers,
        "note": "[协同流控] 同出口(%s)共%d人抢此场: 错峰节流(#%d) burst=%d interval=%.2fs lead=%.2fs%s" % (
            route, n_peers, idx + 1, burst, interval, lead, " [管理员优先]" if admin_prio else ""),
    }


def _register_and_plan_grab(u, did, off):
    with _ACTIVE_GRABS_LOCK:
        _ACTIVE_GRABS.add((u.username, did))
    return _plan_grab_profile(u, did, off)


def _unregister_active_grab(username, did):
    with _ACTIVE_GRABS_LOCK:
        _ACTIVE_GRABS.discard((username, did))


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


def _save_users_meta():
    with USERS_LOCK:
        _atomic_write_json(USERS_PATH, USERS_META, indent=2)


def _primary_username(cfg):
    auth = cfg.get("auth") or {}
    return str(auth.get("username") or "").strip()


def _auth_configured(cfg):
    auth = cfg.get("auth") or {}
    return bool(auth.get("username") and auth.get("password_hash"))


def _init_all_users():
    cfg = load_cfg()
    prim = _primary_username(cfg) or "admin"
    try:
        with open(USERS_PATH, encoding="utf-8") as f:
            raw_users = json.load(f)
        if not isinstance(raw_users, dict):
            raw_users = {}
    except Exception:
        raw_users = {}

    with USERS_LOCK:
        USERS_META.clear()
        USER_RUNTIMES.clear()
        rt_prim = UserRuntime(prim, role="admin", is_primary=True, data_dir=DATA_DIR)
        rt_prim.set_proxy((cfg.get("auth") or {}).get("proxy_url", ""))
        rt_prim.boot()
        USER_RUNTIMES[prim] = rt_prim
        for uname, rec in raw_users.items():
            if not isinstance(rec, dict) or uname == prim or not USERNAME_RE.match(uname):
                continue
            USERS_META[uname] = rec
            if not rec.get("disabled"):
                rt = UserRuntime(uname, role="user", is_primary=False)
                rt.set_proxy(rec.get("proxy_url", ""))
                rt.boot()
                USER_RUNTIMES[uname] = rt


def _get_user_auth_record(username, root_cfg):
    prim = _primary_username(root_cfg)
    if prim and hmac.compare_digest(username.encode("utf-8"), prim.encode("utf-8")):
        auth = root_cfg.get("auth") or {}
        if not _auth_configured(root_cfg):
            return None
        return {
            "username": prim,
            "password_hash": auth.get("password_hash", ""),
            "role": "admin",
            "api_token": auth.get("api_token", ""),
            "proxy_url": auth.get("proxy_url", ""),
            "session_version": int(auth.get("session_version", 1) or 1),
            "disabled": False,
            "is_primary": True,
        }
    with USERS_LOCK:
        rec = USERS_META.get(username)
        return dict(rec) if rec else None


def _all_runtimes():
    with USERS_LOCK:
        return list(USER_RUNTIMES.values())


def _create_subuser(username, password, role="user"):
    username = (username or "").strip()
    if not USERNAME_RE.match(username):
        return False, "用户名须为 2-24 位字母、数字、下划线或短横线", None
    if len(password or "") < 6:
        return False, "密码长度至少 6 位", None
    root_cfg = load_cfg()
    prim = _primary_username(root_cfg) or "admin"
    with USERS_LOCK:
        if username == prim or username in USERS_META:
            return False, "用户名已存在", None
        tok = secrets.token_hex(24)
        rec = {
            "username": username,
            "password_hash": _hash_password(password),
            "role": "user" if role != "admin" else "admin",
            "api_token": tok,
            "session_version": 1,
            "disabled": False,
            "created_at": nowstr(),
        }
        USERS_META[username] = rec
        _save_users_meta()
        rt = UserRuntime(username, role=rec["role"], is_primary=False)
        rt.save_cfg(copy.deepcopy(DEFAULT_CFG))
        rt.boot()
        USER_RUNTIMES[username] = rt
    log("[users] 新增账号 %s" % username)
    return True, tok, rt


def _b64u_enc(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def _b64u_dec(s):
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def _make_session_token(username, root_cfg, session_version=1):
    auth = root_cfg.get("auth") or {}
    secret = _ensure_session_secret(root_cfg).encode("utf-8")
    ttl = max(300, int(auth.get("session_ttl_sec", 604800) or 604800))
    payload = {
        "u": username,
        "exp": int(time.time()) + ttl,
        "v": int(session_version),
        "jti": secrets.token_hex(8),
    }
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    p_b64 = _b64u_enc(raw)
    sig = hmac.new(secret, p_b64.encode("ascii"), hashlib.sha256).digest()
    return "%s.%s" % (p_b64, _b64u_enc(sig)), ttl


def _parse_session_token(token, root_cfg):
    if not token or "." not in token:
        return None
    auth = root_cfg.get("auth") or {}
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
    uname = str(payload.get("u") or "")
    rec = _get_user_auth_record(uname, root_cfg)
    if not rec or rec.get("disabled"):
        return None
    if int(payload.get("v", -1)) != int(rec.get("session_version", 1) or 1):
        return None
    jti = str(payload.get("jti", ""))
    with _REVOKED_LOCK:
        for k in [kk for kk, exp in _REVOKED_JTIS.items() if exp <= now]:
            del _REVOKED_JTIS[k]
        if jti in _REVOKED_JTIS:
            return None
    return payload


def _revoke_session_token(token, root_cfg):
    payload = _parse_session_token(token, root_cfg)
    if not payload:
        return
    jti = str(payload.get("jti", ""))
    exp = int(payload.get("exp", 0))
    if jti:
        with _REVOKED_LOCK:
            _REVOKED_JTIS[jti] = exp


class _AuthGuard:
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


def _public_cfg(cfg):
    c = {k: v for k, v in cfg.items() if k not in ("auth", "multi_user")}
    return c


def _check_request_auth(root_cfg):
    auth = root_cfg.get("auth") or {}
    prim = _primary_username(root_cfg) or "admin"
    if not auth.get("enabled", True):
        with USERS_LOCK:
            return USER_RUNTIMES.get(prim), 200, "", 0
    if not _auth_configured(root_cfg):
        return None, 401, "尚未配置登录账号密码，请先设置", 0

    tok = request.cookies.get(SESSION_COOKIE_NAME, "")
    if tok:
        payload = _parse_session_token(tok, root_cfg)
        if payload:
            with USERS_LOCK:
                rt = USER_RUNTIMES.get(payload["u"])
            if rt is not None:
                return rt, 200, "", 0

    hdr_tok = request.headers.get("X-API-Token", "")
    if not hdr_tok:
        auth_hdr = request.headers.get("Authorization", "")
        if auth_hdr.startswith("Bearer "):
            hdr_tok = auth_hdr[7:].strip()
    if hdr_tok:
        ip = _client_ip()
        allowed, wait_sec = _AUTH_GUARD.check_allowed(ip)
        if not allowed:
            return None, 429, "尝试过于频繁，请 %d 秒后再试" % wait_sec, wait_sec

        matched_user = None
        prim_tok = str(auth.get("api_token") or "")
        if prim_tok and hmac.compare_digest(hdr_tok.encode("utf-8"), prim_tok.encode("utf-8")):
            matched_user = prim
        else:
            with USERS_LOCK:
                for uname, rec in USERS_META.items():
                    if rec.get("disabled"):
                        continue
                    utok = str(rec.get("api_token") or "")
                    if utok and hmac.compare_digest(hdr_tok.encode("utf-8"), utok.encode("utf-8")):
                        matched_user = uname
                        break
        if matched_user:
            with USERS_LOCK:
                rt = USER_RUNTIMES.get(matched_user)
            if rt is not None:
                _AUTH_GUARD.record_success(ip)
                return rt, 200, "", 0

        cnt, lock_sec = _AUTH_GUARD.record_failure(ip)
        log("[auth] API Token 校验失败 ip=%s (连续第%d次)" % (ip, cnt))
        if lock_sec:
            return None, 429, "尝试过于频繁，请 %d 秒后再试" % lock_sec, lock_sec

    return None, 401, "未登录或会话已过期", 0


# ==================== keep-alive & 共享扫描引擎 ====================
def _sleep(sec):
    STOP.wait(max(1.0, float(sec)))


def _keepalive_one(u):
    u_ka = 300
    try:
        u_ka = int(u.load_cfg(readonly=True).get("keepalive_sec", 300) or 300)
        u.watch_token_file()
    except Exception as e:
        u.log("[keepalive] watch_token_file 异常 %s" % e)
    if STOP.is_set():
        return u_ka
    if u.client.cookie:
        verdict, info = u.probe_cookie()
        with u.lock:
            u.state["cookie"]["last_check"] = nowstr()
        if verdict == "alive":
            u.record_alive()
        elif verdict == "dead":
            u.record_dead_candidate(info, source="keepalive")
        else:
            u.log("[keepalive] 心跳未知(网络/服务端抖动), 不计入失效")
    else:
        with u.lock:
            u._dead["streak"] = 0
            u.state["cookie"].update(valid=False, present=False)
    u.refresh_cookie_state(reload_disk=False)
    return u_ka


def keepalive_loop():
    log("[keepalive] 启动 (多用户模式)")
    while not STOP.is_set():
        root_cfg = load_cfg(readonly=True)
        rts = _all_runtimes()
        min_ka = int(root_cfg.get("keepalive_sec", 300) or 300)
        if len(rts) <= 1:
            for u in rts:
                min_ka = min(min_ka, _keepalive_one(u))
        else:
            with ThreadPoolExecutor(max_workers=min(8, len(rts))) as ex:
                for u_ka in ex.map(_keepalive_one, rts):
                    min_ka = min(min_ka, u_ka)
        _sleep(max(30, min_ka))
    log("[keepalive] 已停止")


def engine_loop():
    log("[engine] 启动 (共享扫描 + 多用户隔离抢报)")
    with GLOBAL_LOCK:
        GLOBAL_STATE["running"] = True
    off = 0.0
    for u in _all_runtimes():
        if u.client.cookie:
            try:
                off = u.client.server_offset(samples=3)
                log("[engine] 服务器时钟偏移 %.3fs" % off)
                break
            except Exception:
                pass
    with GLOBAL_LOCK:
        GLOBAL_STATE["offset"] = off

    rnd = 0
    while not STOP.is_set():
        rnd += 1
        rts = _all_runtimes()
        root_cfg = load_cfg(readonly=True)
        min_interval = int((root_cfg.get("grab") or {}).get("interval_sec", 30) or 30)

        scanners = []
        for u in rts:
            ucfg = u.load_cfg(readonly=True)
            ui = int((ucfg.get("grab") or {}).get("interval_sec", 30) or 30)
            if u.client.cookie:
                if ui < min_interval:
                    min_interval = ui
                # 优先选择当前有效、主管理员且直连的账号扫描全校列表
                with u.lock:
                    v = u.state["cookie"].get("valid")
                scanners.append((
                    0 if v is True else (1 if v is None else 2),
                    0 if u.is_primary else 1,
                    0 if not u.proxy_url else 1,
                    u,
                ))

        with GLOBAL_LOCK:
            GLOBAL_STATE["round"] = rnd

        if not scanners:
            if rnd == 1 or rnd % 20 == 0:
                log("[engine] 尚无任何用户配置有效 cookie, 等待同步…")
            _sleep(min(min_interval, 10))
            continue

        scanners.sort(key=lambda item: item[:3])
        if rnd % 10 == 0:
            for *_, su in scanners:
                try:
                    off = su.client.server_offset(samples=3)
                    with GLOBAL_LOCK:
                        GLOBAL_STATE["offset"] = off
                    break
                except Exception:
                    continue

        uniq = None
        used_scanner = None
        for *_, su in scanners:
            try:
                st, msg, rows = su.client.scan_lectures_ex(statuses=(0,), max_pages=3, page_size=50, stop_when_ended=True)
            except Exception as e:
                st, msg, rows = "error", str(e), None
            if st == "dead":
                su.record_dead_candidate("扫描返回失效(%s)" % msg, source="engine")
                continue
            if st == "ok" and rows is not None:
                su.record_alive()
                uniq = rows
                used_scanner = su
                break
            log("[engine] 扫描网络/服务端抖动(用户=%s): %s" % (su.username, msg))
            break

        with GLOBAL_LOCK:
            GLOBAL_STATE["last_scan"] = nowstr()
            if uniq is not None:
                GLOBAL_STATE["scanned"] = len(uniq)

        if uniq is None:
            _sleep(min_interval)
            continue

        if len(rts) <= 1:
            for u in rts:
                try:
                    u.process_scan_rows(uniq, off, rnd)
                except Exception as e:
                    u.log("[engine] 处理扫描结果异常: %s" % e)
        else:
            def _proc_user(usr):
                try:
                    usr.process_scan_rows(uniq, off, rnd)
                except Exception as e:
                    usr.log("[engine] 处理扫描结果异常: %s" % e)
            with ThreadPoolExecutor(max_workers=min(8, len(rts))) as ex:
                list(ex.map(_proc_user, rts))

        _sleep(max(10, min_interval))
    with GLOBAL_LOCK:
        GLOBAL_STATE["running"] = False
    log("[engine] 已停止")


# ==================== Flask ====================
app = Flask(__name__)


@app.before_request
def _auth_guard():
    if request.path in ("/", "/api/login", "/api/logout", "/api/register", "/api/auth/meta"):
        return None
    root_cfg = load_cfg(readonly=True)
    user_rt, code, msg, retry_after = _check_request_auth(root_cfg)
    if user_rt is not None:
        flask_g.current_user = user_rt
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
    root_cfg = load_cfg(readonly=True)
    user_rt, _, _, _ = _check_request_auth(root_cfg)
    if user_rt is None:
        try:
            with open(LOGIN_PATH, encoding="utf-8") as f:
                return Response(f.read(), mimetype="text/html")
        except Exception:
            return "<h1>login.html 缺失</h1>", 500
    try:
        with open(WEBUI_PATH, encoding="utf-8") as f:
            return Response(f.read(), mimetype="text/html")
    except Exception:
        return "<h1>webui.html 缺失</h1>", 500


@app.route("/api/auth/meta")
def api_auth_meta():
    cfg = load_cfg(readonly=True)
    mu = cfg.get("multi_user") or {}
    return jsonify({
        "configured": _auth_configured(cfg),
        "allow_register": bool(mu.get("allow_register", False)),
        "invite_required": bool(str(mu.get("invite_code") or "").strip()),
    })


@app.route("/api/login", methods=["POST"])
def api_login():
    root_cfg = load_cfg(readonly=True)
    auth = root_cfg.get("auth") or {}
    if auth.get("enabled", True) and not _auth_configured(root_cfg):
        return jsonify({"ok": False, "not_configured": True,
                        "msg": "尚未配置管理员账号密码，请先设置"}), 503

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
    rec = _get_user_auth_record(user, root_cfg) if user else None
    if not rec or rec.get("disabled"):
        _verify_password(pwd, "")  # 恒定时间防用户名枚举
        pwd_ok = False
    else:
        pwd_ok = _verify_password(pwd, rec.get("password_hash", ""))

    if not pwd_ok:
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
    tok, ttl = _make_session_token(rec["username"], root_cfg, rec.get("session_version", 1))
    is_https = request.is_secure or (request.headers.get("X-Forwarded-Proto", "").lower() == "https")
    resp = make_response(jsonify({"ok": True, "username": rec["username"], "role": rec["role"]}))
    resp.set_cookie(SESSION_COOKIE_NAME, tok, max_age=ttl, httponly=True, samesite="Lax", secure=is_https)
    log("[auth] 登录成功 ip=%s user=%s" % (ip, rec["username"]))
    return resp


@app.route("/api/register", methods=["POST"])
def api_register():
    root_cfg = load_cfg(readonly=True)
    if not _auth_configured(root_cfg):
        return jsonify({"ok": False, "msg": "管理员账号尚未初始化"}), 503
    mu = root_cfg.get("multi_user") or {}
    if not mu.get("allow_register"):
        return jsonify({"ok": False, "msg": "管理员未开放自助注册，请联系管理员开通账号"}), 403

    ip = _client_ip()
    allowed, wait_sec = _AUTH_GUARD.check_allowed(ip)
    if not allowed:
        return jsonify({"ok": False, "retry_after": wait_sec, "msg": "操作过于频繁，请稍后再试"}), 429

    data = request.get_json(silent=True) or {}
    need_inv = str(mu.get("invite_code") or "").strip()
    got_inv = str(data.get("invite_code") or "").strip()
    if need_inv and not hmac.compare_digest(got_inv.encode("utf-8"), need_inv.encode("utf-8")):
        _AUTH_GUARD.record_failure(ip)
        return jsonify({"ok": False, "msg": "邀请码不正确"}), 403

    username = str(data.get("username") or "").strip()
    password = str(data.get("password") or "")
    ok, res, _ = _create_subuser(username, password)
    if not ok:
        return jsonify({"ok": False, "msg": res}), 400

    tok, ttl = _make_session_token(username, root_cfg, 1)
    is_https = request.is_secure or (request.headers.get("X-Forwarded-Proto", "").lower() == "https")
    resp = make_response(jsonify({"ok": True, "username": username, "api_token": res}))
    resp.set_cookie(SESSION_COOKIE_NAME, tok, max_age=ttl, httponly=True, samesite="Lax", secure=is_https)
    return resp


@app.route("/api/logout", methods=["POST"])
def api_logout():
    root_cfg = load_cfg(readonly=True)
    tok = request.cookies.get(SESSION_COOKIE_NAME, "")
    if tok:
        _revoke_session_token(tok, root_cfg)
    resp = make_response(jsonify({"ok": True}))
    resp.set_cookie(SESSION_COOKIE_NAME, "", max_age=0, httponly=True, samesite="Lax")
    return resp


@app.route("/api/status")
def api_status():
    u = flask_g.current_user
    with GLOBAL_LOCK:
        gs = dict(GLOBAL_STATE)
    off = gs.get("offset") or 0.0
    now = g.srv_now(off)
    with u.lock:
        ck = u.state["cookie"]
        eng = u.state["engine"]
        cands = [
            {"did": d, "title": v.get("title", ""), "lvl": v.get("lvl", ""), "tsu": v.get("tsu", ""),
             "ltime": v.get("ltime", ""),
             "auto": v.get("auto", False), "manual": v.get("manual", False),
             "status": v.get("status", "waiting"), "countdown": round((v.get("tgt") or now) - now)}
            for d, v in eng["locked"].items()
            if v.get("status", "waiting") in ("waiting", "grabbing")
        ]
        st = {
            "started_at": u.state["started_at"],
            "user": {"username": u.username, "role": u.role, "proxy_enabled": bool(u.proxy_url)},
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
                "running": gs.get("running", False),
                "round": gs.get("round", 0),
                "last_scan": gs.get("last_scan", ""),
                "offset": off,
                "scanned": gs.get("scanned", 0),
                "fired": list(eng.get("fired") or []),
                "candidates": cands,
                "won": [dict(w) for w in (eng.get("won") or [])],
            },
            "college": dict(u.state["college"]),
            "events": [dict(e) for e in (u.state["events"] or [])],
        }
    st["cfg"] = _public_cfg(u.load_cfg(readonly=True))
    st["now"] = nowstr()
    return jsonify(st)


@app.route("/api/logs")
def api_logs():
    u = flask_g.current_user
    try:
        seq = int(request.args.get("since", 0) or 0)
    except ValueError:
        seq = 0
    lines = LOGBUF.since(seq) if u.is_primary else u.logs.since(seq)
    return jsonify({"lines": lines, "seq": (lines[-1]["seq"] if lines else seq)})


@app.route("/api/config", methods=["GET", "POST"])
def api_config():
    u = flask_g.current_user
    if request.method == "GET":
        return jsonify(_public_cfg(u.load_cfg(readonly=True)))
    c = u.load_cfg()
    data = request.get_json(silent=True) or {}
    grab = data.get("grab")
    if isinstance(grab, dict):
        for k in ("xiao_watch", "xiao_auto", "xiao_campus", "yuan_watch", "yuan_auto",
                  "yuan_college_only", "yuan_campus", "keywords", "interval_sec", "force"):
            if k in grab:
                c.setdefault("grab", {})[k] = grab[k]
        c.setdefault("grab", {}).pop("levels", None)
        c["grab"].pop("auto", None)
    if "keepalive_sec" in data:
        c["keepalive_sec"] = int(data["keepalive_sec"])
    d = data.get("dingtalk")
    if isinstance(d, dict):
        for k in ("notify_events", "prefix", "webhook", "secret"):
            if k in d:
                c.setdefault("dingtalk", {})[k] = d[k]
    u.save_cfg(c)
    u.log("[config] 已更新 grab=%s keepalive=%s" % (json.dumps(c.get("grab"), ensure_ascii=False), c.get("keepalive_sec")))
    return jsonify({"ok": True, "cfg": _public_cfg(c)})


@app.route("/api/cookie", methods=["POST"])
def api_cookie():
    u = flask_g.current_user
    data = request.get_json(silent=True) or {}
    cookie = data.get("cookie", "")
    if not cookie and data.get("session_id"):
        cookie = "PG.ASP.Session.ID=%s; PG.ASP.WeiXinCode.ID=%s" % (
            data.get("session_id"), data.get("weixin_code_id", ""))
    meta = {"captured_at": data.get("captured_at"), "student": data.get("student")}
    alive, res = u.apply_cookie(cookie, meta=meta, source=data.get("source", "webui"))
    return jsonify({"ok": alive, "valid": alive, "result": res})


@app.route("/api/reload-cookie", methods=["POST"])
def api_reload():
    u = flask_g.current_user
    d = u.read_token_file()
    ck = d.get("cookie", "")
    if not ck:
        return jsonify({"ok": False, "valid": False, "msg": "token.json 无 cookie"})
    alive, res = u.apply_cookie(ck, meta=d, source="reload")
    return jsonify({"ok": alive, "valid": alive})


@app.route("/api/scan", methods=["POST"])
def api_scan():
    u = flask_g.current_user
    if not u.client.cookie:
        return jsonify({"ok": False, "msg": "无 cookie"})
    body = request.get_json(silent=True) or {}
    lvl_filter = str(body.get("level", "") or "").strip()
    scan_st, scan_msg, uniq = u.client.scan_lectures_ex(statuses=(0,), max_pages=3, page_size=50)
    if scan_st == "dead":
        return jsonify({"ok": False, "msg": "cookie 失效(%s)" % scan_msg})
    if scan_st != "ok" or uniq is None:
        return jsonify({"ok": False, "msg": "扫描请求异常(%s)" % scan_msg})
    mc, _ = u.client.my_college()
    with u.lock:
        active = {d for d, v in u.state["engine"]["locked"].items()
                  if v.get("status") in ("waiting", "grabbing")}
        won_list = list(u.state["engine"].get("won", []))
        won_dids = {w.get("did") for w in won_list}
    won_map = {w.get("did"): w for w in won_list}
    rows = []
    for x in uniq:
        did, st, title, tsu, lts, lvl = g._row_fields(x)
        if lvl_filter and lvl != lvl_filter:
            continue
        cap = x.get("Capacity")
        sign = x.get("SignupNum")
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
    rows.sort(key=lambda r: (r["st"] == 4, r["st"] == 2, str(r["tsu"])))
    threading.Thread(target=_campus_filler, args=(uniq, u.client), daemon=True).start()
    with GLOBAL_LOCK:
        GLOBAL_STATE["last_scan"] = nowstr()
        GLOBAL_STATE["scanned"] = len(uniq)
    return jsonify({"ok": True, "count": len(uniq), "shown": len(rows), "rows": rows[:200]})


@app.route("/api/grab", methods=["POST"])
def api_grab():
    u = flask_g.current_user
    data = request.get_json(silent=True) or {}
    did = str(data.get("did", "") or "").strip()
    if not did:
        return jsonify({"ok": False, "msg": "缺少 did"})
    if not u.client.cookie:
        return jsonify({"ok": False, "msg": "无 cookie, 请先同步"})
    force_def = bool(u.load_cfg(readonly=True).get("grab", {}).get("force", False))
    return jsonify(u.arm_grab(did, str(data.get("title", "") or "")[:60], str(data.get("tsu", "") or ""),
                              str(data.get("lvl", "") or "校级"),
                              bool(data.get("force", force_def)),
                              ltime=str(data.get("ltime", "") or "")))


@app.route("/api/won", methods=["POST"])
def api_won():
    u = flask_g.current_user
    data = request.get_json(silent=True) or {}
    act = str(data.get("action", "") or "")
    did = str(data.get("did", "") or "").strip()
    if not did:
        return jsonify({"ok": False, "msg": "缺少 did"})
    with u.lock:
        won = u.state["engine"].setdefault("won", [])
        entry = next((w for w in won if w.get("did") == did), None)
        if not entry:
            return jsonify({"ok": False, "msg": "不在已抢到清单"})
        won.remove(entry)
    u.save_won()
    if act == "remove":
        u.log("[won] 已移除卡片: 《%s》" % str(entry.get("title"))[:30])
        return jsonify({"ok": True, "msg": "已移除"})
    if act == "rearm":
        if not u.client.cookie:
            with u.lock:
                u.state["engine"].setdefault("won", []).insert(0, entry)
            u.save_won()
            return jsonify({"ok": False, "msg": "无 cookie, 请先同步"})
        u.log("[续抢] 重新武装: 《%s》" % str(entry.get("title"))[:30])
        force_def = bool(u.load_cfg(readonly=True).get("grab", {}).get("force", False))
        return jsonify(u.arm_grab(did, str(entry.get("title", ""))[:60], str(entry.get("tsu", "") or ""),
                                  str(entry.get("lvl", "") or "校级"), force_def,
                                  ltime=str(entry.get("ltime", "") or "")))
    with u.lock:
        u.state["engine"].setdefault("won", []).insert(0, entry)
    u.save_won()
    return jsonify({"ok": False, "msg": "未知操作"})


@app.route("/api/pick", methods=["POST"])
def api_pick():
    u = flask_g.current_user
    data = request.get_json(silent=True) or {}
    act = str(data.get("action", "remove"))
    did = str(data.get("did", "") or "").strip()

    if act == "add":
        if not did:
            return jsonify({"ok": False, "msg": "缺少 did"})
        if not u.client.cookie:
            return jsonify({"ok": False, "msg": "无 cookie, 请先同步"})
        title = str(data.get("title", "") or "")[:60]
        tsu = str(data.get("tsu", "") or "")
        lvl = str(data.get("lvl", "") or "校级")
        ltime = str(data.get("ltime", "") or "")
        lts = str(data.get("lts", "") or "")
        tgt = g.parse_cn_epoch(tsu) if tsu else None
        with GLOBAL_LOCK:
            off = GLOBAL_STATE.get("offset") or 0.0
        now = g.srv_now(off)
        if tgt is None:
            tgt = now
        with u.lock:
            locked = u.state["engine"]["locked"]
            fired = u.state["engine"]["fired"]
            ign = u.state["engine"].setdefault("ignored", [])
            if did in ign:
                ign.remove(did)
            already_open = (tgt - now) <= g.LEAD + 1
            v = locked.get(did) or {}
            keep = v.get("status") if v.get("status") in ("grabbing", "success") else "waiting"
            v.update({"title": title or v.get("title") or did, "tsu": tsu or v.get("tsu", ""),
                      "lvl": lvl or v.get("lvl", "校级"), "tgt": tgt, "manual": True, "auto": True,
                      "locked_at": v.get("locked_at") or nowstr(), "brief": v.get("brief", ""),
                      "ltime": ltime or v.get("ltime", ""),
                      "lts_epoch": g.parse_cn_epoch(lts) or v.get("lts_epoch", 0),
                      "open_notified": True, "status": keep})
            if keep == "waiting":
                v["fail_count"] = 0
                if did in fired:
                    fired.remove(did)
            locked[did] = v
            vt, vs = v["title"], v["status"]
        u.save_picked()
        if vs != "waiting":
            return jsonify({"ok": True, "mode": "已在清单", "msg": "该项已在待抢清单(%s)" % vs})
        if already_open:
            u.log("[待抢] 加入清单(已开放, 监测捡漏) did=%s title=%s" % (did[:8], vt))
            return jsonify({"ok": True, "mode": "已加入待抢", "msg": "已开放报名, 已加入待抢清单监测捡漏"})
        u.log("[待抢] 加入清单(未到点, 到点自动抢) did=%s tgt=%s" % (did[:8], tsu))
        return jsonify({"ok": True, "mode": "已加入待抢", "msg": "已加入待抢清单, 到 %s 自动开火" % (tsu or "点")})

    with u.lock:
        locked = u.state["engine"]["locked"]
        fired = u.state["engine"]["fired"]
        if act == "clear":
            rm = [d for d, v in locked.items() if v.get("manual") and v.get("status") != "grabbing"]
            ign = u.state["engine"].setdefault("ignored", [])
            for d in rm:
                del locked[d]
                if d in fired:
                    fired.remove(d)
                if d not in ign:
                    ign.append(d)
            u.save_picked()
            u.save_ignored()
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
            ign = u.state["engine"].setdefault("ignored", [])
            if did not in ign:
                ign.append(did)
            u.save_picked()
            u.save_ignored()
            u.log("[待抢] 已取消 did=%s" % did[:8])
            return jsonify({"ok": True})
    return jsonify({"ok": False, "msg": "未知 action"})


@app.route("/api/test-notify", methods=["POST"])
def api_test_notify():
    u = flask_g.current_user
    n = notify_mod.get_notifier(u.load_cfg(readonly=True))
    if not n:
        return jsonify({"ok": False, "msg": "未配置 dingtalk.webhook"})
    res = n.text("WebUI 测试推送 ✅ (%s / %s)" % (u.username, nowstr()))
    return jsonify({"ok": res.get("errcode") == 0, "result": res})


@app.route("/api/engine", methods=["POST"])
def api_engine():
    u = flask_g.current_user
    data = request.get_json(silent=True) or {}
    if data.get("action") == "reset":
        with u.lock:
            u.state["engine"]["locked"] = {}
            u.state["engine"]["fired"] = []
            u.state["engine"]["candidates"] = []
            u.state["engine"]["ignored"] = []
        u.save_picked()
        u.save_ignored()
        u.log("[engine] 已重置锁定/开火/手选/忽略清单")
        return jsonify({"ok": True})
    return jsonify({"ok": False, "msg": "未知 action"})


@app.route("/api/account", methods=["GET", "POST"])
def api_account():
    u = flask_g.current_user
    root_cfg = load_cfg()
    rec = _get_user_auth_record(u.username, root_cfg)
    if not rec:
        return jsonify({"ok": False, "msg": "用户不存在"}), 404
    if request.method == "GET":
        return jsonify({"ok": True, "username": u.username, "role": u.role, "api_token": rec.get("api_token", "")})

    data = request.get_json(silent=True) or {}
    act = str(data.get("action") or "")
    if act == "rotate_token":
        new_tok = secrets.token_hex(24)
        if u.is_primary:
            root_cfg.setdefault("auth", {})["api_token"] = new_tok
            save_cfg(root_cfg)
        else:
            with USERS_LOCK:
                if u.username in USERS_META:
                    USERS_META[u.username]["api_token"] = new_tok
                    _save_users_meta()
        return jsonify({"ok": True, "api_token": new_tok})
    if act == "password":
        old_pw = str(data.get("old_password") or "")
        new_pw = str(data.get("new_password") or "")
        if len(new_pw) < 6:
            return jsonify({"ok": False, "msg": "新密码至少 6 位"}), 400
        if not _verify_password(old_pw, rec.get("password_hash", "")):
            return jsonify({"ok": False, "msg": "原密码不正确"}), 403
        new_hash = _hash_password(new_pw)
        if u.is_primary:
            auth = root_cfg.setdefault("auth", {})
            auth["password_hash"] = new_hash
            auth["session_version"] = int(auth.get("session_version", 1) or 1) + 1
            save_cfg(root_cfg)
        else:
            with USERS_LOCK:
                if u.username in USERS_META:
                    USERS_META[u.username]["password_hash"] = new_hash
                    USERS_META[u.username]["session_version"] = int(USERS_META[u.username].get("session_version", 1) or 1) + 1
                    _save_users_meta()
        return jsonify({"ok": True, "msg": "密码已修改，请重新登录"})
    return jsonify({"ok": False, "msg": "未知操作"}), 400


@app.route("/api/admin/users", methods=["GET", "POST"])
def api_admin_users():
    u = flask_g.current_user
    if u.role != "admin":
        return jsonify({"ok": False, "msg": "仅管理员可管理多用户"}), 403
    root_cfg = load_cfg()

    if request.method == "GET":
        items = []
        prim = _primary_username(root_cfg) or "admin"
        with USERS_LOCK:
            all_names = [prim] + sorted(USERS_META.keys())
            for nm in all_names:
                rec = _get_user_auth_record(nm, root_cfg) or {}
                rt = USER_RUNTIMES.get(nm)
                ck_valid = None
                stu_nm = ""
                won_cnt = 0
                cand_cnt = 0
                if rt is not None:
                    with rt.lock:
                        ck_valid = rt.state["cookie"].get("valid")
                        stu = rt.state["cookie"].get("student") or {}
                        stu_nm = str(stu.get("Name") or stu.get("StudentId") or "")
                        won_cnt = len(rt.state["engine"].get("won") or [])
                        cand_cnt = len(rt.state["engine"].get("candidates") or [])
                items.append({
                    "username": nm,
                    "role": rec.get("role", "user"),
                    "is_primary": bool(rec.get("is_primary")),
                    "disabled": bool(rec.get("disabled")),
                    "api_token": rec.get("api_token", ""),
                    "proxy_url": rec.get("proxy_url", ""),
                    "cookie_valid": ck_valid,
                    "student": stu_nm,
                    "won_count": won_cnt,
                    "candidates_count": cand_cnt,
                    "created_at": rec.get("created_at", ""),
                })
        mu = root_cfg.get("multi_user") or {}
        return jsonify({
            "ok": True,
            "users": items,
            "multi_user": {
                "allow_register": bool(mu.get("allow_register", False)),
                "invite_code": str(mu.get("invite_code") or ""),
                "cofire_throttle": bool(mu.get("cofire_throttle", True)),
                "admin_priority": bool(mu.get("admin_priority", True)),
            },
        })

    data = request.get_json(silent=True) or {}
    act = str(data.get("action") or "")
    if act == "settings":
        mu = root_cfg.setdefault("multi_user", {})
        if "allow_register" in data:
            mu["allow_register"] = bool(data["allow_register"])
        if "invite_code" in data:
            mu["invite_code"] = str(data["invite_code"] or "").strip()
        if "cofire_throttle" in data:
            mu["cofire_throttle"] = bool(data["cofire_throttle"])
        if "admin_priority" in data:
            mu["admin_priority"] = bool(data["admin_priority"])
        save_cfg(root_cfg)
        return jsonify({"ok": True})
    if act == "create":
        ok, res, _ = _create_subuser(data.get("username", ""), data.get("password", ""))
        if not ok:
            return jsonify({"ok": False, "msg": res}), 400
        return jsonify({"ok": True, "api_token": res})

    target = str(data.get("username") or "").strip()
    prim = _primary_username(root_cfg) or "admin"
    if act == "set_proxy":
        ok_p, clean_p = _normalize_proxy_url(data.get("proxy_url", ""))
        if not ok_p:
            return jsonify({"ok": False, "msg": clean_p}), 400
        if not target:
            return jsonify({"ok": False, "msg": "缺少用户名"}), 400
        if target == prim:
            root_cfg.setdefault("auth", {})["proxy_url"] = clean_p
            save_cfg(root_cfg)
            with USERS_LOCK:
                rt = USER_RUNTIMES.get(prim)
            if rt is not None:
                rt.set_proxy(clean_p)
                rt.log("[proxy] 已更新主管理员出口代理: %s" % (clean_p or "直连"))
            return jsonify({"ok": True, "proxy_url": clean_p})
        with USERS_LOCK:
            rec = USERS_META.get(target)
            if not rec:
                return jsonify({"ok": False, "msg": "用户不存在"}), 404
            rec["proxy_url"] = clean_p
            _save_users_meta()
            rt = USER_RUNTIMES.get(target)
        if rt is not None:
            rt.set_proxy(clean_p)
            rt.log("[proxy] 管理员已更新出口代理: %s" % (clean_p or "直连"))
        return jsonify({"ok": True, "proxy_url": clean_p})

    if not target or target == prim:
        return jsonify({"ok": False, "msg": "不能通过多用户面板修改主管理员"}), 400

    with USERS_LOCK:
        rec = USERS_META.get(target)
        if not rec:
            return jsonify({"ok": False, "msg": "用户不存在"}), 404
        if act == "toggle":
            rec["disabled"] = not bool(rec.get("disabled"))
            if rec["disabled"]:
                USER_RUNTIMES.pop(target, None)
            else:
                rt = UserRuntime(target, role="user", is_primary=False)
                rt.set_proxy(rec.get("proxy_url", ""))
                rt.boot()
                USER_RUNTIMES[target] = rt
            _save_users_meta()
            return jsonify({"ok": True, "disabled": rec["disabled"]})
        if act == "rotate_token":
            rec["api_token"] = secrets.token_hex(24)
            _save_users_meta()
            return jsonify({"ok": True, "api_token": rec["api_token"]})
        if act == "reset_password":
            npw = str(data.get("password") or "")
            if len(npw) < 6:
                return jsonify({"ok": False, "msg": "密码至少 6 位"}), 400
            rec["password_hash"] = _hash_password(npw)
            rec["session_version"] = int(rec.get("session_version", 1) or 1) + 1
            _save_users_meta()
            return jsonify({"ok": True})
        if act == "delete":
            del USERS_META[target]
            USER_RUNTIMES.pop(target, None)
            _save_users_meta()
            if data.get("purge_data"):
                shutil.rmtree(os.path.join(USERS_DIR, target), ignore_errors=True)
            return jsonify({"ok": True})
    return jsonify({"ok": False, "msg": "未知 action"}), 400


def _cli_set_auth(args):
    idx = args.index("--set-auth")
    rest = args[idx + 1:]
    username = rest[0].strip() if len(rest) >= 1 else input("WebUI 管理员账号: ").strip()
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
    print("[✓] 已更新主管理员凭据: username=%s (写入 %s)" % (username, CFG_PATH))
    print("[i] api_token=%s" % auth["api_token"])


def _cli_add_user(args):
    idx = args.index("--add-user")
    rest = args[idx + 1:]
    username = rest[0].strip() if len(rest) >= 1 else input("新增同门账号: ").strip()
    if len(rest) >= 2:
        password = rest[1]
    else:
        password = getpass.getpass("初始密码(至少6位): ")
    _init_all_users()
    ok, res, _ = _create_subuser(username, password)
    if not ok:
        print("[!] 添加失败: %s" % res)
        sys.exit(2)
    print("[✓] 已添加同门账号: username=%s" % username)
    print("[i] 专属 API Token: %s" % res)


def main():
    if "--set-auth" in sys.argv[1:]:
        _cli_set_auth(sys.argv[1:])
        return
    if "--add-user" in sys.argv[1:]:
        _cli_add_user(sys.argv[1:])
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

    sys.stdout = Tee(sys.__stdout__)
    _init_all_users()
    rts = _all_runtimes()
    log("=" * 62)
    log("[boot] 同济高等讲堂·抢讲座服务启动 (原生多用户版)  %s" % nowstr())
    log("[boot] 数据目录=%s  已加载用户数=%d  WebUI鉴权=%s" % (
        DATA_DIR, len(rts), "已配置" if _auth_configured(cfg) else "未设置(请先 --set-auth)"))

    threading.Thread(target=keepalive_loop, daemon=True).start()
    threading.Thread(target=engine_loop, daemon=True).start()
    host = (os.environ.get("TJ_HOST") or cfg.get("webui", {}).get("host", "0.0.0.0")).strip()
    port = int(os.environ.get("TJ_PORT") or cfg.get("webui", {}).get("port", 8848))
    log("[boot] WebUI 监听 http://%s:%d" % (host, port))
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
