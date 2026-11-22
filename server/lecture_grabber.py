#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
同济高等讲堂 · 抢讲座报名脚本  (逆向分析产物)
站点: https://lecture.tongji.edu.cn  (微信公众号 H5, 微信 AppID wx82f715ccc13c779c)

========================= 逆向结论速览 =========================
1. /index 直接访问 404, 因为它是 Vue(history 模式) 的前端路由; 真正入口是 "/"。
   微信里点按钮 -> OAuth -> 回到 "/?iswechat=true&code=xxx" -> 前端换 token -> 客户端跳 /index。
2. 后端 ASP.NET, 统一响应信封: {"state":"success"|"fail","msg":...,"data":...,"code":...}
3. 认证 = Authorization(固定 Basic) + 会话 Cookie  【实测地面真相】:
     Authorization: Basic <固定, 所有用户相同>
     Cookie: PG.ASP.Session.ID=<会话>; PG.ASP.WeiXinCode.ID=<微信绑定>
   实测【没有 token 请求头】! 登录态完全由这两个 ASP.NET 会话 Cookie 承载。
   没有学号密码登录, Cookie 只能从一次真实微信登录里抓取(capture_token.py 自动完成)。
4. 抢报名动作链:
     SetCredentials(dataId)  -> 拿到 credentialsCode (动态凭证, 进详情页即下发)
     GetCredentials(code)    -> 返回 iscode(此刻是否有效); 前端越接近报名开始时间刷新越频繁
     GetIsFinishFace()       -> 必须已完成人脸录入, 否则报名被拦
     SginInLectureHallCredentials(code) -> 【报名动作】(名字带 SignIn, 实为报名)
     GetSginInTime(dataId)   -> 轮询结果: data.state==1 => 报名成功, ==-1 => 失败
5. 讲座状态 LectureHallStatus(以服务端 LectureHallStatusName 为准): 1=可报名(有余位) 2=已报满 3=未开始报名 4=已结束
   关键字段: DataId / Cathedra(讲座标题) / TimeSigningUp(报名开始) / LectureTimeStart / NameSpeaker
   院级(ClassLevel=2)讲座可能限本院报名(SetCredentials 返回"无报名资格!"); 校级(ClassLevel=1)通常全员可报。

========================= 用法 =========================
  0) 先抓登录态: python capture_token.py   (自动抓取会话Cookie写入 token.json)
  1) python lecture_grabber.py discover                 # 验证凭据, dump 全部接口真实响应
  2) python lecture_grabber.py find                     # 列出可报名/即将报名的讲座及 DataId
  3) python lecture_grabber.py pick                     # 交互式选场次(可多选 1,3,5 / 2-4) -> 定点猛攻
  4) python lecture_grabber.py detail <DataId>          # 看某讲座详情/报名时间/凭证
  5) python lecture_grabber.py grab <DataId> [DataId2 ...]  # 对一个/多个 DataId 定时猛攻
  6) python lecture_grabber.py watch [--level=校级] [--keyword=关键词] [--interval=60] [--no-auto]
        值守模式: 持续轮询, 发现'未来开报'的目标场次自动锁定, 到各自 TimeSigningUp 自动猛攻。
        实测: 校级讲座固定 12:30 开报、周五最密集且全员可报(不会'无报名资格'), 故默认只盯校级。
"""

import sys
import os
import json
import time
import calendar
import statistics
import threading
import datetime as dt
from concurrent.futures import ThreadPoolExecutor, as_completed, TimeoutError as FuturesTimeoutError
from http.cookiejar import DefaultCookiePolicy

import requests

# 让 Windows 控制台正确显示中文
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# ==================== 配置 ====================
BASE = "https://lecture.tongji.edu.cn"
AUTHORIZATION = "Basic cTN4YXRwbTV0eHc0MmtoejVjYzg1YWY0OmI1dTRteWVrZDVkYno0cGUxcTFoY3dnb3h4eXR0bTM3"

# 【主认证】会话 Cookie: PG.ASP.Session.ID=xxx; PG.ASP.WeiXinCode.ID=yyy
# 通常由 capture_token.py 自动抓取写入 token.json, 下面 _autoload_token() 自动读入;
# 也可手动粘这里或设环境变量 TJ_LECTURE_COOKIE。
COOKIE = os.environ.get("TJ_LECTURE_COOKIE", "").strip()

# (兼容保留) 若某环境确实用 token 头, 可填这里; 实测本站不用。
TOKEN = os.environ.get("TJ_LECTURE_TOKEN", "").strip()


# 自动从同目录 token.json 读取(由 capture_token.py / token_sniffer.py 自动抓取写入);
# 手动填的 TOKEN/COOKIE 优先。
def _autoload_token():
    global TOKEN, COOKIE
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "token.json")
    if not os.path.exists(p):
        return
    try:
        with open(p, encoding="utf-8") as f:
            d = json.load(f)
    except Exception:
        return
    if not TOKEN and d.get("token"):
        TOKEN = str(d["token"]).strip()
    if not COOKIE and d.get("cookie"):
        COOKIE = str(d["cookie"]).strip()


_autoload_token()

# 实测抓到的 微信PC 内置浏览器 UA(与登录会话一致, 降低被风控概率)
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/144.0.0.0 Safari/537.36 NetType/WIFI MicroMessenger/7.0.20.1781(0x6700143B) "
      "WindowsWechat(0x63090a13) UnifiedPCWindowsWechat(0xf2541d41) XWEB/25560")
REFERER = BASE + "/index"

TIMEOUT = 2.5           # 单请求超时(秒): 止损点而非失败点, 超时就补发下一发
GRAB_DEADLINE = 60      # 抢报名总窗口(秒): 从开火时刻起持续猛攻多久
BURST = 5               # 每轮并发发数
VOLLEY_INTERVAL = 0.12  # 每轮之间的间隔(秒)
LEAD = 0.4              # 提前开火量(秒): 抵消 RTT, 让第一发正好落在报名开启瞬间
CLOCK_SAMPLES = 5       # 服务器时钟同步采样次数

# ==================== 端点映射 (逆向得到) ====================
EP = {
    "StudentInfo":  "/api/gj/studentwx/studentapi/StudentInfo",
    "IsFinishFace": "/api/gj/studentwx/studentapi/GetIsFinishFace",
    "HallNum":      "/api/gj/studentwx/studentapi/GetLectureHallNum",
    "SetCred":      "/api/gj/studentwx/studentapi/SetCredentials",
    "GetCred":      "/api/gj/studentwx/studentapi/GetCredentials",
    "SignUp":       "/api/gj/studentwx/studentapi/SginInLectureHallCredentials",
    "SignInTime":   "/api/gj/studentwx/studentapi/GetSginInTime",
    "Cancel":       "/api/gj/studentwx/studentapi/CancelLectureHall",
    "HallList":     "/api/gj/studentwx/lecturehallapi/GetLectureHallList",
    "Hall":         "/api/gj/studentwx/lecturehallapi/GetLectureHall",
    "Hall30":       "/api/gj/studentwx/lecturehallapi/GetLectureHall30",
    "MonthHall":    "/api/gj/studentwx/lecturehallapi/GetMonthLectureHall",
    "WxIndex":      "/api/gj/manage/weixinapi/Index",
}

STATUS_TEXT = {0: "全部", 1: "可报名(有余位)", 2: "已报满", 3: "未开始报名", 4: "已结束"}

def _unwrap(resp):
    """把 requests.Response 解成后端 JSON 信封; 解析失败时返回原始文本。"""
    try:
        return resp.json()
    except Exception:
        return {"state": "error", "msg": "非JSON响应", "raw": resp.text[:500],
                "http": resp.status_code}


class TongjiClient:
    """单用户隔离的同济高等讲堂 API 客户端 (独立 Cookie、代理路由、学院缓存与 HTTP 连接池)。"""

    def __init__(self, cookie="", token="", pool_connections=8, pool_maxsize=32, proxy_url=""):
        self.cookie = (cookie or "").strip()
        self.token = (token or "").strip()
        self.proxy_url = ""
        self._college_lock = threading.Lock()
        self._student_college = {"code": None, "name": None}
        self._session = requests.Session()
        self._session.trust_env = False  # 忽略系统代理(抓包时的 mitmproxy), 抢课默认直连, 降延迟
        try:
            self._session.cookies.set_policy(DefaultCookiePolicy(allowed_domains=[]))
        except Exception:
            pass
        try:
            from requests.adapters import HTTPAdapter
            adapter = HTTPAdapter(pool_connections=pool_connections, pool_maxsize=pool_maxsize)
            self._session.mount("https://", adapter)
            self._session.mount("http://", adapter)
        except Exception:
            pass
        self.set_proxy(proxy_url)

    def set_proxy(self, proxy_url=""):
        """为当前用户会话设置独立出口代理 (如 mihomo http://127.0.0.1:7891); 留空则直连。"""
        p = (proxy_url or "").strip()
        self.proxy_url = p
        self._session.proxies = {"http": p, "https": p} if p else {}

    def set_cookie(self, cookie, token=None):
        self.cookie = (cookie or "").strip()
        if token is not None:
            self.token = str(token).strip()
        self.reset_student_cache()

    def reset_student_cache(self):
        with self._college_lock:
            self._student_college["code"] = None
            self._student_college["name"] = None

    def _hdr_json(self, cookie=None):
        ck = self.cookie if cookie is None else cookie
        h = {"Authorization": AUTHORIZATION, "User-Agent": UA, "Referer": REFERER,
             "Accept": "application/json, text/plain, */*",
             "Accept-Encoding": "gzip, deflate",
             "Content-Type": "application/json;charset=UTF-8"}
        if ck:
            h["Cookie"] = ck
        if self.token:
            h["token"] = self.token
        return h

    def _hdr_form(self, cookie=None):
        ck = self.cookie if cookie is None else cookie
        h = {"Authorization": AUTHORIZATION, "User-Agent": UA, "Referer": REFERER,
             "Accept": "application/json, text/plain, */*",
             "Accept-Encoding": "gzip, deflate", "Origin": BASE}
        if ck:
            h["Cookie"] = ck
        if self.token:
            h["token"] = self.token
        return h

    def get(self, path, params=None, cookie=None):
        try:
            r = self._session.get(BASE + path, params=params, headers=self._hdr_json(cookie=cookie), timeout=TIMEOUT)
            return _unwrap(r)
        except requests.RequestException as e:
            return {"state": "error", "msg": "请求异常: %s" % e}

    def post_form(self, path, fields):
        try:
            files = {k: (None, str(v)) for k, v in fields.items()}
            r = self._session.post(BASE + path, files=files, headers=self._hdr_form(), timeout=TIMEOUT)
            return _unwrap(r)
        except requests.RequestException as e:
            return {"state": "error", "msg": "请求异常: %s" % e}

    def api_student_info(self, cookie=None):
        return self.get(EP["StudentInfo"], cookie=cookie)

    def api_is_finish_face(self):
        return self.get(EP["IsFinishFace"])

    def api_hall_num(self):
        return self.get(EP["HallNum"])

    def api_hall_list(self, page=1, page_size=10, status=0, time_=0, class_level=0):
        return self.get(EP["HallList"], {"page": page, "pageSize": page_size,
                                         "status": status, "time": time_, "classLevel": class_level})

    def api_hall(self, data_id):
        return self.get(EP["Hall"], {"DataId": data_id})

    def api_hall30(self):
        return self.get(EP["Hall30"])

    def api_month_hall(self, year, month):
        return self.get(EP["MonthHall"], {"year": year, "month": month})

    def api_set_credentials(self, data_id):
        return self.post_form(EP["SetCred"], {"dataId": data_id})

    def api_get_credentials(self, code):
        return self.post_form(EP["GetCred"], {"code": code})

    def api_signup(self, code):
        return self.post_form(EP["SignUp"], {"code": code})

    def api_signin_time(self, data_id):
        return self.post_form(EP["SignInTime"], {"dataId": data_id})

    def api_cancel(self, data_id):
        return self.post_form(EP["Cancel"], {"dataId": data_id})

    def server_offset(self, samples=CLOCK_SAMPLES):
        offs = []
        for _ in range(samples):
            t0 = time.time()
            r = self.api_hall_list(page=1, page_size=1, status=0)
            t1 = time.time()
            nt = (r.get("data") or {}).get("nowtime") if isinstance(r, dict) else None
            srv = _parse_iso_epoch(nt) if nt else None
            if srv:
                offs.append(srv - (t0 + t1) / 2.0)
                continue
            try:
                rr = self._session.get(BASE + "/", headers={"User-Agent": UA}, timeout=TIMEOUT)
                d = rr.headers.get("Date")
                t2 = time.time()
                if d:
                    srv = calendar.timegm(time.strptime(d, "%a, %d %b %Y %H:%M:%S GMT"))
                    offs.append(srv - (t0 + t2) / 2.0)
            except requests.RequestException:
                continue
        return statistics.median(offs) if offs else 0.0

    def my_college(self):
        with self._college_lock:
            if self._student_college["code"] is not None:
                return self._student_college["code"], self._student_college["name"]
        info = (self.api_student_info().get("data") or {})
        code = str(info.get("Faculty") or info.get("CollegeCode") or "")
        name = str(info.get("FacultyNmae") or info.get("CollegeCodeName") or "")
        if code or info:
            with self._college_lock:
                self._student_college["code"] = code
                self._student_college["name"] = name
        return code, name

    def scan_lectures_ex(self, statuses=(0,), max_pages=3, page_size=50, stop_when_ended=False):
        all_rows = []
        for status in statuses:
            page = 1
            while page <= max_pages:
                r = self.api_hall_list(page=page, page_size=page_size, status=status)
                if not token_alive(r):
                    return "dead", str(r.get("msg") or "未登录/超时"), None
                if not isinstance(r, dict) or r.get("state") == "error":
                    if not all_rows:
                        return "error", str((r or {}).get("msg") or "扫描请求异常"), None
                    break
                data = r.get("data") or {}
                rows = data.get("row") or []
                if not rows:
                    break
                for x in rows:
                    x["_q"] = status
                all_rows.extend(rows)
                try:
                    total_page = int(data.get("totalPage") or 0)
                except (TypeError, ValueError):
                    total_page = 0
                if len(rows) < page_size or (total_page > 0 and page >= total_page):
                    break
                if stop_when_ended and len(rows) >= 10 and all(x.get("LectureHallStatus") == 4 for x in rows[-10:]):
                    break
                page += 1
        seen, uniq = set(), []
        for x in all_rows:
            did = x.get("DataId") or x.get("dataId")
            if did in seen:
                continue
            seen.add(did)
            uniq.append(x)
        return "ok", "", uniq

    def _acquire_code(self, data_id):
        sc = self.api_set_credentials(data_id)
        code = (sc.get("data") or {}).get("code") if isinstance(sc, dict) else None
        return code, sc

    def _confirm_signup(self, data_id, tries=6, delay=1.0, P=None):
        def _p(s):
            if P:
                P(s)
        last = "未确认"
        for i in range(max(1, tries)):
            try:
                chk = self.api_signin_time(data_id)
                dat = (chk.get("data") or {}) if isinstance(chk, dict) else {}
                s2 = dat.get("state")
                if s2 in (1, "1"):
                    return True, "GetSginInTime.state=1 signUpTime=%s" % dat.get("signUpTime")
                dd = (self.api_hall(data_id).get("data") or {})
                xs = dd.get("XSSigningUp")
                if xs:
                    return True, "XSSigningUp=%s (我的报名时间非空)" % xs
                if s2 in (-1, "-1"):
                    return False, "GetSginInTime.state=-1 报名失败 msg=%s" % (
                        chk.get("msg") if isinstance(chk, dict) else "")
                last = "GetSginInTime.state=%s signUpTime=%s XSSigningUp=%s" % (
                    s2, dat.get("signUpTime"), xs)
            except Exception as e:
                last = "确认异常: %s" % e
            if i < tries - 1:
                _p("  确认中(%d/%d): %s, %.1fs后重试" % (i + 1, tries, last, delay))
                time.sleep(delay)
        return False, last

    def grab_one(self, data_id, off, force=False, tag="", cancel_check=None, return_reason=False, log_fn=None,
                 burst=None, volley_interval=None, lead=None, deadline_sec=None):
        def P(s):
            if log_fn:
                log_fn(tag + s)
            else:
                print(tag + s)

        def _ret(ok, reason):
            return (ok, reason) if return_reason else ok

        burst_n = max(1, int(burst if burst is not None else BURST))
        v_interval = max(0.05, float(volley_interval if volley_interval is not None else VOLLEY_INTERVAL))
        lead_sec = max(0.0, float(lead if lead is not None else LEAD))
        deadline_win = max(5.0, float(deadline_sec if deadline_sec is not None else GRAB_DEADLINE))

        d = self.api_hall(data_id)
        dd = d.get("data") or {}
        if not token_alive(d):
            P("[!!] 拉取详情时登录凭据失效。")
            return _ret(False, "cookie_dead")
        tsu = dd.get("TimeSigningUp")
        status = dd.get("LectureHallStatus")
        target = parse_cn_epoch(tsu)
        P("[i] 讲座=%s" % str(dd.get("Cathedra") or "")[:40])
        P("[i] 状态=%s(%s) 报名开始 TimeSigningUp=%s 已报/容量=%s/%s" % (
            status, status_name(dd), tsu, dd.get("SignupNum"), dd.get("Capacity")))
        if status == 4:
            P("[!] 该场已结束(状态4), 跳过。")
            return _ret(False, "expired")
        if target:
            P("    距报名开始还有 %.1f 秒 (服务器时间)" % (target - srv_now(off)))

        code, sc = self._acquire_code(data_id)
        if code:
            gc = self.api_get_credentials(code)
            P("[✓] 已预取 credentialsCode=%s 当前 iscode=%s" % (
                code, (gc.get("data") or {}).get("iscode")))
        else:
            P("[i] 暂未取到 code (msg=%s)。报名未开始属正常, 将在开火时刻重试获取。" % sc.get("msg"))
            if not token_alive(sc):
                return _ret(False, "cookie_dead")
            if "无报名资格" in str(sc.get("msg", "")) and target and srv_now(off) >= target and not force:
                P("[!] 报名已开始却仍'无报名资格!': 很可能院级限本院, 或你不符合条件。加 --force 强行尝试, 或换校级场次。")
                return _ret(False, "hard_fail")

        if target:
            P("[..] 等待报名开启 (提前 %.2fs 开火)..." % lead_sec)
            last_refresh = time.time()
            while srv_now(off) < target - lead_sec:
                if cancel_check and cancel_check():
                    P("[i] 目标已被取消, 退出等待。")
                    return _ret(False, "cancelled")
                remain = target - lead_sec - srv_now(off)
                time.sleep(min(remain, 0.5) if remain > 0.5 else max(remain, 0))
                gap = 1 if remain < 10 else (2 if remain < 30 else 5)
                if remain < 30 and time.time() - last_refresh > gap:
                    if not code:
                        code, sc = self._acquire_code(data_id)
                        if code:
                            P("[✓] 窗口临近取到 code=%s" % code)
                    else:
                        gc = self.api_get_credentials(code)
                        if (gc.get("data") or {}).get("iscode"):
                            P("[✓] iscode=true, 凭证已激活!")
                    last_refresh = time.time()
            fire_start = max(target, srv_now(off))
        else:
            P("[!] 未拿到 TimeSigningUp, 立即开火 (适合已开放/手动触发场景)。")
            fire_start = srv_now(off)

        deadline = fire_start + deadline_win
        P("\n>>> 开火! 窗口 %ds, 每轮 %d 发, 间隔 %.2fs <<<" % (int(deadline_win), burst_n, v_interval))
        volley = 0
        seen_msgs = {}
        success = False
        submitted = False
        stop_reason = None
        volley_timeout = min(0.8, TIMEOUT)
        ex = ThreadPoolExecutor(max_workers=max(2, burst_n * 2))
        try:
            while srv_now(off) < deadline and not success and not submitted:
                if cancel_check and cancel_check():
                    P("[i] 目标已被取消, 中止猛攻。")
                    return _ret(False, "cancelled")
                volley += 1
                if not code:
                    code, sc = self._acquire_code(data_id)
                    if not code:
                        m = str(sc.get("msg", ""))
                        seen_msgs["[SetCred]" + m] = seen_msgs.get("[SetCred]" + m, 0) + 1
                        if not token_alive(sc):
                            P("[!!] 登录凭据失效, 中止。")
                            return _ret(False, "cookie_dead")
                        if volley % 5 == 1:
                            P("  第%d轮 仍无code(msg=%s) 剩余%.1fs" % (volley, m, deadline - srv_now(off)))
                        time.sleep(v_interval)
                        continue
                    P("[✓] 开火时刻取到 code=%s, 开始猛攻报名!" % code)

                futs = [ex.submit(self.api_signup, code) for _ in range(burst_n)]
                try:
                    for f in as_completed(futs, timeout=volley_timeout):
                        try:
                            r = f.result()
                        except Exception as e:
                            r = {"state": "error", "msg": str(e)}
                        state = r.get("state")
                        msg = str(r.get("msg", ""))
                        seen_msgs[msg] = seen_msgs.get(msg, 0) + 1
                        if not token_alive(r):
                            P("[!!] 登录凭据失效, 中止。请重新抓取。")
                            return _ret(False, "cookie_dead")
                        if state == "success":
                            P("\n[i] 收到 SignUp success 回执, 停火 → 转权威确认(GetSginInTime.data.state==1)…")
                            submitted = True
                            break
                        if "已报名" in msg or "已经报名" in msg or "重复" in msg:
                            P("\n[✓] 已在报名名单中 (msg=%s), 停止。" % msg)
                            success = True
                            break
                        if ("已满" in msg) or ("无余位" in msg) or ("报满" in msg) or ("名额" in msg and "满" in msg):
                            P("\n[x] 名额已满 (msg=%s), 停止本轮。" % msg)
                            stop_reason = "full_or_timeout"
                            break
                        if ("人脸" in msg) or ("认证" in msg and "完成" in msg):
                            P("\n[x] 被前置条件拦截 (msg=%s)。请先在微信完成人脸录入。" % msg)
                            stop_reason = "hard_fail"
                            break
                except FuturesTimeoutError:
                    seen_msgs["[单轮超时]"] = seen_msgs.get("[单轮超时]", 0) + 1
                if success or submitted or stop_reason:
                    break
                if volley % 10 == 1:
                    top = sorted(seen_msgs.items(), key=lambda kv: -kv[1])[:3]
                    P("  第%d轮 t=%s 剩余%.1fs 最近msg:%s" % (
                        volley, cn_str(srv_now(off)), deadline - srv_now(off), top))
                if code and volley % 20 == 0:
                    nc, _ = self._acquire_code(data_id)
                    if nc:
                        code = nc
                time.sleep(v_interval)
        finally:
            try:
                ex.shutdown(wait=False, cancel_futures=True)
            except TypeError:
                ex.shutdown(wait=False)

        if stop_reason == "hard_fail":
            return _ret(False, "hard_fail")
        if stop_reason == "full_or_timeout":
            return _ret(False, "full_or_timeout")

        P("\n--- 猛攻结束 --- submitted=%s 已报名回执=%s" % (submitted, success))
        P("出现过的 msg 统计: %s" % json.dumps(seen_msgs, ensure_ascii=False))
        hard_ineligible = (not success and not submitted
                           and any("无报名资格" in m for m in seen_msgs)
                           and not any(("已满" in m or "余位" in m) for m in seen_msgs))
        if hard_ineligible:
            P("[!] 全程'无报名资格!': 该讲座很可能限本院/本人不符合条件, 换一场校级(ClassLevel=1)讲座。")
        tries = 8 if (submitted or success) else 2
        okc, ev = self._confirm_signup(data_id, tries=tries, delay=1.0, P=P)
        dd2 = (self.api_hall(data_id).get("data") or {})
        P("最终状态: %s 我的报名时间 XSSigningUp: %s" % (status_name(dd2), dd2.get("XSSigningUp")))
        final_ok = bool(okc or success)
        if final_ok:
            P("\n[★★★] 报名成功(已确认): %s" % (ev if okc else "名单已含本人(msg=已报名)"))
            return _ret(True, "success")
        P("\n[x] 未确认报名成功(%s) — 不计为抢到, 避免误报。" % ev)
        if dd2.get("LectureHallStatus") == 4:
            return _ret(False, "expired")
        return _ret(False, "hard_fail" if (hard_ineligible and not force) else "full_or_timeout")


_DEFAULT_CLIENT = TongjiClient(cookie=COOKIE, token=TOKEN, pool_connections=16, pool_maxsize=64)


def _dc():
    if _DEFAULT_CLIENT.cookie != COOKIE:
        _DEFAULT_CLIENT.cookie = COOKIE
    if _DEFAULT_CLIENT.token != TOKEN:
        _DEFAULT_CLIENT.token = TOKEN
    return _DEFAULT_CLIENT


def _hdr_json(cookie=None):
    return _dc()._hdr_json(cookie=cookie)


def _hdr_form(cookie=None):
    return _dc()._hdr_form(cookie=cookie)


def get(path, params=None, cookie=None):
    return _dc().get(path, params=params, cookie=cookie)


def post_form(path, fields):
    return _dc().post_form(path, fields)


# ==================== 业务 API 封装 ====================
def api_student_info(cookie=None):
    return _dc().api_student_info(cookie=cookie)


def api_is_finish_face():
    return _dc().api_is_finish_face()


def api_hall_num():
    return _dc().api_hall_num()


def api_hall_list(page=1, page_size=10, status=0, time_=0, class_level=0):
    return _dc().api_hall_list(page=page, page_size=page_size, status=status, time_=time_, class_level=class_level)


def api_hall(data_id):
    return _dc().api_hall(data_id)


def api_hall30():
    return _dc().api_hall30()


def api_month_hall(year, month):
    return _dc().api_month_hall(year, month)


def api_set_credentials(data_id):
    return _dc().api_set_credentials(data_id)


def api_get_credentials(code):
    return _dc().api_get_credentials(code)


def api_signup(code):
    """【报名动作】"""
    return _dc().api_signup(code)


def api_signin_time(data_id):
    """轮询报名/签到结果: data.state==1 报名成功"""
    return _dc().api_signin_time(data_id)


def api_cancel(data_id):
    return _dc().api_cancel(data_id)


# ==================== 服务器时钟同步 ====================
def _parse_iso_epoch(s):
    """解析服务端 ISO8601(通常带 +08:00 时区) -> UTC 纪元秒。"""
    try:
        d = dt.datetime.fromisoformat(str(s))
        if d.tzinfo is None:            # naive 视为北京时间
            return calendar.timegm(d.timetuple()) - 8 * 3600
        return d.timestamp()
    except Exception:
        return None


def server_offset(samples=CLOCK_SAMPLES):
    return _dc().server_offset(samples=samples)


def srv_now(off):
    return time.time() + off


def parse_cn_epoch(s):
    """把 '北京时间' 的朴素时间字符串转成 UTC 纪元秒 (中国固定 UTC+8)。"""
    if not s:
        return None
    s = str(s).strip().replace("T", " ")
    for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y/%m/%d %H:%M:%S", "%Y/%m/%d %H:%M"):
        try:
            return calendar.timegm(dt.datetime.strptime(s, fmt).timetuple()) - 8 * 3600
        except ValueError:
            pass
    try:
        return calendar.timegm(dt.datetime.fromisoformat(s).timetuple()) - 8 * 3600
    except Exception:
        return None


def cn_str(epoch):
    return dt.datetime.utcfromtimestamp(epoch + 8 * 3600).strftime("%Y-%m-%d %H:%M:%S")


# ==================== 工具 ====================
def require_token():
    if not (COOKIE or TOKEN):
        print("[!] 未找到登录凭据。请先运行 capture_token.py 自动抓取(生成 token.json),")
        print("    或手动把会话 Cookie 填到脚本顶部 COOKIE / 环境变量 TJ_LECTURE_COOKIE。")
        sys.exit(2)


def token_alive(resp):
    """判断响应是否表示 token 失效。"""
    if not isinstance(resp, dict):
        return True
    msg = str(resp.get("msg", ""))
    code = resp.get("code")
    return not (("未登录" in msg) or ("超时" in msg) or (code in (40001, "40001")))


def reset_student_cache():
    """Cookie 变更时清空学院缓存, 避免跨账号沿用旧学院。"""
    _dc().reset_student_cache()


def my_college():
    """返回 (学生学院代码, 学院名) —— 用于院级'只抢本院'资格过滤。带缓存。"""
    return _dc().my_college()


def dump(obj, name):
    ts = dt.datetime.now().strftime("%Y%m%d_%H%M%S")
    fn = "%s_%s.json" % (name, ts)
    with open(fn, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)
    print("[+] 已保存:", fn)


def jline(title, resp):
    print("  %-22s state=%-8s %s" % (title, resp.get("state"),
                                      json.dumps(resp.get("data", resp.get("msg")),
                                                 ensure_ascii=False)[:160]))


# ==================== 命令: discover ====================
def cmd_discover():
    require_token()
    print("=" * 64)
    print("discover: 验证 token 并抓取所有接口真实响应")
    print("=" * 64)
    out = {}

    info = api_student_info()
    out["StudentInfo"] = info
    jline("StudentInfo", info)
    if not token_alive(info):
        print("\n[!!] token 无效或已过期。请重新抓取 token 后再试。")
        return
    if info.get("state") != "success":
        print("\n[!] StudentInfo 非 success, token 可能有问题, 仍继续尝试其余接口...")

    out["IsFinishFace"] = api_is_finish_face(); jline("IsFinishFace", out["IsFinishFace"])
    out["HallNum"] = api_hall_num();            jline("HallNum", out["HallNum"])
    out["Hall30"] = api_hall30();               jline("Hall30", out["Hall30"])

    # 讲座列表(第 1 页, 全部状态) + 服务器时钟
    lst = api_hall_list(page=1, page_size=10, status=0)
    out["HallList_p1"] = lst
    jline("HallList(page1)", lst)
    ldata = lst.get("data") or {}
    print("  服务器nowtime=%s  总数=%s  总页=%s" % (
        ldata.get("nowtime"), ldata.get("totalcount"), ldata.get("totalPage")))
    rows = ldata.get("row") or []
    print("  列表返回 %d 条; 首条字段:" % len(rows))
    if rows:
        r0 = rows[0]
        print("     标题Cathedra=%s" % str(r0.get("Cathedra"))[:40])
        print("     状态=%s(%s) 级别=%s 报名开始=%s 讲座=%s 余位=%s/%s" % (
            r0.get("LectureHallStatus"), status_name(r0), r0.get("ClassLevelName"),
            r0.get("TimeSigningUp"), r0.get("LectureTimeStart"),
            r0.get("SignupNum"), r0.get("Capacity")))
        print("     原始(截断):", json.dumps(r0, ensure_ascii=False)[:300])

    # 当月日历
    now = dt.datetime.now()
    out["MonthHall"] = api_month_hall(now.year, now.month)
    jline("MonthHall", out["MonthHall"])

    # 若列表有数据, 对第一条做详情 + 凭证链探测
    if rows:
        did = rows[0].get("DataId") or rows[0].get("dataId")
        if did:
            print("\n  -- 对 DataId=%s 做详情/凭证链探测 --" % did)
            d = api_hall(did); out["Hall_detail"] = d; jline("GetLectureHall", d)
            dd = d.get("data") or {}
            print("     TimeSigningUp=%s  LectureHallStatus=%s(%s)  LectureTimeStart=%s" % (
                dd.get("TimeSigningUp"), dd.get("LectureHallStatus"),
                STATUS_TEXT.get(dd.get("LectureHallStatus"), "?"), dd.get("LectureTimeStart")))
            sc = api_set_credentials(did); out["SetCredentials"] = sc; jline("SetCredentials", sc)
            code = (sc.get("data") or {}).get("code")
            if code:
                gc = api_get_credentials(code); out["GetCredentials"] = gc; jline("GetCredentials", gc)
                print("     credentialsCode=%s  iscode=%s" % (code, (gc.get("data") or {}).get("iscode")))
            st = api_signin_time(did); out["SignInTime"] = st; jline("GetSginInTime", st)

    dump(out, "discover")
    print("\n[✓] discover 完成。请把生成的 discover_*.json 发我, 据此校准 grab 的字段与消息判断。")


# ==================== 命令: find ====================
def scan_lectures_ex(statuses=(0,), max_pages=3, page_size=50, stop_when_ended=False):
    return _dc().scan_lectures_ex(statuses=statuses, max_pages=max_pages,
                                  page_size=page_size, stop_when_ended=stop_when_ended)


def scan_lectures(statuses=(0,), max_pages=3, page_size=50, stop_when_ended=False):
    """扫描讲座列表, 去重返回 rows。token 失效返回 None, 网络抖动返回 []。"""
    st, msg, uniq = scan_lectures_ex(statuses=statuses, max_pages=max_pages,
                                     page_size=page_size, stop_when_ended=stop_when_ended)
    if st == "dead":
        print("[!!] token 失效: %s" % msg)
        return None
    if st == "error":
        print("[!] 扫描请求异常: %s" % msg)
        return []
    return uniq


def status_name(x):
    """优先用服务端返回的 LectureHallStatusName, 回退到本地映射。"""
    if isinstance(x, dict):
        nm = x.get("LectureHallStatusName")
        if nm:
            return str(nm)
        return STATUS_TEXT.get(x.get("LectureHallStatus"), "?")
    return STATUS_TEXT.get(x, "?")


def _row_fields(x):
    did = x.get("DataId") or x.get("dataId")
    st = x.get("LectureHallStatus")
    title = (x.get("Cathedra") or x.get("Name") or x.get("Title")
             or x.get("NameLecture") or x.get("LectureName") or "(无标题)")
    tsu = x.get("TimeSigningUp") or x.get("SignUpTime") or "?"
    lts = x.get("LectureTimeStart") or "?"
    lvl = x.get("ClassLevelName") or ("校级" if str(x.get("ClassLevel")) == "1"
                                      else "院级" if str(x.get("ClassLevel")) == "2" else "?")
    return did, st, title, tsu, lts, lvl


def print_lectures(uniq, numbered=False, my_college=""):
    print("共 %d 场讲座:\n" % len(uniq))
    for idx, x in enumerate(uniq, 1):
        did, st, title, tsu, lts, lvl = _row_fields(x)
        prefix = ("[%2d] " % idx) if numbered else "  "
        mark = ""
        if lvl == "院级" and my_college:
            mark = "★本院" if str(x.get("CollegeCode")) == str(my_college) else "·外院(无资格)"
        print("%s%-8s 状态=%s(%s) 报名开始=%s 讲座=%s [%s]%s %s" % (
            prefix, (did or "?")[:8], st, status_name(x), tsu, lts, lvl, mark, str(title)[:26]))


def cmd_find():
    require_token()
    print("=" * 64)
    print("find: 扫描讲座列表, 找出可报名/即将报名的讲座")
    print("=" * 64)
    uniq = scan_lectures()
    if uniq is None:
        return
    mc, _mn = my_college()
    print_lectures(uniq, my_college=mc)
    dump(uniq, "find")
    print("\n[+] 推荐: python lecture_grabber.py pick 交互式选择并抢; 或 grab <DataId> 直接抢。")


def parse_multi_sel(sel, n):
    """把 '1,3,5' / '1 3 5' / '2-4' 解析成 0-based 索引(去重保序, 越界忽略)。"""
    sel = (sel or "").replace("，", ",").replace("、", ",").replace(" ", ",").strip()
    idxs = []
    for part in sel.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part and part.replace("-", "").isdigit():
            a, b = part.split("-", 1)
            a, b = int(a), int(b)
            if a > b:
                a, b = b, a
            idxs.extend(range(a, b + 1))
        elif part.isdigit():
            idxs.append(int(part))
    out, seen = [], set()
    for i in idxs:
        if 1 <= i <= n and i not in seen:
            seen.add(i)
            out.append(i - 1)
    return out


def cmd_pick():
    require_token()
    print("=" * 64)
    print("pick: 选择场次(可多选) -> 盯 TimeSigningUp -> 定点猛攻")
    print("=" * 64)
    uniq = scan_lectures()
    if not uniq:
        print("[!] 没有扫描到讲座。")
        return
    mc, _mn = my_college()
    print_lectures(uniq, numbered=True, my_college=mc)
    try:
        sel = input("\n输入序号(可多选, 如 1,3,5 或 2-4; 直接回车取消): ").strip()
    except EOFError:
        sel = ""
    idxs = parse_multi_sel(sel, len(uniq))
    if not idxs:
        print("已取消。")
        return
    data_ids = []
    for i in idxs:
        row = uniq[i]
        did, st, title, tsu, lts, lvl = _row_fields(row)
        if not did:
            continue
        if st == 4:
            print("[!] 跳过(已结束 状态4): %s %s" % (str(did)[:8], str(title)[:20]))
            continue
        note = ""
        if st == 2:
            note += " (已报满, 尝试捡漏)"
        if str(row.get("ClassLevel")) == "2":
            note += " (院级, 可能'无报名资格')"
        print("[✓] 已选: %s [%s] %s 报名开始=%s%s" % (
            str(did)[:8], lvl, str(title)[:24], tsu, note))
        data_ids.append(did)
    if not data_ids:
        print("[!] 没有有效目标。")
        return
    cmd_grab(data_ids, force=False)


# ==================== 命令: detail ====================
def cmd_detail(data_id):
    require_token()
    d = api_hall(data_id)
    print(json.dumps(d, ensure_ascii=False, indent=2)[:2000])
    dd = d.get("data") or {}
    print("\n-- 解析 --")
    print("  DataId           :", dd.get("DataId"))
    print("  LectureHallStatus:", dd.get("LectureHallStatus"), STATUS_TEXT.get(dd.get("LectureHallStatus"), ""))
    print("  TimeSigningUp    :", dd.get("TimeSigningUp"), "(报名开始)")
    print("  LectureTimeStart :", dd.get("LectureTimeStart"))
    print("  NameSpeaker      :", dd.get("NameSpeaker"))
    print("  XSSigningUp      :", dd.get("XSSigningUp"), "(我的报名时间, 非空=已报)")


# ==================== 命令: grab ====================
def _acquire_code(data_id):
    return _dc()._acquire_code(data_id)


def _preflight(force):
    """登录态 + 人脸录入预检 (多目标时只做一次)。返回 True=可继续抢。"""
    info = api_student_info()
    if not token_alive(info):
        print("[!!] 登录凭据失效(会话过期), 请重新运行 capture_token.py 抓取。")
        return False
    print("[✓] 登录有效:", json.dumps(info.get("data"), ensure_ascii=False)[:120])
    face = api_is_finish_face()
    face_ok = bool(face.get("data"))
    print("[%s] 人脸录入 GetIsFinishFace.data=%s" % ("✓" if face_ok else "!", face.get("data")))
    if not face_ok and not force:
        print("    未完成人脸录入通常无法报名。确认已完成请加 --force; 否则先去微信里完成人脸录入。")
        return False
    return True


def _confirm_signup(data_id, tries=6, delay=1.0, P=None):
    return _dc()._confirm_signup(data_id, tries=tries, delay=delay, P=P)


def grab_one(data_id, off, force=False, tag="", cancel_check=None, return_reason=False):
    return _dc().grab_one(data_id, off, force=force, tag=tag, cancel_check=cancel_check, return_reason=return_reason)


def cmd_grab(data_ids, force=False):
    """抢一个或多个讲座(各自盯 TimeSigningUp 定点猛攻)。data_ids 可为 str 或 list。"""
    require_token()
    if isinstance(data_ids, str):
        data_ids = [data_ids]
    data_ids = [d for d in data_ids if d]
    if not data_ids:
        print("[!] 没有指定 DataId。")
        return
    off = server_offset()
    print("=" * 64)
    print("grab: 抢报名 %d 个目标 (服务器时钟偏移 %.3fs)" % (len(data_ids), off))
    print("      目标: %s" % ", ".join(str(x)[:8] for x in data_ids))
    print("=" * 64)
    if not _preflight(force):
        return
    if len(data_ids) == 1:
        grab_one(data_ids[0], off, force=force, tag="")
        return
    # 多目标: 每个一个线程, 各自等到自己的 TimeSigningUp 再猛攻
    results = {}
    with ThreadPoolExecutor(max_workers=len(data_ids)) as ex:
        futs = {ex.submit(grab_one, d, off, force, "[%s] " % str(d)[:6]): d for d in data_ids}
        for f in as_completed(futs):
            d = futs[f]
            try:
                results[d] = f.result()
            except Exception as e:
                results[d] = False
                print("[%s] 异常: %s" % (str(d)[:8], e))
    print("\n" + "=" * 64)
    print("多目标抢报结果:")
    for d, ok in results.items():
        print("  %s : %s" % (str(d)[:8], "✓ 成功" if ok else "× 未成功"))
    print("=" * 64)


GRACE_PAST = 300   # 报名开始已过去超过此秒数的场次不再当候选(多半已处理/报满)


def _candidates(uniq, off, level="校级", keyword=None, my_college=""):
    """筛出'报名开始在未来(或刚开报不久)'的目标场次, 按开报时间升序。
    level: '校级'/'院级'/None(全部); keyword: 标题子串; my_college: 非空时院级只保留本院(CollegeCode匹配)。"""
    now = srv_now(off)
    out = []
    for x in uniq:
        did, st, title, tsu, lts, lvl = _row_fields(x)
        if not did or st == 4:
            continue
        if level and lvl != level:
            continue
        if keyword and keyword.lower() not in str(title).lower():
            continue
        # 院级资格: 只抢本院(实测外院 SetCredentials 返回"无报名资格!"); 校级全员可报不过滤
        if my_college and lvl == "院级" and str(x.get("CollegeCode")) != str(my_college):
            continue
        tgt = parse_cn_epoch(tsu)
        if not tgt or (tgt - now) < -GRACE_PAST:
            continue
        out.append((x, tgt, tgt - now))
    out.sort(key=lambda r: r[1])
    return out


def cmd_watch(level="校级", keyword=None, interval=60, auto=True, force=False, all_colleges=False):
    """值守模式: 持续轮询列表 -> 发现'未来开报'的目标 -> 到各自 TimeSigningUp 自动猛攻。
    解决'讲座临近开报才放出、当前列表无候选'的现实; 校级实测固定 12:30 开报、周五最密集。
    院级默认只抢本院(CollegeCode==学生Faculty), 外院会'无报名资格'; --all-colleges 关闭该过滤。"""
    require_token()
    off = server_offset()
    mc, mn = my_college()
    use_college = "" if all_colleges else mc
    print("=" * 64)
    print("watch: 值守轮询 -> 发现目标 -> 到点自动抢")
    print("  过滤 level=%s keyword=%s | 轮询=%ds | 自动抢=%s | 时钟偏移=%.3fs" % (
        level or "全部", keyword or "(无)", interval, "是" if auto else "否(仅提示)", off))
    if use_college:
        print("  院级资格: 只抢本院 [%s] %s (外院院级'无报名资格'已排除; --all-colleges 可关闭)" % (use_college, mn))
    else:
        print("  院级资格: 不过滤(--all-colleges), 外院院级也会尝试(预计'无报名资格')")
    print("  按 Ctrl+C 退出。")
    print("=" * 64)
    if not _preflight(force):
        return
    locked, fired = {}, set()
    rnd = 0
    try:
        while True:
            rnd += 1
            if rnd % 10 == 0:
                off = server_offset()
            uniq = scan_lectures()
            if uniq is None:
                print("[!!] 登录凭据失效, 请重新运行 capture_token.py 抓取后再值守。")
                return
            cands = _candidates(uniq, off, level=level, keyword=keyword, my_college=use_college)
            now = srv_now(off)
            for x, tgt, delta in cands:
                did = _row_fields(x)[0]
                if did in fired or did in locked:
                    continue
                _, st, title, tsu, lts, lvl = _row_fields(x)
                print("[%s] [新发现] %s [%s] %s 报名开始=%s (还有 %.0f 秒)" % (
                    cn_str(now), str(did)[:8], lvl, str(title)[:24], tsu, delta))
                locked[did] = (x, tgt)
            due = [d for d, (x, t) in locked.items() if d not in fired and t - now <= LEAD + 1]
            for did in due:
                fired.add(did)
                x, tgt = locked[did]
                title = _row_fields(x)[2]
                print("\n[%s] >>> 到点! 开抢 %s %s" % (cn_str(srv_now(off)), str(did)[:8], str(title)[:24]))
                if auto:
                    threading.Thread(target=grab_one,
                                     args=(did, off, force, "[%s] " % str(did)[:6]),
                                     daemon=True).start()
                else:
                    print("    (非自动) 手动执行: python lecture_grabber.py grab %s" % did)
            if rnd % 5 == 1 or due:
                pend = [d for d in locked if d not in fired]
                print("[%s] 第%d轮: 扫描%d场 命中候选%d 已锁定%d 待开火%d" % (
                    cn_str(srv_now(off)), rnd, len(uniq), len(cands), len(locked), len(pend)))
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[i] 值守已停止。锁定 %d 个目标, 开火 %d 个。" % (len(locked), len(fired)))


# ==================== 入口 ====================
def _opt(args, name, default=None):
    for a in args[1:]:
        if a.startswith("--" + name + "="):
            return a.split("=", 1)[1]
    return default


def main():
    args = sys.argv[1:]
    if not args:
        print(__doc__)
        return
    cmd = args[0].lower()
    force = "--force" in args
    rest = [a for a in args[1:] if not a.startswith("--")]

    if cmd == "discover":
        cmd_discover()
    elif cmd == "find":
        cmd_find()
    elif cmd == "pick":
        cmd_pick()
    elif cmd == "watch":
        level = _opt(args, "level", "校级")
        if level in ("all", "全部", "0", ""):
            level = None
        keyword = _opt(args, "keyword", None)
        try:
            interval = int(_opt(args, "interval", "60"))
        except ValueError:
            interval = 60
        auto = "--no-auto" not in args
        all_colleges = "--all-colleges" in args
        cmd_watch(level=level, keyword=keyword, interval=interval, auto=auto,
                  force=force, all_colleges=all_colleges)
    elif cmd == "detail":
        if not rest:
            print("用法: python lecture_grabber.py detail <DataId>"); return
        cmd_detail(rest[0])
    elif cmd == "grab":
        if not rest:
            print("用法: python lecture_grabber.py grab <DataId> [DataId2 ...] [--force]"); return
        cmd_grab(rest, force=force)
    else:
        print("未知命令:", cmd); print(__doc__)


if __name__ == "__main__":
    main()
