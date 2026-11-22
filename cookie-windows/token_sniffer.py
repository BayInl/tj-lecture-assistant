#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
token_sniffer.py —— mitmproxy 插件 (会话 Cookie 自动抓取版)

【实测地面真相】lecture.tongji.edu.cn 的登录态不是 token 头, 而是两个会话 Cookie:
    PG.ASP.Session.ID=<会话 uuid>
    PG.ASP.WeiXinCode.ID=<微信绑定 id>
本插件从 微信内置浏览器 <-> 站点 的流量里自动截获这条 Cookie, 连同 weixinapi/Callback
返回的学生信息一起写入 token.json, 供 lecture_grabber.py 直接读取使用。

同时把 target host 的 API 请求/响应转储到 sniff_debug.log 便于排查。
mitmdump 会热重载本文件, 改完刷新一次 H5 即生效。
"""

import os
import json
import datetime

from mitmproxy import http, ctx

TARGET_HOST = "lecture.tongji.edu.cn"
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.environ.get("TJ_SNIFFER_OUT") or os.path.join(HERE, "token.json")
DEBUG = os.environ.get("TJ_SNIFFER_LOG") or os.path.join(HERE, "sniff_debug.log")
VERBOSE_DEBUG = os.environ.get("TJ_SNIFF_DEBUG") == "1"

SESSION_KEY = "PG.ASP.Session.ID"
WEIXIN_KEY = "PG.ASP.WeiXinCode.ID"

STATIC_EXT = (".js", ".css", ".ico", ".png", ".jpg", ".jpeg", ".gif",
              ".woff", ".woff2", ".ttf", ".svg", ".map", ".mp4", ".webp")


def _ts():
    return datetime.datetime.now().strftime("%H:%M:%S")


def _log(msg):
    try:
        with open(DEBUG, "a", encoding="utf-8") as f:
            f.write("[%s] %s\n" % (_ts(), msg))
    except Exception:
        pass


def _interesting(path):
    """只关心 API / 回调, 跳过静态大文件(app.js 等), 避免调试日志爆炸。"""
    p = (path or "").lower().split("?")[0]
    return not p.endswith(STATIC_EXT)


def _cookie_val(cookie, name):
    for part in (cookie or "").split(";"):
        part = part.strip()
        if part.startswith(name + "="):
            return part[len(name) + 1:]
    return ""


def _load_existing():
    try:
        with open(OUT, encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _atomic_write(data):
    tmp = OUT + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        os.replace(tmp, OUT)
        return True
    except Exception as e:
        ctx.log.error("[TOKEN] 写盘失败: %s" % e)
        return False


_LAST_RUN_COOKIE = ""


def _write_cred(cookie, source, host):
    """截获会话 Cookie -> token.json。同一次嗅探运行内 Cookie 未变化则跳过(避免每请求刷屏)。"""
    global _LAST_RUN_COOKIE
    if not cookie or SESSION_KEY not in cookie:
        return
    if _LAST_RUN_COOKIE == cookie:
        return
    _LAST_RUN_COOKIE = cookie
    ex = _load_existing()
    data = {
        "cookie": cookie,
        "session_id": _cookie_val(cookie, SESSION_KEY),
        "weixin_code_id": _cookie_val(cookie, WEIXIN_KEY),
        "token": ex.get("token", ""),
        "captured_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "source": source,
        "host": host,
    }
    if ex.get("student"):
        data["student"] = ex["student"]
    if not _atomic_write(data):
        return
    try:
        ctx.log.info("[TOKEN] 已捕获会话Cookie(%s) -> %s" % (source, OUT))
    except Exception:
        pass
    _log("### 已捕获会话Cookie(%s): %s" % (source, data["session_id"]))
    print("\n" + "=" * 58)
    print("  [OK] 抓到登录会话 Cookie  (来源: %s)" % source)
    print("  PG.ASP.Session.ID = %s" % data["session_id"])
    print("  PG.ASP.WeiXinCode.ID = %s" % data["weixin_code_id"])
    print("  已写入: %s" % OUT)
    print("=" * 58 + "\n", flush=True)


def _write_student(student):
    """把 Callback 返回的 userInfo 合并进 token.json 的 student 字段。"""
    if not isinstance(student, dict) or not student:
        return
    ex = _load_existing()
    if ex.get("student") == student:
        return
    ex["student"] = student
    ex.setdefault("host", TARGET_HOST)
    _atomic_write(ex)
    _log("### 已捕获学生信息: StudentId=%s" % student.get("StudentId"))


class TokenSniffer:
    def request(self, flow: http.HTTPFlow):
        try:
            host = flow.request.host or ""
            if TARGET_HOST not in host:
                return
            path = flow.request.path or ""
            if not _interesting(path):
                return

            if VERBOSE_DEBUG:
                _log("REQ  %s %s" % (flow.request.method, flow.request.url))
                _log("     headers= %s" % json.dumps(dict(flow.request.headers),
                                                     ensure_ascii=False))

            cookie = (flow.request.headers.get("Cookie")
                      or flow.request.headers.get("cookie"))
            if cookie and SESSION_KEY in cookie:
                _write_cred(cookie, "request-cookie", host)
        except Exception as e:
            ctx.log.error("[TOKEN] request hook error: %s" % e)

    def response(self, flow: http.HTTPFlow):
        try:
            host = flow.request.host or ""
            if TARGET_HOST not in host:
                return
            if flow.response is None:
                return
            path = flow.request.path or ""
            if not _interesting(path):
                return

            body = ""
            need_body = ("callback" in path.lower()) or VERBOSE_DEBUG
            if need_body:
                try:
                    body = flow.response.get_text(strict=False) or ""
                except Exception:
                    body = ""
            if VERBOSE_DEBUG:
                _log("RESP %s %s -> %s" % (flow.request.method,
                                            flow.request.url,
                                            flow.response.status_code))
                _log("     resp-headers= %s" % json.dumps(dict(flow.response.headers),
                                                          ensure_ascii=False))
                if body:
                    _log("     body[:2000]= %s" % body[:2000].replace("\n", " "))

            # weixinapi/Callback -> userInfo(学生信息)
            if "callback" in path.lower():
                try:
                    j = json.loads(body)
                    ui = (j.get("data") or {}).get("userInfo")
                    if ui:
                        _write_student(ui)
                except Exception:
                    pass

            # 兜底: Set-Cookie 里下发会话
            for k, v in flow.response.headers.items(multi=True):
                if k.lower() == "set-cookie" and SESSION_KEY in v:
                    ck = "%s=%s" % (SESSION_KEY, _cookie_val(v, SESSION_KEY))
                    wx = _cookie_val(v, WEIXIN_KEY)
                    if wx:
                        ck += "; %s=%s" % (WEIXIN_KEY, wx)
                    _write_cred(ck, "set-cookie", host)
        except Exception as e:
            ctx.log.error("[TOKEN] response hook error: %s" % e)


addons = [TokenSniffer()]
