#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""notify.py —— 钉钉机器人推送(加签模式)。可被 server_app.py 复用, 也可命令行自测。

安全方式: 加签(HMAC-SHA256 + Base64 + urlencode)。webhook/secret 从 tj_config.json 读取。
命令行:
  python notify.py                 # 发一条自测文本
  python notify.py 自定义内容...    # 发指定文本
"""
import time
import hmac
import base64
import hashlib
import json
import os
import sys
import urllib.parse

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

import requests

_SESSION = requests.Session()

HERE = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.environ.get("TJ_DATA_DIR") or HERE
CFG = os.path.join(DATA_DIR, "tj_config.json")


def load_cfg(path=None):
    try:
        return json.load(open(path or CFG, encoding="utf-8"))
    except Exception:
        return {}


class DingTalk:
    """钉钉自定义机器人(加签)。errcode==0 表示成功。"""

    def __init__(self, webhook, secret=None, prefix="", timeout=8):
        self.webhook = webhook
        self.secret = secret
        self.prefix = prefix or ""
        self.timeout = timeout

    def _url(self):
        if not self.secret:
            return self.webhook
        ts = str(round(time.time() * 1000))
        string_to_sign = "%s\n%s" % (ts, self.secret)
        digest = hmac.new(self.secret.encode("utf-8"),
                          string_to_sign.encode("utf-8"),
                          digestmod=hashlib.sha256).digest()
        sign = urllib.parse.quote_plus(base64.b64encode(digest))
        sep = "&" if "?" in self.webhook else "?"
        return "%s%stimestamp=%s&sign=%s" % (self.webhook, sep, ts, sign)

    def _post(self, payload):
        try:
            r = _SESSION.post(self._url(), json=payload, timeout=self.timeout,
                              headers={"Content-Type": "application/json"})
            try:
                return r.json()
            except Exception:
                return {"errcode": -1, "errmsg": "非JSON: %s" % r.text[:200]}
        except Exception as e:
            return {"errcode": -2, "errmsg": "请求异常: %s" % e}

    def text(self, content, at_all=False):
        return self._post({"msgtype": "text",
                           "text": {"content": self.prefix + content},
                           "at": {"isAtAll": at_all}})

    def markdown(self, title, text, at_all=False):
        return self._post({"msgtype": "markdown",
                           "markdown": {"title": title, "text": text},
                           "at": {"isAtAll": at_all}})


def get_notifier(cfg=None):
    cfg = cfg if cfg is not None else load_cfg()
    d = cfg.get("dingtalk") or {}
    wh = d.get("webhook")
    if not wh:
        return None
    return DingTalk(wh, d.get("secret"), d.get("prefix", ""))


def notify(event, content, cfg=None, at_all=False):
    """按 tj_config.json 的 notify_events 白名单推送; event 不在白名单则跳过。
    返回钉钉响应 dict 或 None(未配置/被过滤)。"""
    cfg = cfg if cfg is not None else load_cfg()
    d = cfg.get("dingtalk") or {}
    events = d.get("notify_events")
    if events and event not in events:
        return None
    n = get_notifier(cfg)
    if not n:
        return None
    return n.text(content, at_all=at_all)


if __name__ == "__main__":
    msg = " ".join(sys.argv[1:]) or "notify.py 自测消息 ✅ (加签推送正常)"
    n = get_notifier()
    if not n:
        print("[!] tj_config.json 里没有 dingtalk.webhook")
        sys.exit(1)
    res = n.text(msg)
    print("钉钉返回:", json.dumps(res, ensure_ascii=False))
    print("[OK] 推送成功" if res.get("errcode") == 0 else "[FAIL] 推送失败")
