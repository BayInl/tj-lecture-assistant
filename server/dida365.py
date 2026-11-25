#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dida365.py —— 滴答清单 (Dida365) 官方 Open API 轻量同步客户端
  · 使用官方 Personal API Token (Authorization: Bearer dp_...)
  · 支持自动查找/创建专属清单、创建带起止时间与手机提醒的讲座任务、退选自动删除
  · 零第三方依赖 (仅用 requests), 严格忽略系统代理 (trust_env=False)
"""
import re
import datetime as dt
import requests

BASE = "https://api.dida365.com/open/v1"
TIMEOUT = 10


def _session(token):
    s = requests.Session()
    s.trust_env = False
    s.headers.update({
        "Authorization": "Bearer %s" % str(token or "").strip(),
        "Content-Type": "application/json",
        "Accept": "application/json",
    })
    return s


def _fmt_iso_cn(d):
    return d.strftime("%Y-%m-%dT%H:%M:%S+0800")


def parse_lecture_time_range(ltime, default_duration_min=120):
    """解析 '2026-11-26 14:00~16:00' / '2026-11-26 14:00 ~ 2026-11-26 16:00' / '2026-11-26 14:00'."""
    s = str(ltime or "").strip()
    if not s:
        return None, None
    s = s.replace("T", " ").replace("至", "~").replace("—", "~")
    m = re.search(r"(\d{4}-\d{2}-\d{2})\s+(\d{1,2}:\d{2})(?::(\d{2}))?", s)
    if not m:
        return None, None
    y_m_d, hm, sec = m.group(1), m.group(2), m.group(3) or "00"
    try:
        start_dt = dt.datetime.strptime("%s %s:%s" % (y_m_d, hm, sec), "%Y-%m-%d %H:%M:%S")
    except Exception:
        return None, None

    rest = s[m.end():]
    end_dt = None
    m_full = re.search(r"(\d{4}-\d{2}-\d{2})\s+(\d{1,2}:\d{2})(?::(\d{2}))?", rest)
    if m_full:
        try:
            end_dt = dt.datetime.strptime(
                "%s %s:%s" % (m_full.group(1), m_full.group(2), m_full.group(3) or "00"),
                "%Y-%m-%d %H:%M:%S",
            )
        except Exception:
            end_dt = None
    else:
        m_hm = re.search(r"[~\-]\s*(\d{1,2}:\d{2})(?::(\d{2}))?", rest)
        if m_hm:
            try:
                end_dt = dt.datetime.strptime(
                    "%s %s:%s" % (y_m_d, m_hm.group(1), m_hm.group(2) or "00"),
                    "%Y-%m-%d %H:%M:%S",
                )
            except Exception:
                end_dt = None

    if end_dt is None or end_dt <= start_dt:
        end_dt = start_dt + dt.timedelta(minutes=max(30, int(default_duration_min or 120)))
    return _fmt_iso_cn(start_dt), _fmt_iso_cn(end_dt)


def list_projects(token):
    tok = str(token or "").strip()
    if not tok:
        return False, "未配置滴答清单 API 口令", []
    try:
        r = _session(tok).get(BASE + "/project", timeout=TIMEOUT)
        if r.status_code == 401:
            return False, "API 口令无效或已过期 (HTTP 401)", []
        if r.status_code >= 400:
            return False, "滴答清单接口错误 HTTP %d: %s" % (r.status_code, r.text[:160]), []
        data = r.json()
        if not isinstance(data, list):
            return False, "返回格式异常", []
        return True, "ok", data
    except Exception as e:
        return False, "请求滴答清单失败: %s" % e, []


def ensure_project(token, project_name="🎓 同济讲座", project_id=""):
    ok, msg, projs = list_projects(token)
    if not ok:
        return False, msg, "", ""
    pid = str(project_id or "").strip()
    pname = str(project_name or "🎓 同济讲座").strip() or "🎓 同济讲座"
    if pid:
        for p in projs:
            if str(p.get("id") or "") == pid:
                return True, "ok", pid, str(p.get("name") or pname)
    for p in projs:
        if str(p.get("name") or "").strip() == pname:
            return True, "ok", str(p.get("id") or ""), str(p.get("name") or pname)
    try:
        r = _session(token).post(
            BASE + "/project",
            json={"name": pname, "color": "#4A90E2", "viewMode": "list", "kind": "TASK"},
            timeout=TIMEOUT,
        )
        if r.status_code >= 400:
            return False, "创建清单失败 HTTP %d: %s" % (r.status_code, r.text[:160]), "", ""
        obj = r.json() or {}
        return True, "created", str(obj.get("id") or ""), str(obj.get("name") or pname)
    except Exception as e:
        return False, "创建清单异常: %s" % e, "", ""


def build_reminders(remind_before_min=60):
    try:
        mins = int(remind_before_min)
    except Exception:
        mins = 60
    rems = []
    if mins > 0:
        rems.append("TRIGGER:-PT%dM" % mins)
    rems.append("TRIGGER:PT0S")
    return rems


def create_lecture_task(token, project_id, lecture, remind_before_min=60):
    tok = str(token or "").strip()
    if not tok:
        return False, "未配置 API 口令", ""
    lvl = str(lecture.get("lvl") or "").strip()
    raw_title = str(lecture.get("title") or "同济高等讲堂讲座").strip()
    title = ("[%s] %s" % (lvl, raw_title)) if lvl else raw_title
    ltime = str(lecture.get("ltime") or "").strip()
    venue = str(lecture.get("venue") or "").strip()
    campus = str(lecture.get("campus") or "").strip()
    speaker = str(lecture.get("speaker") or "").strip()
    did = str(lecture.get("did") or "").strip()
    won_at = str(lecture.get("won_at") or "").strip()

    lines = []
    if ltime:
        lines.append("时间：%s" % ltime.replace("~", " 至 "))
    if campus or venue:
        lines.append("地点：%s" % (" · ".join(x for x in (campus, venue) if x)))
    if speaker:
        lines.append("主讲：%s" % speaker)
    if won_at:
        lines.append("抢中：%s" % won_at)
    if did:
        lines.append("讲座ID：%s" % did)

    start_iso, due_iso = parse_lecture_time_range(ltime)
    payload = {
        "title": title[:120],
        "projectId": str(project_id or "").strip(),
        "content": "\n".join(lines),
        "priority": 3,
        "timeZone": "Asia/Shanghai",
    }
    if start_iso and due_iso:
        payload["isAllDay"] = False
        payload["startDate"] = start_iso
        payload["dueDate"] = due_iso
        payload["reminders"] = build_reminders(remind_before_min)

    try:
        r = _session(tok).post(BASE + "/task", json=payload, timeout=TIMEOUT)
        if r.status_code >= 400:
            return False, "创建任务失败 HTTP %d: %s" % (r.status_code, r.text[:200]), ""
        obj = r.json() or {}
        tid = str(obj.get("id") or "")
        return True, "ok", tid
    except Exception as e:
        return False, "创建任务异常: %s" % e, ""


def delete_task(token, project_id, task_id):
    tok = str(token or "").strip()
    pid = str(project_id or "").strip()
    tid = str(task_id or "").strip()
    if not (tok and pid and tid):
        return False, "缺少参数"
    try:
        r = _session(tok).delete("%s/project/%s/task/%s" % (BASE, pid, tid), timeout=TIMEOUT)
        if r.status_code in (200, 204, 404):
            return True, "ok"
        return False, "删除任务失败 HTTP %d: %s" % (r.status_code, r.text[:160])
    except Exception as e:
        return False, "删除任务异常: %s" % e
