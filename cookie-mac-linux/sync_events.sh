#!/bin/bash
# sync_events.sh —— 把 Linux 服务器上的抢报事件同步成 macOS 通知
# 由 LaunchAgent com.tj.lecture.eventwatch 每 60 秒调用。
set -u
SERVER_API="${TJ_SERVER_URL:-http://127.0.0.1:8848}"
DIR="$(cd "$(dirname "$0")" && pwd)"
API_TOKEN="${TJ_API_TOKEN:-}"                    # 可设环境变量或写入同目录 .api_token (勿提交到 Git)
[ -z "$API_TOKEN" ] && [ -f "$DIR/.api_token" ] && API_TOKEN=$(tr -d '[:space:]' < "$DIR/.api_token")
PY="$DIR/../server/venv/bin/python"
[ -x "$PY" ] || PY="$(command -v python3)"
STATE="$DIR/.last_event_key"

CURL_AUTH=()
[ -n "$API_TOKEN" ] && CURL_AUTH=(-H "X-API-Token: $API_TOKEN")
json=$(curl -s --max-time 6 "${CURL_AUTH[@]}" "$SERVER_API/api/status" || true)
[ -z "$json" ] && exit 0

line=$(printf '%s' "$json" | "$PY" -c '
import sys, json
try:
    d = json.load(sys.stdin)
    evs = d.get("events") or []
    if not evs:
        sys.exit(0)
    e = evs[0]
    t = str(e.get("t", ""))
    ev = str(e.get("event", ""))
    txt = str(e.get("text", ""))
    if ev in ("success", "grab_fail", "lecture_soon", "cookie_dead", "new_target"):
        print(t + "|" + ev + "|" + txt.replace(chr(10), " ")[:180])
except Exception:
    pass
' 2>/dev/null)

[ -z "$line" ] && exit 0
key=$(printf '%s' "$line" | cut -d'|' -f1)

last=$(cat "$STATE" 2>/dev/null || true)
if [ "$key" != "$last" ]; then
  echo "$key" > "$STATE"
  body=$(printf '%s' "$line" | cut -d'|' -f3- | sed 's/\\/\\\\/g; s/"/\\"/g')
  osascript -e "display notification \"$body\" with title \"同济抢讲座\" sound name \"Glass\"" >/dev/null 2>&1
fi
