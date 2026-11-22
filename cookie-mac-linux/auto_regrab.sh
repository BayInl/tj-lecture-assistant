#!/bin/bash
# auto_regrab.sh —— Cookie 失效自动更新（不重启微信版）
# 原理: Mac 微信 4.x (Radium/Chromium 内核) 动态读取系统代理 ——
#       只需「临时切代理 + 用户刷新一次 H5」即可抓到 Cookie, 完全不需要重启微信。
#   由 LaunchAgent com.tj.lecture.tokenwatch 定期调用。
#   手动: bash auto_regrab.sh [--dry-run] [--force]
#   临时暂停: touch .auto_regrab_paused ; 恢复: rm .auto_regrab_paused
set -u

PROJ="${TJ_PROJ_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"
COOKIE_DIR="$PROJ/cookie-mac-linux"
PY="$PROJ/server/venv/bin/python"
[ -x "$PY" ] || PY="$(command -v python3)"
LOG="$COOKIE_DIR/auto_regrab.log"
STATE="$COOKIE_DIR/.auto_regrab_state"
LOCK="$COOKIE_DIR/.auto_regrab.lock"
TOKEN="$COOKIE_DIR/token.json"
SVC="${TJ_NETWORK_SERVICE:-Wi-Fi}"
PROXY_PORT="${TJ_PROXY_PORT:-8080}"
SERVER="${TJ_REMOTE_SSH:-}"                      # 远程上传目标(可选, 如 user@server; 留空则只走 API 热重载)
SERVER_API="${TJ_SERVER_URL:-http://127.0.0.1:8848}" # 服务器 WebUI/API
SERVER_TOKEN="${TJ_REMOTE_TOKEN_PATH:-~/tj_lecture/token.json}" # 远程服务器 token.json 路径
API_TOKEN="${TJ_API_TOKEN:-}"                    # 可设环境变量或写入同目录 .api_token (勿提交到 Git)
[ -z "$API_TOKEN" ] && [ -f "$COOKIE_DIR/.api_token" ] && API_TOKEN=$(tr -d '[:space:]' < "$COOKIE_DIR/.api_token")
CURL_AUTH=()
[ -n "$API_TOKEN" ] && CURL_AUTH=(-H "X-API-Token: $API_TOKEN")

COOLDOWN_SEC=10800       # 两次自动尝试之间的最短间隔(秒; 失败后 3 小时再试)
MAX_PER_DAY=3            # 每天最多自动尝试次数
ACTIVE_FROM=7            # 活跃时段(小时)
ACTIVE_TO=23
WAIT_SEC=300             # 等待用户刷新 H5 的窗口(秒)

DRY=0; FORCE=0
for a in "$@"; do
  [ "$a" = "--dry-run" ] && DRY=1
  [ "$a" = "--force" ] && FORCE=1
done

log() { echo "[$(date '+%F %T')] $*" >> "$LOG"; }
notify() { osascript -e "display notification \"$1\" with title \"$2\" sound name \"Glass\"" >/dev/null 2>&1; }

# ---------- 记录/还原原系统代理 ----------
ORIG_EN=$(networksetup -getwebproxy "$SVC" 2>/dev/null | awk -F': ' '/Enabled/{print $2}' | tr -d ' ')
ORIG_SRV=$(networksetup -getwebproxy "$SVC" 2>/dev/null | awk -F': ' '/Server/{print $2}' | tr -d ' ')
ORIG_PORT=$(networksetup -getwebproxy "$SVC" 2>/dev/null | awk -F': ' '/Port/{print $2}' | tr -d ' ')

restore_proxy() {
  if [ "$ORIG_EN" = "Yes" ] && [ -n "${ORIG_SRV:-}" ] && [ -n "${ORIG_PORT:-}" ]; then
    networksetup -setwebproxy "$SVC" "$ORIG_SRV" "$ORIG_PORT" >/dev/null 2>&1
    networksetup -setsecurewebproxy "$SVC" "$ORIG_SRV" "$ORIG_PORT" >/dev/null 2>&1
    networksetup -setwebproxystate "$SVC" on >/dev/null 2>&1
    networksetup -setsecurewebproxystate "$SVC" on >/dev/null 2>&1
    log "已还原系统代理 -> $ORIG_SRV:$ORIG_PORT"
  else
    networksetup -setwebproxystate "$SVC" off >/dev/null 2>&1
    networksetup -setsecurewebproxystate "$SVC" off >/dev/null 2>&1
    log "已关闭系统代理(原本未启用)"
  fi
}

# ---------- 防重入 ----------
if [ "$DRY" = "0" ]; then
  if ! mkdir "$LOCK" 2>/dev/null; then
    oldpid=$(cat "$LOCK/pid" 2>/dev/null || true)
    if [ -n "${oldpid:-}" ] && kill -0 "$oldpid" 2>/dev/null; then
      echo "上一轮仍在运行(pid $oldpid), 跳过"; exit 0
    fi
    rm -rf "$LOCK"; mkdir "$LOCK" 2>/dev/null || { echo "锁竞争, 跳过"; exit 0; }
  fi
  echo $$ > "$LOCK/pid"
  trap 'rm -rf "$LOCK"' EXIT
fi

# ---------- 暂停开关 ----------
if [ "$FORCE" = "0" ] && [ -f "$COOKIE_DIR/.auto_regrab_paused" ]; then
  echo "已暂停(存在 .auto_regrab_paused), 跳过"; exit 0
fi

# ---------- 服务是否在跑 ----------
status_json=$(curl -s --max-time 8 "${CURL_AUTH[@]}" "$SERVER_API/api/status" || true)
if [ -z "$status_json" ]; then
  echo "服务器未响应(未运行?), 跳过"; exit 0
fi

# ---------- cookie 是否有效 ----------
valid=$("$PY" -c '
import sys, json
try:
    d = json.loads(sys.stdin.read())
    print(1 if d.get("cookie", {}).get("valid") else 0)
except Exception:
    print("?")' <<<"$status_json" 2>/dev/null)

if [ "$FORCE" = "1" ]; then
  echo "[force] 忽略状态判定, 强制执行"
elif [ "$valid" = "1" ]; then
  echo "cookie 有效, 无需处理"; exit 0
elif [ "$valid" != "0" ]; then
  echo "状态解析异常($valid), 保守跳过"; exit 0
fi

# ---------- 是否已有抓取在运行 ----------
if pgrep -f "token_sniffer.py" >/dev/null 2>&1; then
  echo "检测到抓包器正在运行(可能在抓取中), 跳过"; exit 0
fi

# ---------- 时段 / 冷却 / 次数 ----------
now_ts=$(date +%s); today=$(date +%Y%m%d); hour=$((10#$(date +%H)))
last_ts=0; last_day=""; count=0
if [ -f "$STATE" ]; then
  read -r last_ts last_day count < "$STATE" 2>/dev/null || true
fi
[ "${last_day:-}" != "$today" ] && count=0

if [ "$FORCE" = "0" ]; then
  if [ "$hour" -lt "$ACTIVE_FROM" ] || [ "$hour" -ge "$ACTIVE_TO" ]; then
    echo "非活跃时段(${ACTIVE_FROM}:00-${ACTIVE_TO}:00), 跳过"; exit 0
  fi
  if [ $((now_ts - last_ts)) -lt "$COOLDOWN_SEC" ]; then
    echo "冷却中(距上次尝试不足 $((COOLDOWN_SEC / 60)) 分钟), 跳过"; exit 0
  fi
  if [ "$count" -ge "$MAX_PER_DAY" ]; then
    echo "今日自动尝试已达上限(${MAX_PER_DAY} 次), 跳过"; exit 0
  fi
fi

if [ "$DRY" = "1" ]; then
  echo "[dry-run] cookie 失效, 将执行: 通知 → 切代理(8080) → 你刷新一次电脑微信的「同济高等讲堂」→ 抓取 → 还原代理 → 服务重载 (全程不重启微信)"
  exit 1
fi

# ---------- 记账 ----------
count=$((count + 1))
echo "$now_ts $today $count" > "$STATE"
log "=== Cookie 自动更新开始 (今日第 $count 次, 不重启微信) ==="

# ---------- 起抓包器 ----------
cd "$COOKIE_DIR" || exit 1
nohup ./venv/bin/mitmdump -s token_sniffer.py --listen-host 127.0.0.1 --listen-port "$PROXY_PORT" --allow-hosts '^lecture\.tongji\.edu\.cn(:443)?$' --set ssl_insecure=true >/dev/null 2>&1 &
MITM_PID=$!
sleep 3
if ! kill -0 "$MITM_PID" 2>/dev/null; then
  log "抓包器启动失败"
  notify "❌ Cookie 更新失败：抓包器启动失败（详见日志）" "同济抢讲座"
  exit 1
fi

# ---------- 切系统代理 ----------
networksetup -setwebproxy "$SVC" 127.0.0.1 "$PROXY_PORT" >/dev/null 2>&1
networksetup -setsecurewebproxy "$SVC" 127.0.0.1 "$PROXY_PORT" >/dev/null 2>&1
networksetup -setwebproxystate "$SVC" on >/dev/null 2>&1
networksetup -setsecurewebproxystate "$SVC" on >/dev/null 2>&1
log "系统代理已切到 127.0.0.1:$PROXY_PORT, 等待用户刷新 H5 (最长 ${WAIT_SEC}s)"

notify "Cookie 失效，请在 ${WAIT_SEC} 秒内打开/刷新一次【电脑微信】里的「同济高等讲堂」（点开即可，无需重启微信）" "同济抢讲座"

# ---------- 等待 token.json 更新 ----------
OLD_MT=0
[ -f "$TOKEN" ] && OLD_MT=$(stat -f %m "$TOKEN")
ok=0
for _ in $(seq 1 $((WAIT_SEC / 5))); do
  sleep 5
  if ! kill -0 "$MITM_PID" 2>/dev/null; then
    log "抓包器意外退出"
    break
  fi
  [ -f "$TOKEN" ] || continue
  NEW_MT=$(stat -f %m "$TOKEN")
  if [ "$NEW_MT" != "$OLD_MT" ]; then
    log "检测到 token.json 已更新, 校验中…"
    VAL=$("$PY" -c "
import json, sys
sys.path.insert(0, '$COOKIE_DIR')
from capture_token import validate_token
try:
    d = json.load(open('$TOKEN'))
    ok, res = validate_token(d.get('cookie', ''), d.get('token', ''))
    print('1' if ok else '0')
except Exception:
    print('0')
" 2>/dev/null)
    if [ "$VAL" = "1" ]; then ok=1; break; fi
    OLD_MT=$NEW_MT
  fi
done

# ---------- 还原代理 + 停抓包器 ----------
restore_proxy
kill "$MITM_PID" 2>/dev/null
sleep 1

# ---------- 结果 ----------
if [ "$ok" = "1" ]; then
  # 优先直传 Cookie JSON 到服务端 API；若配置了 TJ_REMOTE_SSH 也兼容 scp 上传
  up=0
  if [ -n "$SERVER" ] && scp -o BatchMode=yes -o ConnectTimeout=8 "$TOKEN" "$SERVER:$SERVER_TOKEN" >/dev/null 2>&1; then
    up=1
    log "token.json 已上传到服务器 $SERVER"
  else
    up=1
  fi
  reload_ok=0
  for _ in 1 2 3; do
    r=$(curl -s -X POST --max-time 20 "${CURL_AUTH[@]}" -H "Content-Type: application/json" -d @"$TOKEN" "$SERVER_API/api/cookie" || true)
    case "$r" in *'"valid":true'*) reload_ok=1; break ;; esac
    sleep 5
  done
  echo "0 $today 0" > "$STATE"
  log "Cookie 自动更新成功(未重启微信), 上传=$up, 服务器重载=$reload_ok"
  if [ "$up" = "1" ] && [ "$reload_ok" = "1" ]; then
    notify "✅ Cookie 已自动更新并上传服务器（微信未重启），抢讲座服务已恢复" "同济抢讲座"
  else
    notify "⚠️ Cookie 已抓到，但上传/重载异常（上传=$up 重载=$reload_ok），请查看日志" "同济抢讲座"
  fi
else
  log "Cookie 更新失败(等待超时或校验失败), 代理已还原"
  notify "❌ Cookie 更新未完成：请在方便时打开一次电脑微信里的「同济高等讲堂」（无需重启微信）" "同济抢讲座"
fi
