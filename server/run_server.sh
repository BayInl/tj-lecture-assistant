#!/usr/bin/env bash
# run_server.sh —— watchdog: 保持 server_app.py 常驻(崩溃自动重启)。
# 由 ctl.sh 用 setsid 脱离终端后台启动; 日志写入 app.log / watchdog.log。
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR" || exit 1
echo $$ > "$DIR/watchdog.pid"
export PYTHONUNBUFFERED=1
export PYTHONIOENCODING=utf-8
trap 'rm -f "$DIR/watchdog.pid"; exit 0' TERM INT
PY="$DIR/venv/bin/python"
[ -x "$PY" ] || PY=/usr/bin/python3
while true; do
  echo "[$(date '+%F %T')] 启动 server_app.py" >> watchdog.log
  "$PY" "$DIR/server_app.py" >> "$DIR/app.log" 2>&1
  rc=$?
  echo "[$(date '+%F %T')] server_app.py 退出 rc=$rc, 3 秒后重启" >> watchdog.log
  sleep 3
done
