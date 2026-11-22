#!/usr/bin/env bash
# ctl.sh —— 抢讲座服务控制脚本(容器无 systemd 时用 watchdog + setsid 常驻)。
#   ctl.sh start|stop|restart|status|logs [N]|install-hook|autostart
set -u
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR" || exit 1
PIDFILE="$DIR/watchdog.pid"

wd_running()  { [ -f "$PIDFILE" ] && kill -0 "$(cat "$PIDFILE" 2>/dev/null)" 2>/dev/null; }
app_running() { pgrep -f "$DIR/server_app.py" >/dev/null 2>&1; }

# 脱离终端后台拉起（macOS 无 setsid，用子 shell 兜底）
launch() {
  if command -v setsid >/dev/null 2>&1; then
    setsid bash "$DIR/run_server.sh" >/dev/null 2>&1 </dev/null &
  else
    (bash "$DIR/run_server.sh" >/dev/null 2>&1 </dev/null &)
  fi
}

start() {
  if wd_running; then echo "[i] watchdog 已在运行 (pid $(cat "$PIDFILE"))"; return 0; fi
  launch
  for _ in 1 2 3 4 5; do sleep 1; app_running && break; done
  if wd_running; then
    echo "[✓] 已启动: watchdog pid $(cat "$PIDFILE")  app pid $(pgrep -f "$DIR/server_app.py" | tr '\n' ' ')"
  else
    echo "[!] 启动可能失败, 请查看 watchdog.log / app.log"
  fi
}

stop() {
  wd_running && kill "$(cat "$PIDFILE")" 2>/dev/null
  pkill -f "$DIR/run_server.sh" 2>/dev/null
  pkill -f "$DIR/server_app.py" 2>/dev/null
  rm -f "$PIDFILE"
  sleep 1
  app_running && echo "[!] 仍有残留进程" || echo "[✓] 已停止"
}

status() {
  echo -n "watchdog : "; wd_running && echo "RUNNING (pid $(cat "$PIDFILE"))" || echo "STOPPED"
  echo -n "app      : "; if app_running; then pgrep -af "$DIR/server_app.py" | tr '\n' ' '; echo; else echo "NOT RUNNING"; fi
  echo "--- app.log 末尾 ---"; tail -n 12 "$DIR/app.log" 2>/dev/null || echo "(暂无 app.log)"
}

install_hook() {
  local rc="$HOME/.bashrc"; touch "$rc"
  if grep -q "tj_lecture autostart" "$rc" 2>/dev/null; then
    echo "[i] .bashrc 自启钩子已存在, 跳过"
  else
    {
      echo ""
      echo "# --- tj_lecture autostart (容器无 systemd 时, 登录/开终端自动拉起服务) ---"
      echo "[ -f \"$DIR/ctl.sh\" ] && bash \"$DIR/ctl.sh\" autostart >/dev/null 2>&1"
      echo "# --- end tj_lecture autostart ---"
    } >> "$rc"
    echo "[✓] 已写入 .bashrc 自启钩子"
  fi
}

# 供 .bashrc 调用: 未运行则静默后台拉起(不等待, 不拖慢开终端)
autostart() { wd_running || app_running || launch; }

case "${1:-status}" in
  start)        start ;;
  stop)         stop ;;
  restart)      stop; sleep 1; start ;;
  status)       status ;;
  logs)         tail -n "${2:-40}" -f "$DIR/app.log" 2>/dev/null ;;
  install-hook) install_hook ;;
  autostart)    autostart ;;
  *)            echo "用法: ctl.sh {start|stop|restart|status|logs [N]|install-hook|autostart}" ;;
esac
