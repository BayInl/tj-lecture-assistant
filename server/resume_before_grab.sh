#!/bin/bash
# 11:20 自动恢复服务 + 重新锁定目标（12:30 抢报兜底）
DIR="$(cd "$(dirname "$0")" && pwd)"
cd "$DIR" || exit 1
LOG="$DIR/resume.log"
echo "[$(date '+%F %T')] resume task start" >> "$LOG"
bash ctl.sh start >> "$LOG" 2>&1
sleep 10
echo "[$(date '+%F %T')] resume done" >> "$LOG"
