#!/usr/bin/env bash
# add_user.sh —— 在 Linux 服务器上为同门开通独立隔离的抢讲座实例
# 共享同一份服务端代码(/root/tj_lecture/), 每个同门拥有独立数据目录、独立端口、独立登录凭据与 Cookie。
# 用法:
#   sudo bash add_user.sh <用户名> <端口> [登录密码]
# 示例:
#   sudo bash add_user.sh zhangsan 8849
set -euo pipefail

if [ "$#" -lt 2 ]; then
  echo "用法: $0 <用户名(字母数字)> <端口(如8849)> [初始密码(留空自动生成)]"
  exit 1
fi

USER_ID="$1"
PORT="$2"
PASSWORD="${3:-}"
if ! [[ "$USER_ID" =~ ^[a-zA-Z0-9_-]+$ ]]; then
  echo "[!] 用户名仅允许字母、数字、下划线或短横线"
  exit 2
fi
if ! [[ "$PORT" =~ ^[0-9]+$ ]] || [ "$PORT" -lt 1024 ] || [ "$PORT" -gt 65535 ]; then
  echo "[!] 端口无效: $PORT"
  exit 2
fi

CODE_DIR="$(cd "$(dirname "$0")" && pwd)"
PY="$CODE_DIR/venv/bin/python"
[ -x "$PY" ] || PY="$(command -v python3)"
DATA_DIR="/root/tj_lecture_users/${USER_ID}"
UNIT="tj-lecture-${USER_ID}"
UNIT_FILE="/etc/systemd/system/${UNIT}.service"

mkdir -p "$DATA_DIR"
if [ ! -f "$DATA_DIR/tj_config.json" ] && [ -f "$CODE_DIR/tj_config.example.json" ]; then
  cp "$CODE_DIR/tj_config.example.json" "$DATA_DIR/tj_config.json"
fi

if [ -z "$PASSWORD" ]; then
  PASSWORD="$("$PY" -c 'import secrets; print(secrets.token_urlsafe(9))')"
fi

TJ_DATA_DIR="$DATA_DIR" "$PY" "$CODE_DIR/server_app.py" --set-auth "$USER_ID" "$PASSWORD"

API_TOKEN="$("$PY" -c "import json; print((json.load(open('$DATA_DIR/tj_config.json')).get('auth') or {}).get('api_token',''))")"

cat > "$UNIT_FILE" <<EOF
[Unit]
Description=Tongji Lecture Grabber (${USER_ID})
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
WorkingDirectory=${CODE_DIR}
Environment=PYTHONUNBUFFERED=1
Environment=PYTHONIOENCODING=utf-8
Environment=TJ_DATA_DIR=${DATA_DIR}
Environment=TJ_HOST=0.0.0.0
Environment=TJ_PORT=${PORT}
ExecStart=${PY} ${CODE_DIR}/server_app.py
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "$UNIT"

echo ""
echo "========================================================"
echo " [✓] 已为同门 ${USER_ID} 开通独立实例 (${UNIT})"
echo " 数据目录 : ${DATA_DIR}"
echo " WebUI地址: http://<服务器IP>:${PORT}"
echo " 登录账号 : ${USER_ID}"
echo " 登录密码 : ${PASSWORD}"
echo " API Token: ${API_TOKEN}"
echo "========================================================"
