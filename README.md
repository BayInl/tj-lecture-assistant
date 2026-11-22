# 同济高等讲堂 · 抢讲座系统（完整发布包）

自动盯讲座名额、到点秒抢、满了自动监测捡漏的一套系统。分三部分：**抢讲座服务** + **抓登录 Cookie 的工具（Windows exe / macOS·Linux py）**。

---

## 一、这个包分几块

```
tj_lecture_full/
├── server/               ← 【核心】抢讲座服务，跑在 Linux/Mac 服务器上，含 WebUI 控制台
├── cookie-windows/       ← Windows 抓 Cookie 工具（exe，开箱即用，抓本机微信PC）
├── cookie-mac-linux/     ← macOS / Linux 抓 Cookie 工具（py，功能等价 exe）
└── README.md             ← 本文件
```

三块的关系（数据怎么流动）：

```
[抓 Cookie]                          [抢讲座]
cookie-windows/ 或 cookie-mac-linux/   server/
  capture_token(.exe/.py)              server_app.py + lecture_grabber.py
        │ 抓到会话 Cookie                     │ 读 token.json
        ▼                                      ▼
   token.json  ──────────────────────►  自动抢 / 监测捡漏 + WebUI 控制台(:8848)
```

> **关键点**：`token.json` 是抓取工具的输出、抢讲座服务的输入。
> - 在**跑 server 的同一台机器**上抓 → `token.json` 就地生效，服务自动热加载，无需任何额外操作。
> - 在**另一台机器**（如你的 Windows 电脑）抓 → 把 `token.json` 拷到服务器的 `server/token.json`，服务会自动检测并热加载。

---

## 二、每块里都是什么文件

### 1) `server/` —— 抢讲座服务（部署在 Linux / macOS）

| 文件 | 作用 |
|---|---|
| `server_app.py` | **主程序**：Flask Web 服务 + 抢讲座引擎。提供 WebUI 控制台和全部 API，负责到点秒抢、监测捡漏、状态管理 |
| `lecture_grabber.py` | 讲座接口逆向库：拉讲座列表、解析状态、发起抢报，被 `server_app.py` 调用 |
| `notify.py` | 钉钉推送：抢到 / Cookie 失效 / 抢失败等事件通知（可选，不配 webhook 就不推） |
| `webui.html` | WebUI 前端页面：讲座列表、待抢清单、已选到卡片、配置面板 |
| `ctl.sh` | **服务控制脚本**：`start / stop / restart / status / logs`（容器无 systemd 时用 watchdog 常驻） |
| `run_server.sh` | watchdog：由 `ctl.sh` 调用，崩溃自动重启 `server_app.py` |
| `tj_config.example.json` | 配置模板（已脱敏）。复制成 `tj_config.json` 再改；**也可不复制**，首次启动会自动生成默认配置 |
| `requirements.txt` | 服务端依赖：`flask`、`requests` |

### 2) `cookie-windows/` —— Windows 抓 Cookie（exe）

| 文件 | 作用 |
|---|---|
| `capture_token.exe` | **双击即用**的抓取工具：自动改系统代理 → 抓本机微信PC 打开的 H5 → 截获 Cookie → 写 `token.json` → 自动还原代理 |
| `mitmdump/` | exe 的运行依赖（内含 `mitmdump.exe` + `_internal/`）。**请勿删除、勿单独移动** |
| `token_sniffer.py` | mitmproxy 嗅探插件，真正从流量里截获 Cookie 的核心（exe 内部调用） |
| `HOWTO.txt` | Windows 图文速用步骤 |

### 3) `cookie-mac-linux/` —— macOS / Linux 抓 Cookie（py）

| 文件 | 作用 |
|---|---|
| `capture_token.py` | 跨平台抓取主程序，功能与 exe 一致。Windows 用 `winreg`、macOS 用 `networksetup`、Linux 用 `gsettings` 改代理；另有 `--phone` 手机/局域网模式（服务器无微信时用） |
| `token_sniffer.py` | 同上，mitmproxy 嗅探插件 |
| `requirements.txt` | 依赖：`mitmproxy`、`requests` |

---

## 三、怎么部署（server 部分）

在 Linux / macOS 服务器上操作：

```bash
# 1. 上传 server/ 整个目录到服务器，例如 ~/tj_lecture/
cd ~/tj_lecture

# 2. 装依赖（若报 externally-managed-environment，用虚拟环境或加 --break-system-packages）
python3 -m pip install -r requirements.txt

# 3. （可选）改配置：复制模板再改；不改也行，首次启动自动生成默认配置
cp tj_config.example.json tj_config.json
#   编辑 tj_config.json：钉钉 webhook/secret（要推送才填）、端口、抢报策略等

# 4. 启动服务
bash ctl.sh start          # 后台常驻（崩溃自动重启）
bash ctl.sh status         # 查看运行状态 + 日志末尾
bash ctl.sh logs 60        # 实时看日志（Ctrl+C 退出）

# 想开机/登录自启（容器无 systemd 时）：
bash ctl.sh install-hook
```

不想用 ctl.sh 也可以直接前台跑（调试用）：

```bash
python3 server_app.py      # 然后浏览器打开 http://127.0.0.1:8848
```

启动后浏览器访问 **`http://<服务器IP>:8848`** 打开 WebUI 控制台。

---

## 四、怎么使用

### 第 1 步：抓 Cookie（登录凭证）

**Windows（推荐，最简单）**：
1. 进 `cookie-windows/`，**双击 `capture_token.exe`**
2. 首次会自动装 mitmproxy 证书；若微信 H5 报证书错误，用**管理员**身份重跑，或命令行执行 `capture_token.exe --machine-cert`
3. 按窗口提示：**完全退出并重启微信PC** → 微信里打开「同济高等讲堂」H5 并登录（能看到讲座列表）
4. 工具自动抓取 + 校验，成功后生成 `token.json`，并自动还原系统代理

**macOS / Linux**：
```bash
cd cookie-mac-linux
python3 -m pip install -r requirements.txt      # 装 mitmproxy
python3 capture_token.py                        # 桌面：抓本机微信，自动改/还原代理
python3 capture_token.py --phone                # 服务器无微信：手机 WiFi 代理指向本机IP抓手机微信
python3 capture_token.py --status               # 查看 代理/证书/token 状态
```

### 第 2 步：让 token.json 到位

- **在 server 本机抓的** → 已经在 `server/token.json`，服务自动热加载，跳到第 3 步。
- **在别的机器抓的** → 把 `token.json` 拷到服务器 `~/tj_lecture/token.json`，服务自动检测热加载。

> Cookie 会过期。失效时服务会通过钉钉提醒（若配了 webhook），重新抓一次、覆盖 `token.json` 即可。

### 第 3 步：WebUI 里抢讲座

打开 `http://<服务器IP>:8848`：
1. **讲座列表**：浏览所有讲座，点某场的「抢」按钮 → 加入待抢清单
   - 报名**未到点** → 等到点自动秒抢
   - 报名**已开放**（有余位/已满）→ 自动监测，有名额立即抢、满了等别人退订（捡漏）
2. **待抢清单**：显示每场的倒计时/状态（等待中、监测捡漏中、抢报中）。可随时「取消」→ 退回讲座列表
3. **已选到的讲座**：抢中的场次汇总（级别/标题/讲座时间/报名时间/抢中时间）
4. **配置面板**：调院级/校级自动抢、限定学院、钉钉推送、轮询间隔等

> 院级默认**全自动**（含捡漏），校级默认**监测但不自动抢**（需在列表点「抢」）。这些都可在配置面板改。

---

## 五、常见问题（FAQ）

**Q：exe 和 `capture_token.py` 啥区别？**
功能完全一样，都是抓 Cookie 写 `token.json`。exe 是 Windows 免装 Python 的开箱版；py 是 macOS/Linux 用的跨平台版（Windows 上也能跑）。

**Q：`push_cookie.py` 呢？**
本包**不需要**它。它只是「把 token.json 通过 SSH 从本地推到远程服务器」的便利脚本；你直接把 `token.json` 拷到服务器目录即可，服务会自动热加载。

**Q：Linux 服务器上没有微信怎么抓？**
用 `python3 capture_token.py --phone`：mitmdump 监听 `0.0.0.0`，把手机 WiFi 的 HTTP 代理指向「服务器局域网IP:端口」，手机装 mitmproxy 证书（浏览器开 `http://mitm.it`），再用**手机微信**打开 H5 登录即可抓到。

**Q：mitmdump 目录能删吗？**
不能。`cookie-windows/mitmdump/` 是 exe 的运行依赖，删了 exe 跑不起来。整个 `cookie-windows/` 请保持完整、不要拆散移动。

**Q：端口/策略在哪改？**
`server/tj_config.json`（没有就首次启动自动生成），或直接 WebUI 配置面板改。默认 WebUI 端口 `8848`。
