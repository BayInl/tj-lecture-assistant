param(
    [string]$Version = "dev"
)

$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$Dist = Join-Path $Root "dist"
$Stage = Join-Path $Dist "TJ-Lecture-Windows-x64"

if (Test-Path $Stage) { Remove-Item -Recurse -Force $Stage }
New-Item -ItemType Directory -Force -Path $Stage | Out-Null

# 1. Build MyGo Windows GUI client (no CGO required)
Push-Location (Join-Path $Root "client")
try {
    & go tool mygo build -platform windows/amd64 -skip-installer
    $exeCand = Get-ChildItem -Path "build\windows-amd64" -Filter "*.exe" | Select-Object -First 1
    if (-not $exeCand) { throw "未找到编译产出的 Windows 客户端 exe" }
    Copy-Item $exeCand.FullName -Destination (Join-Path $Stage "同济抢讲座助手.exe")
} finally {
    Pop-Location
}

# 2. Bundle Python Flask server into tj-server.exe (portable, no Python required for end users)
Push-Location (Join-Path $Root "server")
try {
    $pyWork = Join-Path $Dist "pyi-server"
    & python -m PyInstaller --noconfirm --clean --onefile --console `
        --name tj-server `
        --distpath $Stage `
        --workpath $pyWork `
        --add-data "webui.html;." `
        --add-data "login.html;." `
        server_app.py
} finally {
    Pop-Location
}

# 3. Bundle standalone mitmdump.exe from Python environment or local cookie-windows/mitmdump
$localMitm = Join-Path $Root "cookie-windows\mitmdump"
if (Test-Path (Join-Path $localMitm "mitmdump.exe")) {
    Copy-Item $localMitm -Destination (Join-Path $Stage "mitmdump") -Recurse
} else {
    $mitmExe = (Get-Command mitmdump -ErrorAction SilentlyContinue).Source
    if ($mitmExe) {
        $mitmScript = @'
from mitmproxy.tools.main import mitmdump
if __name__ == "__main__":
    mitmdump()
'@
        $mitmPy = Join-Path $Dist "mitmdump_entry.py"
        Set-Content -Path $mitmPy -Value $mitmScript -Encoding UTF8
        & python -m PyInstaller --noconfirm --clean --onefile --console `
            --name mitmdump `
            --distpath (Join-Path $Stage "mitmdump") `
            --workpath (Join-Path $Dist "pyi-mitm") `
            --collect-all mitmproxy `
            $mitmPy
    }
}

# 4. End-user quick-start README
@"
同济高等讲堂助手 Windows 绿色版 ($Version)

【使用方式（二选一）】
方式 A — 本地单机免部署运行（推荐小白 / 个人电脑自跑）：
  1. 直接双击运行 "同济抢讲座助手.exe"（软件会自动在后台启动本机 tj-server.exe）。
  2. 点击托盘图标打开面板，点「手动抓 Cookie」或「一键自动续期」。
     * 首次抓包会自动安装抓包根证书，并切换当前用户代理，完成后自动还原。
     * 若电脑版微信提示证书错误或未走代理，请尝试完全退出并重开一次微信再点开「同济高等讲堂」。

方式 B — 连接远程 Linux 服务器（如果师兄/同门给你开了独立端口与 Token）：
  1. 双击运行 "同济抢讲座助手.exe" → 切到「设置」页签。
  2. 保持「连远程服务器」，填入你的「服务器地址」(如 http://IP:8849) 与「API Token」，点「保存设置」。
  3. 之后直接在软件内抓 Cookie、收通知，关机后服务器也会继续帮你 24 小时盯防抢讲座。
"@ | Set-Content -Path (Join-Path $Stage "使用说明.txt") -Encoding UTF8

$ZipPath = Join-Path $Dist "TJ-Lecture-Windows-x64.zip"
if (Test-Path $ZipPath) { Remove-Item -Force $ZipPath }
Compress-Archive -Path "$Stage\*" -DestinationPath $ZipPath -CompressionLevel Optimal
Write-Host "Built: $ZipPath"
