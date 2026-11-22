#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
capture_token.py —— 跨平台(Windows / macOS / Linux)一键抓取 同济高等讲堂 登录会话 Cookie

【它做什么】
  本地起一个 mitmproxy 嗅探器(token_sniffer.py), 让微信打开「同济高等讲堂」H5 的流量经过它,
  自动从流量里截获会话 Cookie(PG.ASP.Session.ID + PG.ASP.WeiXinCode.ID), 校验通过后写入
  token.json。server_app.py / lecture_grabber.py 直接读 token.json 即可抢讲座。
  —— 功能与 Windows 版 capture_token.exe 完全一致, 只是补齐了 macOS/Linux。

【三种抓取路径】(按平台自动选, 也可手动指定)
  A 本机代理   : Windows/macOS 桌面自动改系统代理, 抓【本机微信PC】打开的 H5
  B 手机/局域网 : 嗅探器监听 0.0.0.0, 手机 WiFi 代理指向本机 IP:端口, 抓【手机微信】的 H5
                 (Linux 服务器无微信, 主力用这个; 手机证书走 http://mitm.it 下载安装)
  C 手动代理   : 你自己设好代理, 脚本只负责起嗅探器 + 抓取校验

【用法】
  python3 capture_token.py                  # 自动: 桌面→A(本机微信); 服务器/无桌面→B(手机)
  python3 capture_token.py --phone          # 强制手机/局域网模式(不改本机代理, 监听0.0.0.0)
  python3 capture_token.py --watch          # 抓到后保持嗅探持续刷新 token(Ctrl+C 结束并还原)
  python3 capture_token.py --status         # 查看 代理/证书/token.json 状态
  python3 capture_token.py --show           # 打印已抓到的完整 Cookie(供复制)
  python3 capture_token.py --restore-proxy  # 【应急】还原/关闭系统代理
  python3 capture_token.py --install-cert   # 只把 mitmproxy CA 证书装进系统信任区
  python3 capture_token.py --port 8080      # 指定监听端口(默认 8080)
  python3 capture_token.py --timeout 300    # 抓取等待超时秒数(默认 300)

【依赖】 pip install -r requirements.txt   (即 mitmproxy + requests)
【说明】 push_cookie.py 非必需: 若直接在跑 server_app.py 的机器上抓取, token.json 就地生效, 无需推送。
"""

import sys
import os
import time
import json
import shutil
import socket
import ctypes
import atexit
import signal
import datetime
import subprocess
import sysconfig

import requests

try:
    import winreg
except ImportError:
    winreg = None

try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

IS_WIN = sys.platform.startswith("win")
IS_MAC = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux")
PLATFORM = "Windows" if IS_WIN else ("macOS" if IS_MAC else ("Linux" if IS_LINUX else sys.platform))

if getattr(sys, "frozen", False):
    HERE = os.path.dirname(sys.executable)   # exe 同目录(放 token_sniffer.py / 写 token.json)
else:
    HERE = os.path.dirname(os.path.abspath(__file__))

PORT = 8080
BASE = "https://lecture.tongji.edu.cn"
AUTH = "Basic cTN4YXRwbTV0eHc0MmtoejVjYzg1YWY0OmI1dTRteWVrZDVkYno0cGUxcTFoY3dnb3h4eXR0bTM3"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/144.0.0.0 Safari/537.36 NetType/WIFI MicroMessenger/7.0.20.1781(0x6700143B) "
      "WindowsWechat(0x63090a13) UnifiedPCWindowsWechat(0xf2541d41) XWEB/25560")
STUDENTINFO = BASE + "/api/gj/studentwx/studentapi/StudentInfo"

MITMPROXY_DIR = os.path.join(os.path.expanduser("~"), ".mitmproxy")
CA_CERT_PEM = os.path.join(MITMPROXY_DIR, "mitmproxy-ca-cert.pem")   # macOS/Linux 用 PEM
CA_CERT_CER = os.path.join(MITMPROXY_DIR, "mitmproxy-ca-cert.cer")   # Windows 用 DER(.cer)
TOKEN_FILE = os.path.join(HERE, "token.json")
SNIFFER = os.path.join(HERE, "token_sniffer.py")

INET_KEY = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"

_orig_proxy = None       # Windows: 精确还原用
_proxy_changed = False   # macOS/Linux: 是否改过本机代理
_proc = None


# ==================== 平台探测 ====================
def has_desktop():
    """是否为有图形桌面的机器(能跑本机微信PC)。Windows/macOS 恒 True; Linux 看 DISPLAY。"""
    if IS_WIN or IS_MAC:
        return True
    return bool(os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"))


def get_lan_ip():
    """本机局域网出口 IP(供手机 WiFi 代理指向)。"""
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))          # 不实际发包, 只为选出出口网卡 IP
        return s.getsockname()[0]
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"
    finally:
        try:
            s.close()
        except Exception:
            pass


def _linux_os_family():
    """'debian'(apt系) / 'rhel'(yum/dnf系) / 'other'。"""
    try:
        with open("/etc/os-release", encoding="utf-8") as f:
            txt = f.read().lower()
        if any(k in txt for k in ("debian", "ubuntu", "mint", "kali", "deepin")):
            return "debian"
        if any(k in txt for k in ("rhel", "centos", "fedora", "rocky", "almalinux", "suse", "arch")):
            return "rhel"
    except Exception:
        pass
    return "other"


def _sudo_available():
    """非交互 sudo 是否可用(免密)。"""
    try:
        r = subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=10)
        return r.returncode == 0
    except Exception:
        return False


# ==================== 系统代理 (三平台) ====================
def _win_get_proxy():
    if winreg is None:
        return (0, "")
    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, INET_KEY, 0, winreg.KEY_READ)
    try:
        try:
            enable = int(winreg.QueryValueEx(k, "ProxyEnable")[0])
        except FileNotFoundError:
            enable = 0
        try:
            server = winreg.QueryValueEx(k, "ProxyServer")[0]
        except FileNotFoundError:
            server = ""
    finally:
        winreg.CloseKey(k)
    return (enable, server)


def _win_notify():
    try:
        wininet = ctypes.windll.Wininet
        wininet.InternetSetOptionW(0, 39, 0, 0)  # SETTINGS_CHANGED
        wininet.InternetSetOptionW(0, 37, 0, 0)  # REFRESH
    except Exception as e:
        print("[warn] 通知 WinINET 失败:", e)


def _win_set_proxy(enable, server=None):
    if winreg is None:
        print("[!] 非 Windows, 无法用注册表设代理")
        return False
    k = winreg.OpenKey(winreg.HKEY_CURRENT_USER, INET_KEY, 0, winreg.KEY_SET_VALUE)
    try:
        winreg.SetValueEx(k, "ProxyEnable", 0, winreg.REG_DWORD, 1 if enable else 0)
        if server is not None:
            winreg.SetValueEx(k, "ProxyServer", 0, winreg.REG_SZ, server)
    finally:
        winreg.CloseKey(k)
    _win_notify()
    return True


def _mac_network_service():
    """macOS 活动网络服务名(优先 Wi-Fi)。"""
    try:
        out = subprocess.run(["networksetup", "-listallnetworkservices"],
                             capture_output=True, text=True, timeout=10).stdout
        svcs = [l.strip() for l in out.splitlines()[1:] if l.strip() and not l.startswith("*")]
        for pref in ("wi-fi", "wifi", "ethernet"):
            for s in svcs:
                if pref in s.lower():
                    return s
        return svcs[0] if svcs else "Wi-Fi"
    except Exception:
        return "Wi-Fi"


def _mac_get_proxy():
    try:
        svc = _mac_network_service()
        out = subprocess.run(["networksetup", "-getwebproxy", svc],
                             capture_output=True, text=True, timeout=10).stdout
        d = {}
        for line in out.splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                d[k.strip().lower()] = v.strip()
        enable = 1 if d.get("enabled", "").lower() == "yes" else 0
        server = ("%s:%s" % (d.get("server", ""), d.get("port", ""))) if enable else ""
        return (enable, server)
    except Exception:
        return (0, "")


def _mac_set_proxy(enable, host="127.0.0.1", port=8080):
    svc = _mac_network_service()
    try:
        if enable:
            subprocess.run(["networksetup", "-setwebproxy", svc, host, str(port)], check=True, timeout=10)
            subprocess.run(["networksetup", "-setsecurewebproxy", svc, host, str(port)], check=True, timeout=10)
        else:
            subprocess.run(["networksetup", "-setwebproxystate", svc, "off"], check=True, timeout=10)
            subprocess.run(["networksetup", "-setsecurewebproxystate", svc, "off"], check=True, timeout=10)
        return True
    except Exception as e:
        print("[warn] macOS 设代理失败: %s" % str(e)[:120])
        print("      可手动: 系统设置→网络→%s→详细信息→代理→网页代理(HTTP)/安全网页代理(HTTPS) 指向 %s:%d" % (svc, host, port))
        return False


def _linux_get_proxy():
    if not shutil.which("gsettings"):
        return (0, "")
    try:
        mode = subprocess.run(["gsettings", "get", "org.gnome.system.proxy", "mode"],
                              capture_output=True, text=True, timeout=10).stdout.strip().strip("'")
        return (1 if mode == "manual" else 0, mode)
    except Exception:
        return (0, "")


def _linux_set_proxy(enable, host="127.0.0.1", port=8080):
    if not shutil.which("gsettings"):
        print("[!] 无 gsettings(非 GNOME 桌面/纯服务器), 无法自动改本机代理。")
        print("    → Linux 建议用手机/局域网模式: python3 capture_token.py --phone")
        return False
    try:
        if enable:
            subprocess.run(["gsettings", "set", "org.gnome.system.proxy", "mode", "manual"], check=True, timeout=10)
            for schema in ("org.gnome.system.proxy.http", "org.gnome.system.proxy.https"):
                subprocess.run(["gsettings", "set", schema, "host", host], check=True, timeout=10)
                subprocess.run(["gsettings", "set", schema, "port", str(port)], check=True, timeout=10)
        else:
            subprocess.run(["gsettings", "set", "org.gnome.system.proxy", "mode", "none"], check=True, timeout=10)
        return True
    except Exception as e:
        print("[warn] Linux 设代理失败: %s" % str(e)[:120])
        return False


def get_proxy():
    if IS_WIN:
        return _win_get_proxy()
    if IS_MAC:
        return _mac_get_proxy()
    if IS_LINUX:
        return _linux_get_proxy()
    return (0, "")


def set_proxy(enable, host="127.0.0.1", port=None):
    global _proxy_changed
    port = port or PORT
    if IS_WIN:
        ok = _win_set_proxy(enable, ("%s:%d" % (host, port)) if enable else None)
    elif IS_MAC:
        ok = _mac_set_proxy(enable, host, port)
    elif IS_LINUX:
        ok = _linux_set_proxy(enable, host, port)
    else:
        ok = False
    if ok:
        _proxy_changed = bool(enable)
    return ok


def restore_proxy():
    """还原/关闭系统代理(退出时自动调用)。"""
    global _orig_proxy, _proxy_changed
    if IS_WIN:
        if _orig_proxy is None:
            return
        en, srv = _orig_proxy
        _win_set_proxy(bool(en), srv if srv else None)
        print("[+] 已还原系统代理 (ProxyEnable=%s, ProxyServer=%s)" % (en, srv or "-"))
        _orig_proxy = None
    elif IS_MAC:
        if _proxy_changed:
            en, srv = (_orig_proxy or (0, ""))
            if en and srv and ":" in srv:
                host, _, port = srv.partition(":")
                if _mac_set_proxy(True, host, port):
                    print("[+] 已还原 macOS 系统代理 -> %s" % srv)
                else:
                    print("[!] 还原系统代理失败, 请手动在 设置→网络 中恢复")
            else:
                _mac_set_proxy(False)
                print("[+] 已关闭 macOS 系统代理")
            _orig_proxy = None
    elif IS_LINUX:
        if _proxy_changed:
            _linux_set_proxy(False)
            print("[+] 已还原 Linux 系统代理")
    _proxy_changed = False


# ==================== CA 证书信任 (三平台) ====================
def _win_install_cert(machine=False):
    if not os.path.exists(CA_CERT_CER):
        return False, "CA 证书尚未生成: %s" % CA_CERT_CER
    args = ["certutil", "-addstore"]
    if not machine:
        args.append("-user")
    args += ["Root", CA_CERT_CER]
    try:
        r = subprocess.run(args, capture_output=True, text=True, timeout=40)
    except Exception as e:
        return False, str(e)
    return (r.returncode == 0), ((r.stdout or "") + (r.stderr or "")).strip()


def _mac_install_cert():
    if not os.path.exists(CA_CERT_PEM):
        return False, "CA 证书尚未生成: %s" % CA_CERT_PEM
    kc = "/Library/Keychains/System.keychain"
    manual = ("  sudo security add-trusted-cert -d -r trustRoot -k %s %s" % (kc, CA_CERT_PEM))
    if not _sudo_available():
        return False, "需要管理员权限。请手动执行:\n" + manual
    try:
        subprocess.run(["sudo", "-n", "security", "add-trusted-cert", "-d", "-r", "trustRoot",
                        "-k", kc, CA_CERT_PEM], check=True, timeout=40)
        return True, "已装入系统钥匙串(System.keychain)"
    except Exception as e:
        return False, "%s\n请手动执行:\n%s" % (str(e)[:120], manual)


def _linux_install_cert():
    if not os.path.exists(CA_CERT_PEM):
        return False, "CA 证书尚未生成: %s" % CA_CERT_PEM
    fam = _linux_os_family()
    if fam == "debian":
        dst = "/usr/local/share/ca-certificates/mitmproxy-ca-cert.crt"
        upd = ["sudo", "update-ca-certificates"]
    elif fam == "rhel":
        dst = "/etc/pki/ca-trust/source/anchors/mitmproxy-ca-cert.pem"
        upd = ["sudo", "update-ca-trust"]
    else:
        return False, "未知发行版, 请手动把 %s 加入系统 CA 信任区" % CA_CERT_PEM
    manual = ("  sudo cp %s %s\n  sudo %s" % (CA_CERT_PEM, dst, upd[1]))
    if not _sudo_available():
        return False, "需要 sudo。请手动执行:\n" + manual
    try:
        subprocess.run(["sudo", "-n", "cp", CA_CERT_PEM, dst], check=True, timeout=20)
        subprocess.run(upd, check=True, timeout=90)
        return True, "已装入系统信任区(%s)" % fam
    except Exception as e:
        return False, "%s\n请手动执行:\n%s" % (str(e)[:120], manual)


def install_cert(machine=False):
    if IS_WIN:
        return _win_install_cert(machine)
    if IS_MAC:
        return _mac_install_cert()
    if IS_LINUX:
        return _linux_install_cert()
    return False, "不支持的平台: %s" % sys.platform


# ==================== mitmdump ====================
def find_mitmdump():
    exe = "mitmdump.exe" if IS_WIN else "mitmdump"
    if getattr(sys, "frozen", False):
        for p in (os.path.join(HERE, "mitmdump.exe"),
                  os.path.join(HERE, "mitmdump", "mitmdump.exe")):
            if os.path.exists(p):
                return [p]
    found = shutil.which(exe) or shutil.which("mitmdump")
    if found:
        return [found]
    p = os.path.join(sysconfig.get_path("scripts"), exe)
    if os.path.exists(p):
        return [p]
    return [sys.executable, "-c", "from mitmproxy.tools.main import mitmdump; mitmdump()"]


def start_mitmdump(listen_host="127.0.0.1"):
    global _proc
    cmd = find_mitmdump() + ["-s", SNIFFER, "--listen-host", listen_host,
                             "--listen-port", str(PORT),
                             "--allow-hosts", r"^lecture\.tongji\.edu\.cn(:443)?$",
                             "--set", "ssl_insecure=true"]
    print("[*] 启动 mitmdump:", " ".join(cmd))
    _proc = subprocess.Popen(cmd, cwd=HERE)
    return _proc


def stop_mitmdump():
    global _proc
    if _proc is not None and _proc.poll() is None:
        try:
            _proc.terminate()
            _proc.wait(timeout=5)
        except Exception:
            try:
                _proc.kill()
            except Exception:
                pass
        print("[+] mitmdump 已停止")
    _proc = None


def cleanup():
    stop_mitmdump()
    restore_proxy()


def _wait_ca(seconds=20):
    for _ in range(seconds * 2):
        if os.path.exists(CA_CERT_PEM) or os.path.exists(CA_CERT_CER):
            return True
        time.sleep(0.5)
    return False


# ==================== token 校验 ====================
def validate_token(cookie, token=""):
    """用会话 Cookie 直连 StudentInfo 校验登录态是否有效。"""
    h = {"Authorization": AUTH, "User-Agent": UA,
         "Accept": "application/json, text/plain, */*",
         "Accept-Encoding": "gzip, deflate",
         "Content-Type": "application/json;charset=UTF-8"}
    if cookie:
        h["Cookie"] = cookie
    if token:
        h["token"] = token
    try:
        r = requests.get(STUDENTINFO, headers=h, timeout=6,
                         proxies={"http": None, "https": None})   # 直连(不走代理), 避免自证循环
        d = r.json()
    except Exception as e:
        return False, "请求异常: %s" % e
    if isinstance(d, dict) and d.get("state") == "success":
        return True, d.get("data")
    return False, (d.get("msg") if isinstance(d, dict) else d)


def wait_for_token(timeout):
    t0 = time.time()
    last = None
    last_try = 0.0
    while time.time() - t0 < timeout:
        if _proc is not None and _proc.poll() is not None:
            print("[!] mitmdump 意外退出, 终止等待")
            return None
        if os.path.exists(TOKEN_FILE):
            try:
                d = json.load(open(TOKEN_FILE, encoding="utf-8"))
            except Exception:
                time.sleep(0.5)
                continue
            ck, tok = d.get("cookie"), d.get("token")
            key = ck or tok
            # cookie 变化 或 距上次校验>=3s 都重试: 登录绑定是异步的(IAM 回调后同一 session 才生效)
            if key and (key != last or time.time() - last_try >= 3.0):
                newkey = key != last
                last = key
                last_try = time.time()
                ok, res = validate_token(ck or "", tok or "")
                if ok:
                    d["valid"] = True
                    d["student"] = res
                    d["validated_at"] = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    with open(TOKEN_FILE, "w", encoding="utf-8") as f:
                        json.dump(d, f, ensure_ascii=False, indent=2)
                    return d
                elif newkey:
                    print("[.] 抓到凭据但校验未过: %s (登录绑定异步, 每3秒自动重试...)" % res)
        time.sleep(0.5)
    return None


def _troubleshoot(phone_mode):
    print("\n---- 排查提示 ----")
    if phone_mode:
        print(" 1) 手机必须与本机在同一局域网, 且能 ping 通本机 IP。")
        print(" 2) 手机 WiFi 代理要填【手动】: 服务器=本机IP, 端口=%d。" % PORT)
        print(" 3) 手机装证书: 代理生效后手机浏览器访问 http://mitm.it 下载对应系统 CA 并信任。")
        print("    iPhone 还需: 设置→通用→关于本机→证书信任设置→开启完全信任。")
        print(" 4) 部分安卓微信不走 WiFi 代理: 改用本机(桌面)微信, 或用安卓全局代理工具。")
    else:
        print(" 1) 微信PC 必须在【设置代理之后】重启, 才会走本地代理。")
        print(" 2) 若微信里 H5 报证书/无法打开: 证书没被信任。重跑并加 --install-cert(或 Windows 用管理员+ --machine-cert)。")
        print(" 3) 确认你在微信里真正完成了登录(能看到讲座列表), 而不是停在授权页。")
        print(" 4) 个别微信版本内置浏览器不走系统代理: 改用手机模式 python3 capture_token.py --phone。")
    print(" 5) 应急还原代理: python3 capture_token.py --restore-proxy")


# ==================== 命令 ====================
def cmd_status():
    print("平台    : %s (%s)" % (PLATFORM, "有桌面" if has_desktop() else "无桌面/服务器"))
    en, srv = get_proxy()
    print("系统代理: %s" % (("开启 -> %s" % srv) if en else "关闭/未设"))
    ca = CA_CERT_CER if IS_WIN else CA_CERT_PEM
    print("CA 证书 : %s" % (("存在 " + ca) if os.path.exists(ca) else "未生成(先跑一次 capture)"))
    print("局域网IP: %s:%d (手机代理指向这里)" % (get_lan_ip(), PORT))
    if os.path.exists(TOKEN_FILE):
        try:
            d = json.load(open(TOKEN_FILE, encoding="utf-8"))
            sid = d.get("session_id") or (d.get("cookie", "")[:24])
            print("token.json: 存在, session=%s captured=%s source=%s valid=%s" % (
                sid, d.get("captured_at"), d.get("source"), d.get("valid")))
            ok, res = validate_token(d.get("cookie", ""), d.get("token", ""))
            print("实时校验  : %s  %s" % ("有效" if ok else "无效", json.dumps(res, ensure_ascii=False)[:100]))
        except Exception as e:
            print("token.json: 读取失败", e)
    else:
        print("token.json: 不存在")


def _print_cookie_block(d):
    """完整打印 cookie(不截断), 方便复制到自己的服务器/环境。"""
    ck = d.get("cookie") or ""
    print("\n[★★★] 会话凭据抓取并校验成功!")
    print("  student  =", json.dumps(d.get("student"), ensure_ascii=False)[:120])
    print("  session  =", d.get("session_id"))
    print("  captured =", d.get("captured_at"), " source =", d.get("source"))
    print("  写入文件 =", TOKEN_FILE)
    print("\n" + "=" * 62)
    print("  完整 Cookie (复制下面这一整行, 填到目标机器 token.json 的 cookie 字段):")
    print("-" * 62)
    print(ck)
    print("-" * 62)
    print("  若就在跑 server_app.py 的机器上抓取: token.json 已就地生成, 服务会自动读取, 无需推送。")
    print("  若在别的机器抓取: 把 token.json 拷到服务器 ~/tj_lecture/ 同目录即可。")
    print("=" * 62)


def cmd_show():
    """随时打印已抓到的完整 cookie(供复制), 无需重新抓取。"""
    if not os.path.exists(TOKEN_FILE):
        print("token.json 不存在, 请先运行 capture_token 抓取。")
        return
    try:
        d = json.load(open(TOKEN_FILE, encoding="utf-8"))
    except Exception as e:
        print("token.json 读取失败:", e)
        return
    ok, res = validate_token(d.get("cookie", ""), d.get("token", ""))
    print("实时校验 =", "有效" if ok else "无效",
          (json.dumps(res, ensure_ascii=False)[:80] if ok else str(res)[:80]))
    _print_cookie_block(d)


def _pause_exit():
    """交互运行时停留窗口, 方便查看/复制完整 Cookie, 回车后再退出(退出时自动还原代理)。"""
    try:
        print()
        input("按回车键退出 (退出时自动还原系统代理/停止嗅探)...")
    except Exception:
        pass


def _print_phone_guide():
    ip = get_lan_ip()
    print("\n" + "★" * 30)
    print("  【手机 / 局域网抓取模式】监听 0.0.0.0:%d" % PORT)
    print("  本机局域网 IP = %s" % ip)
    print("  请在【手机】上操作(手机需与本机同一局域网):")
    print("   1) 手机 WiFi 设置 → HTTP 代理 → 手动 → 服务器 %s  端口 %d" % (ip, PORT))
    print("   2) 手机浏览器访问 http://mitm.it → 下载对应系统 CA 证书并安装、信任")
    print("      · iPhone: 装完后到 设置→通用→关于本机→证书信任设置 开启完全信任")
    print("      · Android: 设置→安全→加密与凭据→安装证书→CA 证书")
    print("   3) 手机微信打开「同济高等讲堂」H5, 完成登录(能看到讲座列表)")
    print("   4) 本窗口会自动抓取+校验, 成功后写入 token.json")
    print("  注: 服务器在机房/远程时手机可能连不上, 请改在能同时访问微信与本机的机器上抓。")
    print("★" * 30 + "\n")


def _print_desktop_guide():
    print("\n" + "★" * 30)
    print("  【本机代理抓取模式】(%s 桌面)" % PLATFORM)
    print("   1) 完全退出并重启 微信PC (让它走本地代理 127.0.0.1:%d)" % PORT)
    print("   2) 微信里打开「同济高等讲堂」H5, 完成登录(能看到讲座列表)")
    print("   3) 本窗口自动抓取+校验, 成功后自动还原代理")
    print("   想改用【手机微信】抓? 加 --phone 重跑: python3 capture_token.py --phone")
    print("★" * 30 + "\n")


def cmd_capture(timeout=300, watch=False, machine_cert=False, phone=False, port=8080):
    global PORT, _orig_proxy
    PORT = port
    desktop = has_desktop()
    use_phone = phone or (not desktop)     # 无桌面(服务器) 或 显式 --phone → 手机模式
    listen_host = "0.0.0.0" if use_phone else "127.0.0.1"

    atexit.register(cleanup)
    for s in ("SIGINT", "SIGBREAK", "SIGTERM"):
        if hasattr(signal, s):
            try:
                signal.signal(getattr(signal, s), lambda *a: (cleanup(), sys.exit(0)))
            except Exception:
                pass

    start_mitmdump(listen_host)
    print("[*] 等待 mitmproxy 生成 CA 证书...")
    _wait_ca(20)

    if use_phone:
        # 手机模式: 不动本机代理、不装本机证书(证书由手机通过 mitm.it 安装)
        _print_phone_guide()
    else:
        # 本机模式: 记录原代理 → 装证书 → 设代理
        _orig_proxy = get_proxy()
        ok, msg = install_cert(machine=machine_cert)
        if ok:
            print("[✓] CA 证书已信任: %s" % msg)
        else:
            print("[!] CA 证书自动信任未成功: %s" % msg)
        if set_proxy(True, "127.0.0.1", PORT):
            print("[✓] 已设置系统代理 -> 127.0.0.1:%d" % PORT)
        _print_desktop_guide()

    d = wait_for_token(timeout)
    if d:
        _print_cookie_block(d)
        print("\n下一步: 本机可 python3 lecture_grabber.py find 验证; 服务器会自动读取 token.json 抢讲座。")
        if watch:
            print("\n[*] watch 模式: 保持嗅探持续刷新 token, 按 Ctrl+C 结束并自动还原。")
            try:
                while True:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
        else:
            _pause_exit()
    else:
        print("\n[!] 超时(%ds)未抓到有效 token。" % timeout)
        _troubleshoot(use_phone)
        _pause_exit()


def main():
    args = sys.argv[1:]
    timeout = 300
    if "--timeout" in args:
        i = args.index("--timeout")
        try:
            timeout = int(args[i + 1])
        except Exception:
            pass
    port = 8080
    if "--port" in args:
        i = args.index("--port")
        try:
            port = int(args[i + 1])
        except Exception:
            pass
    watch = "--watch" in args
    machine = "--machine-cert" in args
    phone = ("--phone" in args) or ("--lan" in args)

    if "--restore-proxy" in args:
        if IS_WIN:
            en, srv = get_proxy()
            set_proxy(False)
            print("[+] 已关闭系统代理 (原 ProxyEnable=%s, ProxyServer=%s)" % (en, srv or "-"))
        elif IS_MAC:
            _mac_set_proxy(False)
            print("[+] 已关闭 macOS 系统代理")
        elif IS_LINUX:
            _linux_set_proxy(False)
            print("[+] 已还原 Linux 系统代理")
        else:
            print("[!] 不支持的平台")
    elif "--install-cert" in args:
        ok, msg = install_cert(machine=machine)
        print(("[✓] " if ok else "[!] ") + msg)
    elif "--status" in args:
        cmd_status()
    elif "--show" in args or "--print-cookie" in args or "--cookie" in args:
        cmd_show()
    else:
        cmd_capture(timeout=timeout, watch=watch, machine_cert=machine, phone=phone, port=port)


if __name__ == "__main__":
    main()
