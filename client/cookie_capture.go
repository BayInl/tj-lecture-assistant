package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

//go:embed resources/token_sniffer.py
var embeddedSniffer []byte

// TokenPayload mirrors token.json written by token_sniffer.py.
type TokenPayload struct {
	Cookie       string         `json:"cookie"`
	SessionID    string         `json:"session_id"`
	WeixinCodeID string         `json:"weixin_code_id"`
	Token        string         `json:"token"`
	CapturedAt   string         `json:"captured_at"`
	Source       string         `json:"source"`
	Student      map[string]any `json:"student,omitempty"`
}

type proxySnapshot struct {
	HTTPEnabled  bool
	HTTPServer   string
	HTTPPort     string
	HTTPSEnabled bool
	HTTPSServer  string
	HTTPSPort    string
}

func findMitmdump(projDir string) string {
	binName := "mitmdump"
	if runtime.GOOS == "windows" {
		binName = "mitmdump.exe"
	}
	var cands []string
	if exe, err := os.Executable(); err == nil {
		exeDir := filepath.Dir(exe)
		cands = append(cands,
			filepath.Join(exeDir, binName),
			filepath.Join(exeDir, "mitmdump", binName),
			filepath.Join(exeDir, "..", "Resources", binName),
		)
	}
	if runtime.GOOS == "windows" {
		cands = append(cands, filepath.Join(configDir(), "venv", "Scripts", binName))
	} else {
		cands = append(cands,
			filepath.Join(configDir(), "venv", "bin", binName),
			"/opt/homebrew/bin/mitmdump",
			"/usr/local/bin/mitmdump",
		)
	}
	if projDir != "" {
		if runtime.GOOS == "windows" {
			cands = append(cands,
				filepath.Join(projDir, "cookie-windows", "mitmdump", binName),
				filepath.Join(projDir, "cookie-mac-linux", "venv", "Scripts", binName),
			)
		} else {
			cands = append(cands, filepath.Join(projDir, "cookie-mac-linux", "venv", "bin", binName))
		}
	}
	for _, p := range cands {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	if p, err := exec.LookPath(binName); err == nil {
		return p
	}
	return ""
}

func prepareCapturePaths(projDir string) (workDir, snifferPath, tokenPath, debugLogPath string, err error) {
	// Always stage capture scripts & temp files in local configDir() (never inside iCloud-synced Desktop).
	_ = projDir
	workDir = filepath.Join(configDir(), "capture")
	if err = os.MkdirAll(workDir, 0o700); err != nil {
		return "", "", "", "", err
	}
	snifferPath = filepath.Join(workDir, "token_sniffer.py")
	existing, rErr := os.ReadFile(snifferPath)
	if rErr != nil || !bytes.Equal(existing, embeddedSniffer) {
		if err = os.WriteFile(snifferPath, embeddedSniffer, 0o600); err != nil {
			return "", "", "", "", err
		}
	}
	return workDir, snifferPath, filepath.Join(workDir, "token.json"), filepath.Join(workDir, "sniff_debug.log"), nil
}

// directHTTPClient bypasses the temporary system proxy when validating captured cookies.
var directHTTPClient = &http.Client{
	Timeout: 6 * time.Second,
	Transport: &http.Transport{
		Proxy:               nil,
		MaxIdleConnsPerHost: 2,
		IdleConnTimeout:     30 * time.Second,
	},
}

func validateTongjiCookie(cookie string) (bool, map[string]any, string) {
	const (
		studentInfoURL = "https://lecture.tongji.edu.cn/api/gj/studentwx/studentapi/StudentInfo"
		authHeader     = "Basic cTN4YXRwbTV0eHc0MmtoejVjYzg1YWY0OmI1dTRteWVrZDVkYno0cGUxcTFoY3dnb3h4eXR0bTM3"
		ua             = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/144.0.0.0 Safari/537.36 NetType/WIFI MicroMessenger/7.0.20.1781(0x6700143B) WindowsWechat(0x63090a13) UnifiedPCWindowsWechat(0xf2541d41) XWEB/25560"
	)
	req, err := http.NewRequest(http.MethodGet, studentInfoURL, nil)
	if err != nil {
		return false, nil, err.Error()
	}
	req.Header.Set("Authorization", authHeader)
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "application/json, text/plain, */*")
	req.Header.Set("Cookie", cookie)

	resp, err := directHTTPClient.Do(req)
	if err != nil {
		return false, nil, err.Error()
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	var env struct {
		State string         `json:"state"`
		Msg   string         `json:"msg"`
		Data  map[string]any `json:"data"`
	}
	if err := json.Unmarshal(raw, &env); err != nil {
		return false, nil, "非 JSON 响应"
	}
	if env.State == "success" {
		return true, env.Data, ""
	}
	return false, nil, env.Msg
}

func waitPortReady(ctx context.Context, host string, port int, maxWait time.Duration, exited <-chan error) error {
	addr := net.JoinHostPort(host, fmt.Sprintf("%d", port))
	deadline := time.Now().Add(maxWait)
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case werr := <-exited:
			return fmt.Errorf("mitmdump 启动后退出(端口 %d 可能被占用): %v", port, werr)
		default:
		}
		conn, err := net.DialTimeout("tcp", addr, 80*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return nil
		}
		time.Sleep(80 * time.Millisecond)
	}
	return fmt.Errorf("mitmdump 在 %v 内未能监听端口 %d，已中止且未切换系统代理", maxWait, port)
}

// captureAndUploadCookie starts mitmdump scoped to lecture.tongji.edu.cn, toggles system proxy,
// optionally triggers WeChat automation, waits for a valid cookie, restores proxy, and uploads to server.
func captureAndUploadCookie(ctx context.Context, cfg ClientConfig, api *apiClient, automateWeChat bool, progress func(string)) error {
	cookieDir, snifferPath, tokenPath, debugLogPath, err := prepareCapturePaths(cfg.ProjectDir)
	if err != nil {
		return fmt.Errorf("准备抓包插件失败: %w", err)
	}
	mitmBin := findMitmdump(cfg.ProjectDir)
	if mitmBin == "" {
		return errors.New("未找到 mitmdump，请确认已随客户端打包或安装了依赖")
	}

	var prevMtime time.Time
	var prevCookie string
	if info, err := os.Stat(tokenPath); err == nil {
		prevMtime = info.ModTime()
		if b, err := os.ReadFile(tokenPath); err == nil {
			var tp TokenPayload
			if json.Unmarshal(b, &tp) == nil {
				prevCookie = tp.Cookie
			}
		}
	}

	progress("正在启动 mitmdump (仅拦截同济高等讲堂域名)…")
	cmd := exec.CommandContext(ctx, mitmBin,
		"-s", snifferPath,
		"--listen-host", "127.0.0.1",
		"--listen-port", fmt.Sprintf("%d", cfg.ProxyPort),
		"--allow-hosts", `^lecture\.tongji\.edu\.cn(:443)?$`,
		"--set", "ssl_insecure=true",
	)
	cmd.Dir = cookieDir
	configureBackgroundCmd(cmd)
	cmd.Env = append(os.Environ(),
		"TJ_SNIFFER_OUT="+tokenPath,
		"TJ_SNIFFER_LOG="+debugLogPath,
	)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("启动 mitmdump 失败: %w", err)
	}
	cmdDone := make(chan error, 1)
	go func() { cmdDone <- cmd.Wait() }()
	defer func() {
		terminateProcess(cmd, cmdDone)
	}()

	if err := waitPortReady(ctx, "127.0.0.1", cfg.ProxyPort, 10*time.Second, cmdDone); err != nil {
		return err
	}
	if _, certMsg := ensureMitmCert(); certMsg != "" {
		progress(certMsg)
	}

	origProxy := getSystemProxy(cfg.NetworkService)
	if err := setSystemProxy(cfg.NetworkService, "127.0.0.1", cfg.ProxyPort); err != nil {
		return fmt.Errorf("设置系统代理失败: %w", err)
	}
	defer restoreSystemProxy(cfg.NetworkService, origProxy)

	if automateWeChat {
		progress("代理已就绪，正在自动操控微信刷新「同济高等讲堂」…")
		if note, err := refreshWeChatLecture(cfg); err != nil {
			progress("自动操控微信未完成(" + err.Error() + ")，请手动点一下微信里的同济高等讲堂")
		} else {
			progress(note + "，等待截获 Cookie…")
		}
	} else {
		if runtime.GOOS == "windows" {
			progress(fmt.Sprintf("代理已切至 127.0.0.1:%d，请在电脑微信打开「同济高等讲堂」（无响应请重开微信）…", cfg.ProxyPort))
		} else {
			progress(fmt.Sprintf("代理已切至 127.0.0.1:%d，请在电脑微信里打开/刷新「同济高等讲堂」…", cfg.ProxyPort))
		}
	}

	deadline := time.Now().Add(180 * time.Second)
	freshOAuthTried := false
	startAt := time.Now()
	var lastChecked string
	var lastTry time.Time
	ticker := time.NewTicker(1200 * time.Millisecond)
	defer ticker.Stop()
	for time.Now().Before(deadline) {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case werr := <-cmdDone:
			return fmt.Errorf("mitmdump 意外退出: %v", werr)
		case <-ticker.C:
		}

		if automateWeChat && !freshOAuthTried && time.Since(startAt) > 8*time.Second {
			freshOAuthTried = true
			progress("暂未收到新会话，尝试从「搜一搜」重新打开 OAuth 登录页…")
			if note, err := openFreshWeChatLecture(cfg); err == nil && note != "" {
				progress(note)
			}
		}

		info, err := os.Stat(tokenPath)
		if err != nil {
			continue
		}
		if info.ModTime().Equal(prevMtime) {
			continue
		}
		b, err := os.ReadFile(tokenPath)
		if err != nil {
			continue
		}
		var tp TokenPayload
		if json.Unmarshal(b, &tp) != nil || tp.Cookie == "" {
			continue
		}
		if tp.Cookie == prevCookie && time.Since(lastTry) < 4*time.Second {
			continue
		}
		if tp.Cookie == lastChecked && time.Since(lastTry) < 3*time.Second {
			continue
		}
		lastChecked = tp.Cookie
		lastTry = time.Now()

		progress("已截获 Cookie，正在直连校验…")
		ok, student, msg := validateTongjiCookie(tp.Cookie)
		if !ok {
			progress("校验暂未生效(" + msg + ")，继续等待…")
			continue
		}
		if student != nil {
			tp.Student = student
		}
		progress("Cookie 校验有效，正在上传并热加载到服务器…")
		if err := api.UploadCookie(cfg, tp); err != nil {
			return fmt.Errorf("上传服务器失败: %w", err)
		}
		return nil
	}
	return errors.New("等待超时(180s)，未抓到新的有效 Cookie")
}
