//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/windows/registry"
)

const inetSettingsPath = `Software\Microsoft\Windows\CurrentVersion\Internet Settings`

var (
	wininetDLL          = syscall.NewLazyDLL("wininet.dll")
	procInternetSetOptW = wininetDLL.NewProc("InternetSetOptionW")
)

func configureBackgroundCmd(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
}

func terminateProcess(cmd *exec.Cmd, done <-chan error) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Kill()
	select {
	case <-done:
	case <-time.After(600 * time.Millisecond):
	}
}

func notifyWinINetProxyChanged() {
	const (
		internetOptionRefresh         = 37
		internetOptionSettingsChanged = 39
	)
	_, _, _ = procInternetSetOptW.Call(0, internetOptionSettingsChanged, 0, 0)
	_, _, _ = procInternetSetOptW.Call(0, internetOptionRefresh, 0, 0)
}

func ensureMitmCert() (bool, string) {
	home, err := os.UserHomeDir()
	if err != nil {
		return false, ""
	}
	cer := filepath.Join(home, ".mitmproxy", "mitmproxy-ca-cert.cer")
	if _, err := os.Stat(cer); err != nil {
		return false, "未找到 CA 证书"
	}
	chk := exec.Command("certutil", "-user", "-verifystore", "Root", "mitmproxy")
	configureBackgroundCmd(chk)
	if chk.Run() == nil {
		return true, "证书已信任"
	}
	add := exec.Command("certutil", "-addstore", "-user", "Root", cer)
	configureBackgroundCmd(add)
	if out, err := add.CombinedOutput(); err != nil {
		return false, strings.TrimSpace(string(out))
	}
	return true, "已将 mitmproxy CA 证书装入当前用户受信任根证书"
}

func getSystemProxy(_ string) proxySnapshot {
	k, err := registry.OpenKey(registry.CURRENT_USER, inetSettingsPath, registry.QUERY_VALUE)
	if err != nil {
		return proxySnapshot{}
	}
	defer k.Close()

	en, _, _ := k.GetIntegerValue("ProxyEnable")
	srv, _, _ := k.GetStringValue("ProxyServer")
	return proxySnapshot{
		HTTPEnabled: en != 0,
		HTTPServer:  srv,
	}
}

func setSystemProxy(_ string, host string, port int) error {
	k, _, err := registry.CreateKey(registry.CURRENT_USER, inetSettingsPath, registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	if err := k.SetDWordValue("ProxyEnable", 1); err != nil {
		return err
	}
	if err := k.SetStringValue("ProxyServer", fmt.Sprintf("%s:%d", host, port)); err != nil {
		return err
	}
	notifyWinINetProxyChanged()
	return nil
}

func restoreSystemProxy(_ string, snap proxySnapshot) {
	k, err := registry.OpenKey(registry.CURRENT_USER, inetSettingsPath, registry.SET_VALUE)
	if err != nil {
		return
	}
	defer k.Close()

	if snap.HTTPEnabled {
		_ = k.SetDWordValue("ProxyEnable", 1)
	} else {
		_ = k.SetDWordValue("ProxyEnable", 0)
	}
	if snap.HTTPServer != "" {
		_ = k.SetStringValue("ProxyServer", snap.HTTPServer)
	}
	notifyWinINetProxyChanged()
}
