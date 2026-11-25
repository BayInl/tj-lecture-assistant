//go:build darwin

package main

import (
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

func configureBackgroundCmd(_ *exec.Cmd) {}

func terminateProcess(cmd *exec.Cmd, done <-chan error) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = cmd.Process.Signal(syscall.SIGTERM)
	select {
	case <-done:
	case <-time.After(600 * time.Millisecond):
		_ = cmd.Process.Kill()
	}
}

func ensureMitmCert() (bool, string) {
	return true, ""
}

func readProxyFlag(svc, flag string) (bool, string, string) {
	out, err := exec.Command("networksetup", flag, svc).Output()
	if err != nil {
		return false, "", ""
	}
	var en bool
	var srv, port string
	for _, line := range strings.Split(string(out), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.TrimSpace(v)
		switch k {
		case "enabled":
			en = strings.EqualFold(v, "yes")
		case "server":
			srv = v
		case "port":
			port = v
		}
	}
	return en, srv, port
}

func getSystemProxy(svc string) proxySnapshot {
	hEn, hSrv, hPort := readProxyFlag(svc, "-getwebproxy")
	sEn, sSrv, sPort := readProxyFlag(svc, "-getsecurewebproxy")
	kEn, kSrv, kPort := readProxyFlag(svc, "-getsocksfirewallproxy")
	return proxySnapshot{
		HTTPEnabled:  hEn,
		HTTPServer:   hSrv,
		HTTPPort:     hPort,
		HTTPSEnabled: sEn,
		HTTPSServer:  sSrv,
		HTTPSPort:    sPort,
		SOCKSEnabled: kEn,
		SOCKSServer:  kSrv,
		SOCKSPort:    kPort,
	}
}

func setSystemProxy(svc, host string, port int) error {
	p := fmt.Sprintf("%d", port)
	if err := exec.Command("networksetup", "-setwebproxy", svc, host, p).Run(); err != nil {
		return err
	}
	if err := exec.Command("networksetup", "-setsecurewebproxy", svc, host, p).Run(); err != nil {
		return err
	}
	// Temporarily disable SOCKS proxy during capture so WeChat/XWeb routes cleanly through mitmdump HTTP/HTTPS.
	_ = exec.Command("networksetup", "-setsocksfirewallproxystate", svc, "off").Run()
	_ = exec.Command("networksetup", "-setwebproxystate", svc, "on").Run()
	_ = exec.Command("networksetup", "-setsecurewebproxystate", svc, "on").Run()
	return nil
}

func restoreSystemProxy(svc string, snap proxySnapshot) {
	if snap.HTTPEnabled && snap.HTTPServer != "" && snap.HTTPPort != "" {
		_ = exec.Command("networksetup", "-setwebproxy", svc, snap.HTTPServer, snap.HTTPPort).Run()
		_ = exec.Command("networksetup", "-setwebproxystate", svc, "on").Run()
	} else {
		_ = exec.Command("networksetup", "-setwebproxystate", svc, "off").Run()
	}
	if snap.HTTPSEnabled && snap.HTTPSServer != "" && snap.HTTPSPort != "" {
		_ = exec.Command("networksetup", "-setsecurewebproxy", svc, snap.HTTPSServer, snap.HTTPSPort).Run()
		_ = exec.Command("networksetup", "-setsecurewebproxystate", svc, "on").Run()
	} else {
		_ = exec.Command("networksetup", "-setsecurewebproxystate", svc, "off").Run()
	}
	if snap.SOCKSEnabled && snap.SOCKSServer != "" && snap.SOCKSPort != "" {
		_ = exec.Command("networksetup", "-setsocksfirewallproxy", svc, snap.SOCKSServer, snap.SOCKSPort).Run()
		_ = exec.Command("networksetup", "-setsocksfirewallproxystate", svc, "on").Run()
	} else {
		_ = exec.Command("networksetup", "-setsocksfirewallproxystate", svc, "off").Run()
	}
}
