//go:build !darwin && !windows

package main

import (
	"errors"
	"os/exec"
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

func ensureMitmCert() (bool, string) { return true, "" }

func getSystemProxy(_ string) proxySnapshot { return proxySnapshot{} }

func setSystemProxy(_ string, _ string, _ int) error {
	return errors.New("当前系统不支持自动切换系统代理")
}

func restoreSystemProxy(_ string, _ proxySnapshot) {}
