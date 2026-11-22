//go:build !darwin && !windows

package main

import (
	"context"
	"errors"

	"github.com/egoist/mygo/plugins/permissionflow"
)

func accessibilityGranted() bool   { return false }
func screenRecordingGranted() bool { return false }

func guidePermission(_ context.Context, _ permissionflow.Permission) (permissionflow.Status, error) {
	return permissionflow.Denied, errors.New("当前系统不支持电脑操控")
}

func recordWindowRelativePoint(_ ClientConfig) (ClickPoint, error) {
	return ClickPoint{}, errors.New("当前系统不支持电脑操控")
}

func openFreshWeChatLecture(_ ClientConfig) (string, error) {
	return "", errors.New("当前系统不支持自动操控微信")
}

func refreshWeChatLecture(_ ClientConfig) (string, error) {
	return "", errors.New("当前系统不支持自动操控微信")
}
