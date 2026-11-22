//go:build windows

package main

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"

	"github.com/egoist/mygo/plugins/permissionflow"
)

var (
	user32DLL             = syscall.NewLazyDLL("user32.dll")
	kernel32DLL           = syscall.NewLazyDLL("kernel32.dll")
	procEnumWindows       = user32DLL.NewProc("EnumWindows")
	procIsWindowVisible   = user32DLL.NewProc("IsWindowVisible")
	procGetWindowTextW    = user32DLL.NewProc("GetWindowTextW")
	procGetWindowRect     = user32DLL.NewProc("GetWindowRect")
	procShowWindow        = user32DLL.NewProc("ShowWindow")
	procSetForegroundWin  = user32DLL.NewProc("SetForegroundWindow")
	procGetCursorPos      = user32DLL.NewProc("GetCursorPos")
	procSetCursorPos      = user32DLL.NewProc("SetCursorPos")
	procMouseEvent        = user32DLL.NewProc("mouse_event")
	procKeybdEvent        = user32DLL.NewProc("keybd_event")
	procOpenClipboard     = user32DLL.NewProc("OpenClipboard")
	procCloseClipboard    = user32DLL.NewProc("CloseClipboard")
	procEmptyClipboard    = user32DLL.NewProc("EmptyClipboard")
	procSetClipboardData  = user32DLL.NewProc("SetClipboardData")
	procGlobalAlloc       = kernel32DLL.NewProc("GlobalAlloc")
	procGlobalLock        = kernel32DLL.NewProc("GlobalLock")
	procGlobalUnlock      = kernel32DLL.NewProc("GlobalUnlock")
	procRtlMoveMemory     = kernel32DLL.NewProc("RtlMoveMemory")
)

type winRect struct {
	Left, Top, Right, Bottom int32
}

type winPoint struct {
	X, Y int32
}

func accessibilityGranted() bool   { return true }
func screenRecordingGranted() bool { return true }

func guidePermission(_ context.Context, _ permissionflow.Permission) (permissionflow.Status, error) {
	return permissionflow.Granted, nil
}

func listWin32WeChatWindows() []WeChatWindow {
	var wins []WeChatWindow
	cb := syscall.NewCallback(func(hwnd uintptr, _ uintptr) uintptr {
		vis, _, _ := procIsWindowVisible.Call(hwnd)
		if vis == 0 {
			return 1
		}
		buf := make([]uint16, 256)
		n, _, _ := procGetWindowTextW.Call(hwnd, uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
		if n == 0 {
			return 1
		}
		title := syscall.UTF16ToString(buf[:n])
		if title != "微信" && !strings.Contains(strings.ToLower(title), "wechat") && !strings.Contains(title, "高等讲堂") {
			return 1
		}
		var rc winRect
		ok, _, _ := procGetWindowRect.Call(hwnd, uintptr(unsafe.Pointer(&rc)))
		if ok == 0 {
			return 1
		}
		w := float64(rc.Right - rc.Left)
		h := float64(rc.Bottom - rc.Top)
		if w < 120 || h < 120 {
			return 1
		}
		wins = append(wins, WeChatWindow{
			ID:    int(hwnd),
			Title: title,
			X:     float64(rc.Left),
			Y:     float64(rc.Top),
			W:     w,
			H:     h,
			Area:  w * h,
		})
		return 1
	})
	_, _, _ = procEnumWindows.Call(cb, 0)
	sort.Slice(wins, func(i, j int) bool { return wins[i].Area > wins[j].Area })
	return wins
}

func setWinClipboardText(text string) error {
	const (
		gmemMoveable  = 0x0002
		cfUnicodeText = 13
	)
	u16 := utf16.Encode([]rune(text + "\x00"))
	sz := uintptr(len(u16) * 2)
	hMem, _, err := procGlobalAlloc.Call(gmemMoveable, sz)
	if hMem == 0 {
		return err
	}
	ptr, _, _ := procGlobalLock.Call(hMem)
	if ptr == 0 {
		return errors.New("GlobalLock 失败")
	}
	_, _, _ = procRtlMoveMemory.Call(ptr, uintptr(unsafe.Pointer(&u16[0])), sz)
	_, _, _ = procGlobalUnlock.Call(hMem)

	ok, _, _ := procOpenClipboard.Call(0)
	if ok == 0 {
		return errors.New("打开剪贴板失败")
	}
	defer func() { _, _, _ = procCloseClipboard.Call() }()
	_, _, _ = procEmptyClipboard.Call()
	r, _, _ := procSetClipboardData.Call(cfUnicodeText, hMem)
	if r == 0 {
		return errors.New("写入剪贴板失败")
	}
	return nil
}

func winClickAt(x, y int) {
	const (
		mouseEventfLeftDown = 0x0002
		mouseEventfLeftUp   = 0x0004
	)
	_, _, _ = procSetCursorPos.Call(uintptr(x), uintptr(y))
	time.Sleep(35 * time.Millisecond)
	_, _, _ = procMouseEvent.Call(mouseEventfLeftDown, 0, 0, 0, 0)
	time.Sleep(35 * time.Millisecond)
	_, _, _ = procMouseEvent.Call(mouseEventfLeftUp, 0, 0, 0, 0)
}

func winKeyTap(vk byte) {
	const keyEventfKeyUp = 0x0002
	_, _, _ = procKeybdEvent.Call(uintptr(vk), 0, 0, 0)
	time.Sleep(20 * time.Millisecond)
	_, _, _ = procKeybdEvent.Call(uintptr(vk), 0, keyEventfKeyUp, 0)
}

func winCtrlKey(vk byte) {
	const (
		vkControl      = 0x11
		keyEventfKeyUp = 0x0002
	)
	_, _, _ = procKeybdEvent.Call(vkControl, 0, 0, 0)
	time.Sleep(20 * time.Millisecond)
	_, _, _ = procKeybdEvent.Call(uintptr(vk), 0, 0, 0)
	time.Sleep(20 * time.Millisecond)
	_, _, _ = procKeybdEvent.Call(uintptr(vk), 0, keyEventfKeyUp, 0)
	time.Sleep(20 * time.Millisecond)
	_, _, _ = procKeybdEvent.Call(vkControl, 0, keyEventfKeyUp, 0)
}

func focusWinWeChatWindow(hwnd int) {
	const swRestore = 9
	_, _, _ = procShowWindow.Call(uintptr(hwnd), swRestore)
	_, _, _ = procSetForegroundWin.Call(uintptr(hwnd))
	time.Sleep(200 * time.Millisecond)
}

func recordWindowRelativePoint(cfg ClientConfig) (ClickPoint, error) {
	var pt winPoint
	ok, _, _ := procGetCursorPos.Call(uintptr(unsafe.Pointer(&pt)))
	if ok == 0 {
		return ClickPoint{}, errors.New("读取鼠标坐标失败")
	}
	wins := listWin32WeChatWindows()
	if len(wins) == 0 {
		return ClickPoint{}, errors.New("未检测到微信窗口，请先打开电脑版微信")
	}
	w := wins[0]
	dx := int(pt.X) - int(w.X)
	dy := int(pt.Y) - int(w.Y)
	if dx < 0 || dy < 0 || float64(dx) > w.W || float64(dy) > w.H {
		return ClickPoint{}, fmt.Errorf("当前鼠标 (%d,%d) 不在微信窗口区域 (%.0f,%.0f %.0fx%.0f) 内", pt.X, pt.Y, w.X, w.Y, w.W, w.H)
	}
	anchor := "ratio"
	if dx <= 76 {
		anchor = "sidebar"
	}
	return ClickPoint{
		RX:     float64(dx) / w.W,
		RY:     float64(dy) / w.H,
		DX:     dx,
		DY:     dy,
		Anchor: anchor,
		Note:   fmt.Sprintf("步骤 %d", len(cfg.ClickPoints)+1),
	}, nil
}

func sendWinWeChatSearch(hwnd int, kw string) error {
	focusWinWeChatWindow(hwnd)
	if err := setWinClipboardText(kw); err != nil {
		return err
	}
	winCtrlKey('F')
	time.Sleep(220 * time.Millisecond)
	winCtrlKey('A')
	time.Sleep(60 * time.Millisecond)
	winKeyTap(0x08) // VK_BACK
	time.Sleep(60 * time.Millisecond)
	winCtrlKey('V')
	time.Sleep(450 * time.Millisecond)
	winKeyTap(0x0D) // VK_RETURN
	return nil
}

func openFreshWeChatLecture(cfg ClientConfig) (string, error) {
	wins := listWin32WeChatWindows()
	if len(wins) == 0 {
		return "", errors.New("未找到已打开的电脑版微信窗口")
	}
	kw := nonEmpty(cfg.SearchKeyword, "同济大学研究生院")
	if err := sendWinWeChatSearch(wins[0].ID, kw); err != nil {
		return "", err
	}
	return "已在 Windows 微信发起「" + kw + "」搜一搜，请点开公众号里的「高等讲堂」", nil
}

func refreshWeChatLecture(cfg ClientConfig) (string, error) {
	wins := listWin32WeChatWindows()
	if len(wins) == 0 {
		return "", errors.New("未找到已打开的电脑版微信窗口，请先登录电脑版微信")
	}
	mw := wins[0]
	focusWinWeChatWindow(mw.ID)
	if len(cfg.ClickPoints) > 0 {
		for _, pt := range cfg.ClickPoints {
			tx, ty := resolveClickPoint(pt, mw)
			winClickAt(tx, ty)
			time.Sleep(750 * time.Millisecond)
			if winsNext := listWin32WeChatWindows(); len(winsNext) > 0 {
				mw = winsNext[0]
			}
		}
		return fmt.Sprintf("已按微信窗口相对坐标依次点击 %d 个位置", len(cfg.ClickPoints)), nil
	}
	kw := nonEmpty(cfg.SearchKeyword, "同济大学研究生院")
	if err := sendWinWeChatSearch(mw.ID, kw); err != nil {
		return "", err
	}
	return "已在 Windows 微信发起「" + kw + "」搜一搜（可录制相对坐标实现全自动点击）", nil
}
