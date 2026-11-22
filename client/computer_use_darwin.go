//go:build darwin

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/egoist/mygo/plugins/permissionflow"
)

func accessibilityGranted() bool {
	st, err := permissionflow.Check(permissionflow.Accessibility)
	return err == nil && st == permissionflow.Granted
}

func screenRecordingGranted() bool {
	st, err := permissionflow.Check(permissionflow.ScreenRecording)
	return err == nil && st == permissionflow.Granted
}

func guidePermission(ctx context.Context, perm permissionflow.Permission) (permissionflow.Status, error) {
	return permissionflow.Guide(ctx, perm, permissionflow.GuideOptions{})
}

func findOCRHelper(projDir string) string {
	var cands []string
	if exe, err := os.Executable(); err == nil {
		cands = append(cands,
			filepath.Join(filepath.Dir(exe), "..", "Resources", "ocr-helper"),
			filepath.Join(filepath.Dir(exe), "resources", "ocr-helper"),
		)
	}
	if projDir != "" {
		cands = append(cands, filepath.Join(projDir, "client", "resources", "ocr-helper"))
	}
	cands = append(cands, filepath.Join("resources", "ocr-helper"))
	for _, p := range cands {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	return ""
}

func listWeChatWindows(helper string) ([]WeChatWindow, error) {
	if helper == "" {
		return nil, errors.New("未找到 ocr-helper")
	}
	out, err := exec.Command(helper, "--wechat-windows").Output()
	if err != nil {
		return nil, fmt.Errorf("枚举微信窗口失败: %w", err)
	}
	var wins []WeChatWindow
	if err := json.Unmarshal(out, &wins); err != nil {
		return nil, err
	}
	return wins, nil
}

func captureWindowOCR(helper string, winID int) ([]OCRHit, error) {
	tmp, err := os.CreateTemp("", "tj-wechat-*.png")
	if err != nil {
		return nil, err
	}
	tmpPath := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(tmpPath)

	if out, err := exec.Command("screencapture", "-x", "-o", "-l", fmt.Sprintf("%d", winID), tmpPath).CombinedOutput(); err != nil {
		return nil, fmt.Errorf("截屏微信窗口失败: %v %s", err, strings.TrimSpace(string(out)))
	}
	out, err := exec.Command(helper, "--ocr", tmpPath).Output()
	if err != nil {
		return nil, fmt.Errorf("Vision OCR 识别失败: %w", err)
	}
	var hits []OCRHit
	if err := json.Unmarshal(out, &hits); err != nil {
		return nil, err
	}
	return hits, nil
}

// currentMousePos returns screen coordinates (top-left origin in points), preferring native ocr-helper over JXA.
func currentMousePos(helper string) (int, int, error) {
	if helper != "" {
		if out, err := exec.Command(helper, "--mouse").Output(); err == nil {
			var res struct {
				X int `json:"x"`
				Y int `json:"y"`
			}
			if json.Unmarshal(out, &res) == nil {
				return res.X, res.Y, nil
			}
		}
	}
	jxa := `ObjC.import("AppKit");
var p = $.NSEvent.mouseLocation;
var screens = $.NSScreen.screens;
var h = screens.objectAtIndex(0).frame.size.height;
JSON.stringify({x: Math.round(p.x), y: Math.round(h - p.y)});`
	out, err := exec.Command("osascript", "-l", "JavaScript", "-e", jxa).Output()
	if err != nil {
		return 0, 0, fmt.Errorf("读取鼠标位置失败: %w", err)
	}
	var res struct {
		X int `json:"x"`
		Y int `json:"y"`
	}
	if err := json.Unmarshal(out, &res); err != nil {
		return 0, 0, err
	}
	return res.X, res.Y, nil
}

// clickAt posts a left mouse click at screen coordinates (top-left origin), preferring native CoreGraphics helper.
func clickAt(helper string, x, y int) error {
	if helper != "" {
		if err := exec.Command(helper, "--click", fmt.Sprintf("%d", x), fmt.Sprintf("%d", y)).Run(); err == nil {
			return nil
		}
	}
	jxa := fmt.Sprintf(`ObjC.import("CoreGraphics");
var pt = $.CGPointMake(%d, %d);
var move = $.CGEventCreateMouseEvent(null, $.kCGEventMouseMoved, pt, $.kCGMouseButtonLeft);
var down = $.CGEventCreateMouseEvent(null, $.kCGEventLeftMouseDown, pt, $.kCGMouseButtonLeft);
var up = $.CGEventCreateMouseEvent(null, $.kCGEventLeftMouseUp, pt, $.kCGMouseButtonLeft);
$.CGEventPost($.kCGHIDEventTap, move);
delay(0.05);
$.CGEventPost($.kCGHIDEventTap, down);
delay(0.05);
$.CGEventPost($.kCGHIDEventTap, up);`, x, y)
	if out, err := exec.Command("osascript", "-l", "JavaScript", "-e", jxa).CombinedOutput(); err != nil {
		return fmt.Errorf("点击 (%d,%d) 失败: %v %s", x, y, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func recordWindowRelativePoint(cfg ClientConfig) (ClickPoint, error) {
	helper := findOCRHelper(cfg.ProjectDir)
	mx, my, err := currentMousePos(helper)
	if err != nil {
		return ClickPoint{}, err
	}
	wins, err := listWeChatWindows(helper)
	if err != nil || len(wins) == 0 {
		return ClickPoint{}, errors.New("未检测到微信窗口，请先打开微信主窗口后再录制")
	}
	w := wins[0] // largest WeChat window
	dx := mx - int(w.X)
	dy := my - int(w.Y)
	if dx < 0 || dy < 0 || float64(dx) > w.W || float64(dy) > w.H {
		return ClickPoint{}, fmt.Errorf("当前鼠标 (%d,%d) 不在微信窗口区域 (%.0f,%.0f %.0fx%.0f) 内", mx, my, w.X, w.Y, w.W, w.H)
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

func findWeChatBrowserWindow(wins []WeChatWindow) (WeChatWindow, bool) {
	for _, w := range wins {
		if strings.Contains(w.Title, "微信 (窗口)") || strings.Contains(w.Title, "高等讲堂") || strings.Contains(strings.ToLower(w.Title), "lecture") {
			return w, true
		}
	}
	return WeChatWindow{}, false
}

func findWeChatMainWindow(wins []WeChatWindow) (WeChatWindow, bool) {
	for _, w := range wins {
		if w.Title == "微信" {
			return w, true
		}
	}
	if len(wins) > 0 {
		return wins[0], true
	}
	return WeChatWindow{}, false
}

func raiseWeChatWindow(titleContains string) {
	esc := strings.ReplaceAll(titleContains, `"`, `\"`)
	script := fmt.Sprintf(`
tell application "WeChat" to activate
delay 0.15
tell application "System Events"
	tell process "WeChat"
		repeat with w in windows
			try
				if name of w contains "%s" then
					perform action "AXRaise" of w
					exit repeat
				end if
			end try
		end repeat
	end tell
end tell`, esc)
	_ = exec.Command("osascript", "-e", script).Run()
	time.Sleep(250 * time.Millisecond)
}

func clickOCRHit(helper string, w WeChatWindow, h OCRHit, raiseIfMulti bool) error {
	if raiseIfMulti && w.Title != "" {
		raiseWeChatWindow(w.Title)
	}
	return clickAt(helper, int(w.X+h.CX*w.W), int(w.Y+h.CY*w.H))
}

// clickOCRBest captures window once and clicks the best matching OCR target within [minCY, maxCY].
func clickOCRBest(helper string, w WeChatWindow, keywords []string, minCY, maxCY float64, maxRunes int, raiseIfMulti bool) (string, bool, error) {
	hits, err := captureWindowOCR(helper, w.ID)
	if err != nil {
		return "", false, err
	}
	h, clean, ok := matchOCRHit(hits, keywords, minCY, maxCY, maxRunes)
	if !ok {
		return "", false, nil
	}
	if err := clickOCRHit(helper, w, h, raiseIfMulti); err != nil {
		return "", false, err
	}
	return clean, true, nil
}

// sendWeChatSearch selects the main WeChat window, opens Cmd+F, clears previous query via Cmd+A+Delete,
// pastes keyword, and optionally presses Return to open 搜一搜.
func sendWeChatSearch(keyword string, pressReturn bool) error {
	esc := strings.ReplaceAll(keyword, `"`, `\"`)
	retCmd := ""
	if pressReturn {
		retCmd = "\ndelay 0.55\nkey code 36"
	}
	asSearch := fmt.Sprintf(`
tell application "WeChat" to activate
delay 0.35
set the clipboard to "%s"
tell application "System Events"
	tell process "WeChat"
		try
			repeat with w in windows
				if name of w is "微信" then
					perform action "AXRaise" of w
					exit repeat
				end if
			end repeat
		end try
		delay 0.2
		keystroke "f" using command down
		delay 0.3
		keystroke "a" using command down
		delay 0.1
		key code 51
		delay 0.1
		keystroke "v" using command down%s
	end tell
end tell`, esc, retCmd)
	if out, err := exec.Command("osascript", "-e", asSearch).CombinedOutput(); err != nil {
		return fmt.Errorf("微信搜索失败: %v %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// openFreshWeChatLecture searches SearchKeyword in WeChat 搜一搜 and clicks the link pill via Vision OCR
// to force a fresh WeChat OAuth login (works even when an existing H5 tab's session has completely expired).
func openFreshWeChatLecture(cfg ClientConfig) (string, error) {
	if !accessibilityGranted() {
		return "", errors.New("未授予「辅助功能」权限")
	}
	helper := findOCRHelper(cfg.ProjectDir)
	kw := nonEmpty(cfg.SearchKeyword, "同济大学研究生院")
	if err := sendWeChatSearch(kw, true); err != nil {
		return "", err
	}
	time.Sleep(1600 * time.Millisecond)
	if screenRecordingGranted() {
		if wins, err := listWeChatWindows(helper); err == nil {
			targetWin, hasBW := findWeChatBrowserWindow(wins)
			if !hasBW && len(wins) > 0 {
				targetWin = wins[0]
			}
			if targetWin.ID != 0 {
				if pillTxt, pillOK, ocrErr := clickOCRBest(helper, targetWin, cfg.OCRTargets, 0.16, 0.68, 10, len(wins) > 1); pillOK {
					return fmt.Sprintf("已搜索「%s」并通过 Vision OCR 点击「%s」发起 OAuth 登录", kw, pillTxt), nil
				} else if ocrErr != nil {
					return "", ocrErr
				}
			}
		}
	}
	return "已在微信发起「" + kw + "」搜一搜", nil
}

// refreshWeChatLecture drives macOS WeChat to obtain a fresh OAuth session for 「同济高等讲堂」
// without relying on absolute screen coordinates:
//  1. If Screen Recording + ocr-helper are available:
//     - If 「微信 (窗口)」 already shows 「我的」/「讲座」 tabs of 同济高等讲堂, click 「我的」 (or 「讲座」) to trigger API traffic;
//       otherwise open 搜一搜 for 「同济大学研究生院」 and Vision-OCR click the 「高等讲堂」 link pill for a fresh OAuth login!
//  2. Otherwise replay window-relative ClickPoints mapped to the live WeChat window rect.
//  3. Fallback: Cmd+F search + Return.
func refreshWeChatLecture(cfg ClientConfig) (string, error) {
	if !accessibilityGranted() {
		return "", errors.New("未授予「辅助功能」权限，请先在「电脑操控」页签授权")
	}

	if err := exec.Command("open", "-a", "WeChat").Run(); err != nil {
		return "", fmt.Errorf("唤起微信失败: %w", err)
	}
	time.Sleep(550 * time.Millisecond)

	helper := findOCRHelper(cfg.ProjectDir)
	wins, winErr := listWeChatWindows(helper)

	// Strategy 1: Zero-coordinate macOS Vision OCR flow (reusing single OCR snapshot per unchanged window)
	if winErr == nil && len(wins) > 0 && screenRecordingGranted() {
		multiWin := len(wins) > 1
		// 1a) If WeChat browser window "微信 (窗口)" is open, capture it ONCE and inspect tabs / SPA / 搜一搜 pills
		if bw, ok := findWeChatBrowserWindow(wins); ok {
			if hits, ocrErr := captureWindowOCR(helper, bw.ID); ocrErr == nil {
				if tabHit, tabTxt, tabOK := matchOCRHit(hits, []string{"同济高等讲堂", "高等讲堂"}, 0.01, 0.09, 30); tabOK {
					if clickOCRHit(helper, bw, tabHit, multiWin) == nil {
						time.Sleep(450 * time.Millisecond)
						if subTxt, subOK, _ := clickOCRBest(helper, bw, []string{"我的", "讲座"}, 0.88, 0.99, 6, false); subOK {
							return fmt.Sprintf("已切到「%s」并点击「%s」刷新会话", tabTxt, subTxt), nil
						}
					}
				}
				if subHit, subTxt, subOK := matchOCRHit(hits, []string{"我的"}, 0.88, 0.99, 4); subOK {
					if clickOCRHit(helper, bw, subHit, multiWin) == nil {
						time.Sleep(450 * time.Millisecond)
						_, _, _ = clickOCRBest(helper, bw, []string{"讲座"}, 0.88, 0.99, 4, false)
						return "已在同济高等讲堂 H5 内切换「" + subTxt + "」触发刷新", nil
					}
				}
				if pillHit, pillTxt, pillOK := matchOCRHit(hits, cfg.OCRTargets, 0.18, 0.65, 10); pillOK {
					if clickOCRHit(helper, bw, pillHit, multiWin) == nil {
						return "已在微信窗口通过 Vision OCR 点击「" + pillTxt + "」打开 OAuth", nil
					}
				}
			}
		}

		// 1b) Open WeChat 搜一搜 for SearchKeyword (default "同济大学研究生院") -> Vision OCR clicks the "高等讲堂" link pill
		kw := nonEmpty(cfg.SearchKeyword, "同济大学研究生院")
		if err := sendWeChatSearch(kw, true); err == nil {
			time.Sleep(1600 * time.Millisecond)
			if wins2, err2 := listWeChatWindows(helper); err2 == nil {
				targetWin, hasBW := findWeChatBrowserWindow(wins2)
				if !hasBW && len(wins2) > 0 {
					targetWin = wins2[0]
				}
				if targetWin.ID != 0 {
					if pillTxt, pillOK, _ := clickOCRBest(helper, targetWin, cfg.OCRTargets, 0.16, 0.68, 10, len(wins2) > 1); pillOK {
						return fmt.Sprintf("已搜索「%s」并通过 Vision OCR 点击「%s」发起 OAuth 登录", kw, pillTxt), nil
					}
				}
			}
		}
	}

	// Strategy 2: Replay window-relative ClickPoints mapped to current WeChat main window rect
	if len(cfg.ClickPoints) > 0 && winErr == nil {
		if mw, ok := findWeChatMainWindow(wins); ok {
			for _, pt := range cfg.ClickPoints {
				tx, ty := resolveClickPoint(pt, mw)
				if err := clickAt(helper, tx, ty); err != nil {
					return "", err
				}
				time.Sleep(750 * time.Millisecond)
				if winsNext, errNext := listWeChatWindows(helper); errNext == nil {
					if mw2, ok2 := findWeChatMainWindow(winsNext); ok2 {
						mw = mw2
					}
				}
			}
			return fmt.Sprintf("已按微信窗口相对坐标依次点击 %d 个位置", len(cfg.ClickPoints)), nil
		}
	}

	// Strategy 3: Pure keyboard search fallback
	kw := nonEmpty(cfg.SearchKeyword, "同济大学研究生院")
	if err := sendWeChatSearch(kw, true); err != nil {
		return "", err
	}
	return "已在微信发起「" + kw + "」搜一搜（如未自动点开，请核对「电脑操控」关键词）", nil
}
