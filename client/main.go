package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"image/color"
	"image/draw"
	"image/png"
	"log"
	"runtime"
	"strings"
	"time"

	"github.com/egoist/mygo"
	"github.com/egoist/mygo/plugins/permissionflow"
	"github.com/egoist/mygo/ui"
)

type lectureApp struct {
	cfg      ClientConfig
	api      *apiClient
	win      *mygo.Window
	tray     *mygo.Tray
	quitting bool

	tab int // 0=总览 1=电脑操控 2=设置

	// Live status
	connected       bool
	lastErr         string
	lastSyncAt      string
	status          ServerStatus
	actionBusy      bool
	actionMsg       string
	captureCancel   context.CancelFunc
	axGranted       bool
	srGranted       bool
	recordingPt     bool
	recordCountdown int

	// Computer use & settings drafts
	draftRunMode   int // 0=remote 1=local
	draftSearchKW  string
	draftOCRList   string
	draftURL       string
	draftToken     string
	draftProj      string
	draftAutoCU    bool
	draftLogin     bool
	settingsMsg    string

	// Notification deduplication & idle power optimization
	initialized        bool
	lastValid          *bool
	lastWonCnt         int
	seenEvents         map[string]struct{}
	autoRegrabInFlight bool
	lastTrayTitle      string
	lastPollAt         time.Time
	uiDirty            bool
	lastTab            int
	wakePollCh         chan struct{}
}

func newLectureApp() *lectureApp {
	cfg := loadConfig()
	rm := 0
	if cfg.RunMode == "local" {
		rm = 1
	}
	return &lectureApp{
		cfg:           cfg,
		api:           newAPIClient(),
		draftRunMode:  rm,
		draftSearchKW: cfg.SearchKeyword,
		draftOCRList:  strings.Join(cfg.OCRTargets, ", "),
		draftURL:      cfg.ServerURL,
		draftToken:    cfg.APIToken,
		draftProj:     cfg.ProjectDir,
		draftAutoCU:   cfg.AutoRegrabOnDead,
		seenEvents:    map[string]struct{}{},
		wakePollCh:    make(chan struct{}, 1),
	}
}

func (a *lectureApp) trayLabel() string {
	if !a.connected {
		return " 离线"
	}
	if a.actionBusy {
		return " 处理中…"
	}
	if a.status.Cookie.Valid == nil || !*a.status.Cookie.Valid {
		return " ⚠️Cookie失效"
	}
	mode := ""
	if a.status.Cfg.Grab.YuanWatch && !a.status.Cfg.Grab.XiaoWatch {
		mode = "院·"
	} else if a.status.Cfg.Grab.XiaoWatch && a.status.Cfg.Grab.YuanWatch {
		mode = "全·"
	}
	if n := len(a.status.Engine.Candidates); n > 0 {
		return fmt.Sprintf(" %s盯%d·得%d", mode, n, len(a.status.Engine.Won))
	}
	return fmt.Sprintf(" %s得%d", mode, len(a.status.Engine.Won))
}

func (a *lectureApp) refreshTrayTitle() {
	if a.tray == nil {
		return
	}
	label := a.trayLabel()
	if label != a.lastTrayTitle {
		a.lastTrayTitle = label
		a.tray.SetTitle(label)
	}
}

// applyUI runs fn on the main thread and only invalidates the Cocoa/Metal canvas
// when the popover is visible and visible state actually changed, keeping background CPU/GPU near zero.
func (a *lectureApp) applyUI(dirty bool, fn func()) {
	if a.win == nil {
		fn()
		return
	}
	mygo.RunOnMain(func() {
		fn()
		if !dirty {
			return
		}
		if a.win.IsVisible() {
			a.uiDirty = false
			a.win.Invalidate()
		} else {
			a.uiDirty = true
		}
	})
}

func (a *lectureApp) triggerPoll() {
	if a.wakePollCh == nil {
		return
	}
	select {
	case a.wakePollCh <- struct{}{}:
	default:
	}
}

func hasImminentCandidate(cands []Candidate, windowSec int) bool {
	for _, cd := range cands {
		if cd.Status == "grabbing" || cd.Countdown <= windowSec {
			return true
		}
	}
	return false
}

func statusChangedForUI(prev ServerStatus, next ServerStatus) bool {
	if prev.Cookie.Present != next.Cookie.Present ||
		prev.Cookie.LastCheck != next.Cookie.LastCheck ||
		(prev.Cookie.Valid == nil) != (next.Cookie.Valid == nil) ||
		(prev.Cookie.Valid != nil && next.Cookie.Valid != nil && *prev.Cookie.Valid != *next.Cookie.Valid) ||
		prev.Cookie.Student != next.Cookie.Student {
		return true
	}
	if prev.Engine.Running != next.Engine.Running ||
		prev.Engine.Round != next.Engine.Round ||
		prev.Engine.Scanned != next.Engine.Scanned ||
		prev.Engine.Offset != next.Engine.Offset ||
		len(prev.Engine.Candidates) != len(next.Engine.Candidates) ||
		len(prev.Engine.Won) != len(next.Engine.Won) ||
		len(prev.Events) != len(next.Events) ||
		prev.Cfg != next.Cfg {
		return true
	}
	for i := range next.Engine.Candidates {
		if prev.Engine.Candidates[i] != next.Engine.Candidates[i] {
			return true
		}
	}
	if len(next.Events) > 0 && len(prev.Events) > 0 && prev.Events[0] != next.Events[0] {
		return true
	}
	return false
}

func (a *lectureApp) pollOnce() time.Duration {
	var winVisible bool
	var curTab int
	var needBootPerms bool
	if a.win != nil {
		mygo.RunOnMain(func() {
			winVisible = a.win.IsVisible()
			curTab = a.tab
			needBootPerms = !a.initialized
		})
	} else {
		needBootPerms = !a.initialized
	}

	var st ServerStatus
	var err error
	if strings.TrimSpace(a.cfg.ServerURL) == "" {
		err = errors.New("尚未配置服务器地址，请在「设置」填写服务器或选「本地单机运行」")
	} else {
		st, err = a.api.FetchStatus(a.cfg)
	}
	now := time.Now()
	nowStr := now.Format("15:04:05")

	// Check TCC permissions only at boot or when the user is viewing the Computer Use tab.
	checkPerms := needBootPerms || (winVisible && curTab == 1)
	var ax, sr bool
	if checkPerms {
		ax = accessibilityGranted()
		sr = screenRecordingGranted()
	}

	var notifyQueue [][3]string // [id, title, body]
	shouldAutoRegrab := false
	nextDelay := 45 * time.Second

	mygo.RunOnMain(func() {
		a.lastPollAt = now
		dirty := false
		if checkPerms {
			if a.axGranted != ax || a.srGranted != sr {
				dirty = true
			}
			a.axGranted = ax
			a.srGranted = sr
		}
		if err != nil {
			if a.connected || a.lastErr != err.Error() {
				dirty = true
			}
			a.connected = false
			a.lastErr = err.Error()
			a.refreshTrayTitle()
			if a.win != nil && dirty {
				if a.win.IsVisible() {
					a.uiDirty = false
					a.win.Invalidate()
				} else {
					a.uiDirty = true
				}
			}
			nextDelay = 30 * time.Second
			return
		}

		if !a.connected || a.lastErr != "" || winVisible || statusChangedForUI(a.status, st) {
			dirty = true
		}
		a.connected = true
		a.lastErr = ""
		a.lastSyncAt = nowStr
		a.status = st

		// Detect transitions and new events for native macOS notifications
		if !a.initialized {
			a.initialized = true
			if st.Cookie.Valid != nil {
				v := *st.Cookie.Valid
				a.lastValid = &v
			}
			a.lastWonCnt = len(st.Engine.Won)
			for _, ev := range st.Events {
				a.seenEvents[ev.Time+"|"+ev.Event+"|"+ev.Text] = struct{}{}
			}
			if st.Cookie.Valid != nil && !*st.Cookie.Valid {
				notifyQueue = append(notifyQueue, [3]string{
					"cookie-init-dead",
					"同济抢讲座 · Cookie 失效",
					"当前服务器 Cookie 无效，点此打开面板一键续期。",
				})
			}
		} else {
			if st.Cookie.Valid != nil {
				curV := *st.Cookie.Valid
				if a.lastValid != nil && *a.lastValid && !curV {
					notifyQueue = append(notifyQueue, [3]string{
						"cookie-dead",
						"⚠️ 同济抢讲座 · Cookie 已过期",
						"登录会话失效，请点击一键续期或打开微信刷新。",
					})
					if a.cfg.AutoRegrabOnDead && !a.actionBusy && !a.autoRegrabInFlight {
						shouldAutoRegrab = true
						a.autoRegrabInFlight = true
					}
				} else if a.lastValid != nil && !*a.lastValid && curV {
					a.autoRegrabInFlight = false
					notifyQueue = append(notifyQueue, [3]string{
						"cookie-alive",
						"✅ 同济抢讲座 · Cookie 已恢复",
						"登录会话校验有效，引擎正常监听中。",
					})
				}
				a.lastValid = &curV
			}
			if len(st.Engine.Won) > a.lastWonCnt {
				diff := len(st.Engine.Won) - a.lastWonCnt
				title := "🎉 抢到新讲座！"
				body := fmt.Sprintf("新增 %d 场已选到讲座，共 %d 场。", diff, len(st.Engine.Won))
				if len(st.Engine.Won) > 0 {
					body = "《" + st.Engine.Won[0].Title + "》 " + st.Engine.Won[0].Ltime
				}
				notifyQueue = append(notifyQueue, [3]string{"won-new", title, body})
			}
			a.lastWonCnt = len(st.Engine.Won)

			if len(a.seenEvents) > 200 {
				kept := make(map[string]struct{}, len(st.Events))
				for _, ev := range st.Events {
					k := ev.Time + "|" + ev.Event + "|" + ev.Text
					if _, ok := a.seenEvents[k]; ok {
						kept[k] = struct{}{}
					}
				}
				a.seenEvents = kept
			}

			for i := len(st.Events) - 1; i >= 0; i-- {
				ev := st.Events[i]
				k := ev.Time + "|" + ev.Event + "|" + ev.Text
				if _, ok := a.seenEvents[k]; ok {
					continue
				}
				a.seenEvents[k] = struct{}{}
				switch ev.Event {
				case "success", "cookie_dead", "grab_fail", "lecture_soon", "new_target":
					notifyQueue = append(notifyQueue, [3]string{
						"ev-" + ev.Event + "-" + ev.Time,
						"同济抢讲座 · " + eventTitle(ev.Event),
						ev.Text,
					})
				}
			}
		}
		a.refreshTrayTitle()
		if a.win != nil && dirty {
			if a.win.IsVisible() {
				a.uiDirty = false
				a.win.Invalidate()
			} else {
				a.uiDirty = true
			}
		}

		// Adaptive polling: fast when popover is visible or grab is imminent, relaxed when idle in background.
		base := max(a.cfg.PollSec, 10)
		switch {
		case a.win != nil && a.win.IsVisible(), a.actionBusy:
			nextDelay = time.Duration(base) * time.Second
		case hasImminentCandidate(st.Engine.Candidates, 180):
			nextDelay = time.Duration(base) * time.Second
		case st.Cookie.Valid == nil || !*st.Cookie.Valid:
			nextDelay = 30 * time.Second
		default:
			nextDelay = time.Duration(max(base*3, 45)) * time.Second
		}
	})

	for _, item := range notifyQueue {
		id, title, body := item[0], item[1], item[2]
		go sendNotification(id, title, body, func() {
			mygo.RunOnMain(a.show)
		})
	}
	if shouldAutoRegrab {
		go a.runCapture(true)
	}
	return nextDelay
}

func eventTitle(ev string) string {
	switch ev {
	case "success":
		return "报名成功"
	case "cookie_dead":
		return "Cookie 失效"
	case "grab_fail":
		return "抢报失败"
	case "lecture_soon":
		return "即将开讲提醒"
	case "new_target":
		return "发现新讲座"
	default:
		return ev
	}
}

func (a *lectureApp) runCapture(automate bool) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	alreadyBusy := false
	a.applyUI(true, func() {
		if a.actionBusy {
			alreadyBusy = true
			return
		}
		a.actionBusy = true
		a.captureCancel = cancel
		a.actionMsg = "准备抓包…"
		a.refreshTrayTitle()
	})
	if alreadyBusy {
		cancel()
		return
	}

	defer cancel()
	err := captureAndUploadCookie(ctx, a.cfg, a.api, automate, func(msg string) {
		a.applyUI(true, func() {
			a.actionMsg = msg
		})
	})

	a.applyUI(true, func() {
		a.actionBusy = false
		a.captureCancel = nil
		a.autoRegrabInFlight = false
		if err != nil {
			a.actionMsg = "❌ " + err.Error()
		} else {
			a.actionMsg = "✅ Cookie 已更新并热加载到服务器"
		}
		a.refreshTrayTitle()
	})
	if err == nil {
		go sendNotification("cookie-updated", "✅ Cookie 已自动更新", "已上传至服务器并恢复监听", nil)
		a.triggerPoll()
	} else if !strings.Contains(err.Error(), "context canceled") {
		go sendNotification("cookie-update-fail", "Cookie 更新未完成", err.Error(), func() {
			mygo.RunOnMain(a.show)
		})
	}
}

func (a *lectureApp) runScan() {
	a.applyUI(true, func() {
		a.actionMsg = "正在通知服务器扫描…"
	})
	n, err := a.api.TriggerScan(a.cfg)
	a.applyUI(true, func() {
		if err != nil {
			a.actionMsg = "❌ 扫描失败: " + err.Error()
		} else {
			a.actionMsg = fmt.Sprintf("✅ 扫描完成，共 %d 场讲座", n)
		}
	})
	a.triggerPoll()
}

func (a *lectureApp) recordMouseAfter3s() {
	if a.recordingPt {
		return
	}
	a.recordingPt = true
	a.recordCountdown = 3
	a.actionMsg = "请保持微信窗口打开并把鼠标移到目标上，3 秒后记录相对位置…"
	go func() {
		for sec := 3; sec >= 1; sec-- {
			s := sec
			a.applyUI(true, func() { a.recordCountdown = s })
			time.Sleep(time.Second)
		}
		pt, err := recordWindowRelativePoint(a.cfg)
		a.applyUI(true, func() {
			a.recordingPt = false
			a.recordCountdown = 0
			if err != nil {
				a.actionMsg = "❌ " + err.Error()
				return
			}
			a.cfg.ClickPoints = append(a.cfg.ClickPoints, pt)
			_ = saveConfig(a.cfg)
			a.actionMsg = fmt.Sprintf("✅ 已记录微信窗口相对位置 (%s: %.0f%%, %.0f%%)", pt.Anchor, pt.RX*100, pt.RY*100)
		})
	}()
}

func (a *lectureApp) view(c *ui.Context) {
	if c.Shortcut(0, ui.KeyEscape) || c.Shortcut(ui.Cmd, ui.KeyW) {
		a.win.Hide()
	}
	c.OnShortcut(ui.Cmd, ui.KeyQ, mygo.App.Quit)
	t := c.Theme()

	ui.Column(c).Fill().Padding(14).Gap(10).Children(func() {
		// Header
		ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
			ui.Text(c, "同济高等讲堂助手").FontSize(17).Bold().Grow(1)
			if a.connected {
				if a.status.Cookie.Valid != nil && *a.status.Cookie.Valid {
					ui.Badge(c, "在线·有效").Background(t.Success).TextColor(t.AccentText)
				} else {
					ui.Badge(c, "Cookie失效").Background(t.Danger).TextColor(t.AccentText)
				}
			} else {
				ui.Badge(c, "未连接").Background(t.Warning).TextColor(t.AccentText)
			}
			if ui.Button(c, "隐藏").Clicked() {
				a.win.Hide()
			}
		})

		ui.Tabs(c, &a.tab, "总览", "电脑操控", "设置")
		if a.tab != a.lastTab {
			a.lastTab = a.tab
			if a.tab == 1 && a.win != nil {
				go a.refreshPermissions()
			}
		}

		ui.Scroll(c).Grow(1).Children(func() {
			switch a.tab {
			case 0:
				a.overviewTab(c)
			case 1:
				a.computerUseTab(c)
			case 2:
				a.settingsTab(c)
			}
		})

		if a.actionMsg != "" {
			ui.Text(c, a.actionMsg).FontSize(12).TextColor(t.TextMuted)
		}

		ui.Divider(c)
		ui.Row(c).AlignItems(ui.Center).Gap(8).Children(func() {
			syncTxt := "同步中…"
			if a.lastSyncAt != "" {
				syncTxt = "同步于 " + a.lastSyncAt
			}
			ui.Text(c, syncTxt).Grow(1).FontSize(11).TextColor(t.TextMuted)
			if ui.Button(c, "打开 WebUI").Clicked() {
				go mygo.Shell.OpenExternal(a.cfg.ServerURL)
			}
			if ui.Button(c, "退出").Clicked() {
				mygo.App.Quit()
			}
		})
	})
}

func (a *lectureApp) overviewTab(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).Gap(10).Children(func() {
		if !a.connected {
			ui.Column(c).Padding(12).Gap(6).Radius(t.Radius).Background(t.Surface).Border(1, t.Border).Children(func() {
				ui.Text(c, "连接服务器失败").Bold().TextColor(t.Danger)
				ui.Text(c, a.lastErr).FontSize(12).TextColor(t.TextMuted)
				ui.Row(c).Gap(8).Children(func() {
					if ui.Button(c, "立即重试").Clicked() {
						a.triggerPoll()
					}
					if ui.Button(c, "前往设置").Clicked() {
						a.tab = 2
					}
				})
			})
			return
		}

		// Work & Cookie status card
		ui.Column(c).Padding(12).Gap(6).Radius(t.Radius).Background(t.Surface).Border(1, t.Border).Children(func() {
			engState := "已停止"
			if a.status.Engine.Running {
				engState = fmt.Sprintf("运行中 · 第 %d 轮 · 扫描 %d 场", a.status.Engine.Round, a.status.Engine.Scanned)
			}
			modeTxt := "全部"
			if a.status.Cfg.Grab.YuanWatch && !a.status.Cfg.Grab.XiaoWatch {
				modeTxt = "仅院级"
			} else if a.status.Cfg.Grab.XiaoWatch && !a.status.Cfg.Grab.YuanWatch {
				modeTxt = "仅校级"
			}
			ui.Text(c, "工作状态: "+engState).FontSize(13).Bold()
			ui.Text(c, fmt.Sprintf("策略: %s (校区: %s) · 偏移 %.3fs · 已选到 %d 场",
				modeTxt, nonEmpty(a.status.Cfg.Grab.YuanCampus, "不限"),
				a.status.Engine.Offset, len(a.status.Engine.Won))).FontSize(12).TextColor(t.TextMuted)

			stu := a.status.Cookie.Student
			stuTxt := "未识别学生信息"
			if stu.Name != "" || stu.StudentID != "" {
				stuTxt = strings.TrimSpace(stu.Name + " " + stu.StudentID + " " + stu.FacultyName)
			}
			ckTxt := "无效/已过期"
			ckCol := t.Danger
			if a.status.Cookie.Valid != nil && *a.status.Cookie.Valid {
				ckTxt = "有效"
				ckCol = t.Success
			}
			ui.Row(c).Gap(6).Children(func() {
				ui.Text(c, "Cookie: "+ckTxt).FontSize(12).Bold().TextColor(ckCol)
				ui.Text(c, "· "+stuTxt).FontSize(12).TextColor(t.TextMuted).Grow(1)
			})
			if a.status.Cookie.LastCheck != "" {
				ui.Text(c, "最后心跳: "+a.status.Cookie.LastCheck).FontSize(11).TextColor(t.TextMuted)
			}
		})

		// Quick actions
		ui.Row(c).Gap(8).Children(func() {
			if ui.PrimaryButton(c, "一键自动续期").Disabled(a.actionBusy).Tooltip("切换代理 + 自动操控微信刷新 + 上传服务器").Clicked() {
				go a.runCapture(true)
			}
			if ui.Button(c, "手动抓 Cookie").Disabled(a.actionBusy).Clicked() {
				go a.runCapture(false)
			}
			if a.actionBusy && a.captureCancel != nil {
				if ui.Button(c, "取消").Clicked() {
					a.captureCancel()
					a.actionMsg = "正在取消抓包并还原代理…"
				}
			} else if ui.Button(c, "立即扫描").Disabled(a.actionBusy).Clicked() {
				go a.runScan()
			}
		})

		// Candidates
		ui.Column(c).Padding(12).Gap(6).Radius(t.Radius).Background(t.Surface).Border(1, t.Border).Children(func() {
			ui.Text(c, fmt.Sprintf("待抢清单 (%d)", len(a.status.Engine.Candidates))).FontSize(13).Bold()
			if len(a.status.Engine.Candidates) == 0 {
				ui.Text(c, "暂无待抢目标，引擎持续监测中").FontSize(12).TextColor(t.TextMuted)
			} else {
				for _, cd := range a.status.Engine.Candidates {
					ui.Row(c.Key("cand-"+cd.Did)).Gap(6).AlignItems(ui.Center).Children(func() {
						ui.Badge(c, cd.Lvl)
						ui.Text(c, truncateRunes(cd.Title, 20)).FontSize(12).Grow(1)
						ui.Text(c, fmt.Sprintf("%s (%ds)", cd.Status, cd.Countdown)).FontSize(11).TextColor(t.TextMuted)
					})
				}
			}
		})

		// Recent won lectures
		if len(a.status.Engine.Won) > 0 {
			ui.Column(c).Padding(12).Gap(5).Radius(t.Radius).Background(t.Surface).Border(1, t.Border).Children(func() {
				ui.Text(c, fmt.Sprintf("已选到讲座 (共 %d 场)", len(a.status.Engine.Won))).FontSize(13).Bold()
				limit := min(4, len(a.status.Engine.Won))
				for i := range limit {
					w := a.status.Engine.Won[i]
					ui.Row(c.Key("won-"+w.Did)).Gap(6).AlignItems(ui.Center).Children(func() {
						ui.Badge(c, w.Lvl)
						ui.Text(c, truncateRunes(w.Title, 18)).FontSize(12).Grow(1)
						ui.Text(c, w.Ltime).FontSize(11).TextColor(t.TextMuted)
					})
				}
			})
		}

		// Recent events
		ui.Column(c).Padding(12).Gap(6).Radius(t.Radius).Background(t.Surface).Border(1, t.Border).Children(func() {
			ui.Text(c, "最近通知事件").FontSize(13).Bold()
			if len(a.status.Events) == 0 {
				ui.Text(c, "暂无事件").FontSize(12).TextColor(t.TextMuted)
			} else {
				limit := min(5, len(a.status.Events))
				for i := range limit {
					ev := a.status.Events[i]
					ui.Text(c, fmt.Sprintf("[%s] %s: %s", ev.Time, eventTitle(ev.Event), truncateRunes(strings.ReplaceAll(ev.Text, "\n", " "), 46))).
						FontSize(11).TextColor(t.TextMuted)
				}
			}
		})
	})
}

func (a *lectureApp) computerUseTab(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).Gap(10).Children(func() {
		ui.Column(c).Padding(12).Gap(8).Radius(t.Radius).Background(t.Surface).Border(1, t.Border).Children(func() {
			if runtime.GOOS == "darwin" {
				ui.Text(c, "macOS 电脑操控权限 (Computer Use)").FontSize(13).Bold()
				axTxt, axCol := "辅助功能: 未授权（无法控制微信窗口和点击）", t.Danger
				if a.axGranted {
					axTxt, axCol = "辅助功能: 已授权 ✅", t.Success
				}
				srTxt, srCol := "屏幕录制: 未授权（仅用Vision零坐标识别文字时需要）", t.Warning
				if a.srGranted {
					srTxt, srCol = "屏幕录制: 已授权 ✅（支持 Vision OCR 零坐标点文字）", t.Success
				}
				ui.Text(c, axTxt).FontSize(12).TextColor(axCol)
				ui.Text(c, srTxt).FontSize(12).TextColor(srCol)
				ui.Row(c).Gap(8).Children(func() {
					if ui.PrimaryButton(c, "授权辅助功能").Disabled(a.axGranted).Clicked() {
						go func() {
							ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
							defer cancel()
							_, _ = guidePermission(ctx, permissionflow.Accessibility)
							ax := accessibilityGranted()
							a.applyUI(true, func() { a.axGranted = ax })
						}()
					}
					if ui.Button(c, "授权屏幕录制").Disabled(a.srGranted).Clicked() {
						go func() {
							ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
							defer cancel()
							_, _ = guidePermission(ctx, permissionflow.ScreenRecording)
							sr := screenRecordingGranted()
							a.applyUI(true, func() { a.srGranted = sr })
						}()
					}
					if ui.Button(c, "测试操控刷新").Disabled(a.actionBusy).Clicked() {
						go func() {
							note, err := refreshWeChatLecture(a.cfg)
							a.applyUI(true, func() {
								if err != nil {
									a.actionMsg = "❌ " + err.Error()
								} else {
									a.actionMsg = "✅ " + note
								}
							})
						}()
					}
				})
			} else {
				ui.Text(c, "电脑操控微信刷新 (Computer Use)").FontSize(13).Bold()
				ui.Text(c, "当前系统无需额外隐私授权，支持自动激活微信搜一搜及下方「窗口相对位置」自动点击。").
					FontSize(12).TextColor(t.TextMuted)
				if ui.Button(c, "测试操控刷新").Disabled(a.actionBusy).Clicked() {
					go func() {
						note, err := refreshWeChatLecture(a.cfg)
						a.applyUI(true, func() {
							if err != nil {
								a.actionMsg = "❌ " + err.Error()
							} else {
								a.actionMsg = "✅ " + note
							}
						})
					}()
				}
			}
		})

		ui.Column(c).Padding(12).Gap(8).Radius(t.Radius).Background(t.Surface).Border(1, t.Border).Children(func() {
			ui.Text(c, "Vision OCR 零坐标文字定位（推荐 · 移动/缩放窗口不失效）").FontSize(13).Bold()
			ui.Text(c, "优先识别微信窗口里的目标文字并自动点击，不依赖固定坐标。").FontSize(11).TextColor(t.TextMuted)
			ui.Text(c, "搜索关键词 (Cmd+F)").FontSize(11).TextColor(t.TextMuted)
			ui.TextInput(c.Key("cu-kw"), &a.draftSearchKW).Placeholder("同济高等讲堂")
			ui.Text(c, "依次识别并点击的文字（逗号分隔）").FontSize(11).TextColor(t.TextMuted)
			ui.TextInput(c.Key("cu-ocr"), &a.draftOCRList).Placeholder("同济高等讲堂, 高等讲堂, 讲座报名")
			if ui.Button(c, "保存文字定位配置").Clicked() {
				a.cfg.SearchKeyword = nonEmpty(a.draftSearchKW, "同济高等讲堂")
				var list []string
				for _, p := range strings.Split(strings.ReplaceAll(a.draftOCRList, "，", ","), ",") {
					if s := strings.TrimSpace(p); s != "" {
						list = append(list, s)
					}
				}
				if len(list) == 0 {
					list = []string{"同济高等讲堂", "高等讲堂", "讲座报名"}
				}
				a.cfg.OCRTargets = list
				if err := saveConfig(a.cfg); err != nil {
					a.actionMsg = "❌ 保存失败: " + err.Error()
				} else {
					a.actionMsg = "✅ 已保存 Vision OCR 文字目标"
				}
			}
		})

		ui.Column(c).Padding(12).Gap(8).Radius(t.Radius).Background(t.Surface).Border(1, t.Border).Children(func() {
			ui.Text(c, "兜底：微信窗口相对位置录制（纯图标入口时使用）").FontSize(13).Bold()
			ui.Text(c, "按微信窗口比例与侧栏锚点记录，拖动或缩放微信窗口依然有效。").
				FontSize(11).TextColor(t.TextMuted)

			recLabel := "3 秒后记录微信相对位置"
			if a.recordingPt {
				recLabel = fmt.Sprintf("倒计时 %d 秒…", a.recordCountdown)
			}
			ui.Row(c).Gap(8).Children(func() {
				if ui.Button(c, recLabel).Disabled(a.recordingPt).Clicked() {
					a.recordMouseAfter3s()
				}
				if ui.Button(c, "清空位置").Disabled(len(a.cfg.ClickPoints) == 0).Clicked() {
					a.cfg.ClickPoints = nil
					_ = saveConfig(a.cfg)
					a.actionMsg = "已清空预设相对位置"
				}
			})

			for i, pt := range a.cfg.ClickPoints {
				idx := i
				ui.Row(c.Key(fmt.Sprintf("pt-%d", i))).AlignItems(ui.Center).Gap(8).Children(func() {
					ui.Text(c, fmt.Sprintf("#%d  [%s] %.0f%%, %.0f%%  %s", idx+1, pt.Anchor, pt.RX*100, pt.RY*100, pt.Note)).FontSize(12).Grow(1)
					if ui.Button(c, "删除").Clicked() {
						a.cfg.ClickPoints = append(a.cfg.ClickPoints[:idx], a.cfg.ClickPoints[idx+1:]...)
						_ = saveConfig(a.cfg)
					}
				})
			}
		})
	})
}

func (a *lectureApp) settingsTab(c *ui.Context) {
	t := c.Theme()
	ui.Column(c).Gap(10).Padding(12).Radius(t.Radius).Background(t.Surface).Border(1, t.Border).Children(func() {
		ui.Text(c, "服务器与自动续期设置").FontSize(13).Bold()
		ui.Tabs(c, &a.draftRunMode, "连远程服务器", "本地单机运行")

		if a.draftRunMode == 1 {
			if strings.TrimSpace(a.draftURL) == "" {
				a.draftURL = "http://127.0.0.1:8848"
			}
			ui.Text(c, "本机运行免部署：助手会自动在后台启动本地抢讲座引擎，数据保存在本机。").FontSize(11).TextColor(t.TextMuted)
			ui.Text(c, "本地服务状态: "+localSrv.statusText()).FontSize(12)
			if a.cfg.LocalPassword != "" {
				ui.Text(c, "本地 WebUI 默认账号: admin / 密码: "+a.cfg.LocalPassword).FontSize(11).TextColor(t.TextMuted)
			}
			ui.Text(c, "本地监听地址").FontSize(11).TextColor(t.TextMuted)
			ui.TextInput(c.Key("cfg-url-local"), &a.draftURL).Placeholder("http://127.0.0.1:8848")
		} else {
			ui.Text(c, "服务器地址").FontSize(11).TextColor(t.TextMuted)
			ui.TextInput(c.Key("cfg-url"), &a.draftURL).Placeholder("http://服务器IP:8848")

			ui.Text(c, "API Token (tj_config.json auth.api_token)").FontSize(11).TextColor(t.TextMuted)
			ui.TextInput(c.Key("cfg-tok"), &a.draftToken).Password().Placeholder("输入专属 api_token")
		}

		ui.Text(c, "项目目录（可选，留空使用内置插件）").FontSize(11).TextColor(t.TextMuted)
		ui.TextInput(c.Key("cfg-proj"), &a.draftProj).Placeholder("独立安装包可留空")

		ui.Row(c).AlignItems(ui.Center).Gap(10).Children(func() {
			ui.Text(c, "Cookie 失效时自动尝试电脑操控续期").FontSize(12).Grow(1)
			ui.Switch(c, &a.draftAutoCU).Label("自动续期")
		})
		ui.Row(c).AlignItems(ui.Center).Gap(10).Children(func() {
			ui.Text(c, "登录系统时自动启动助手（打包安装后生效）").FontSize(12).Grow(1)
			if ui.Switch(c, &a.draftLogin).Label("开机自启").Changed() {
				if err := mygo.App.SetOpenAtLogin(a.draftLogin); err != nil {
					a.settingsMsg = "⚠️ 设置开机自启失败: " + err.Error()
					a.draftLogin = mygo.App.OpenAtLogin()
				}
			}
		})

		ui.Row(c).Gap(8).Children(func() {
			if ui.PrimaryButton(c, "保存设置").Clicked() {
				if a.draftRunMode == 1 {
					a.cfg.RunMode = "local"
					a.cfg.ServerURL = nonEmpty(strings.TrimRight(strings.TrimSpace(a.draftURL), "/"), "http://127.0.0.1:8848")
					a.cfg.APIToken = strings.TrimSpace(a.draftToken)
					ensureLocalSecrets(&a.cfg)
					a.draftURL = a.cfg.ServerURL
					a.draftToken = a.cfg.APIToken
				} else {
					a.cfg.RunMode = "remote"
					a.cfg.ServerURL = strings.TrimRight(strings.TrimSpace(a.draftURL), "/")
					a.cfg.APIToken = strings.TrimSpace(a.draftToken)
				}
				a.cfg.ProjectDir = strings.TrimSpace(a.draftProj)
				a.cfg.AutoRegrabOnDead = a.draftAutoCU
				if err := saveConfig(a.cfg); err != nil {
					a.settingsMsg = "❌ 保存失败: " + err.Error()
				} else {
					if a.cfg.RunMode == "local" {
						a.settingsMsg = "正在启动本地服务…"
						cfgSnap := a.cfg
						go func() {
							err := localSrv.start(cfgSnap)
							a.applyUI(true, func() {
								if err != nil {
									a.settingsMsg = "⚠️ 启动本地服务失败: " + err.Error()
								} else {
									a.settingsMsg = "✅ 设置已保存，本地服务运行中"
								}
							})
							a.triggerPoll()
						}()
					} else {
						localSrv.stop()
						a.settingsMsg = "✅ 设置已保存"
						a.triggerPoll()
					}
				}
			}
			if ui.Button(c, "测试通知").Clicked() {
				go sendNotification("test-notify", "同济抢讲座助手", "桌面通知工作正常 ✅", nil)
			}
		})
		if a.settingsMsg != "" {
			ui.Text(c, a.settingsMsg).FontSize(12).TextColor(t.TextMuted)
		}
	})
}

func (a *lectureApp) refreshPermissions() {
	ax := accessibilityGranted()
	sr := screenRecordingGranted()
	a.applyUI(ax != a.axGranted || sr != a.srGranted, func() {
		a.axGranted = ax
		a.srGranted = sr
	})
}

func (a *lectureApp) show() {
	if a.uiDirty {
		a.uiDirty = false
		a.win.Invalidate()
	}
	if a.tab == 1 {
		go a.refreshPermissions()
	}
	if time.Since(a.lastPollAt) > 3*time.Second {
		a.triggerPoll()
	}
	anchor := a.tray.Bounds()
	if anchor.Width == 0 || anchor.Height == 0 {
		a.win.Center()
	} else {
		area := mygo.Screen.DisplayNearestPoint(mygo.Point{
			X: anchor.X + anchor.Width/2,
			Y: anchor.Y + anchor.Height/2,
		}).WorkArea
		b := a.win.Bounds()
		x := anchor.X + (anchor.Width-b.Width)/2
		y := anchor.Y + anchor.Height + 6
		if y+b.Height > area.Y+area.Height {
			y = anchor.Y - b.Height - 6
		}
		x = max(area.X, min(x, area.X+max(0, area.Width-b.Width)))
		y = max(area.Y, min(y, area.Y+max(0, area.Height-b.Height)))
		a.win.SetPosition(x, y)
	}
	a.win.Show()
}

func (a *lectureApp) toggle() {
	if a.win.IsVisible() {
		a.win.Hide()
	} else {
		a.show()
	}
}

func (a *lectureApp) ready() {
	a.draftLogin = mygo.App.OpenAtLogin()
	var err error
	a.tray, err = mygo.NewTray(mygo.TrayOptions{
		Icon:           trayIconPNG(),
		IconIsTemplate: true,
		Title:          " 连接中…",
		ToolTip:        "同济高等讲堂助手 — 点击打开面板",
	})
	if err != nil {
		log.Fatal("tray: ", err)
	}
	a.win = mygo.NewWindow(mygo.WindowOptions{
		Title:             "同济高等讲堂助手",
		Width:             440,
		Height:            580,
		Hidden:            true,
		Frameless:         true,
		DisableResize:     true,
		DisableMinimize:   true,
		DisableMaximize:   true,
		DisableFullScreen: true,
		AlwaysOnTop:       true,
		SkipTaskbar:       true,
		Content:           ui.View(a.view),
	})
	a.win.OnBlur(a.win.Hide)
	a.win.OnClose(func(e *mygo.CloseEvent) {
		if !a.quitting {
			e.PreventDefault()
			a.win.Hide()
		}
	})

	menu := mygo.NewMenu([]*mygo.MenuItem{
		{Label: "打开状态面板", Click: func(*mygo.MenuItem, *mygo.Window) { a.show() }},
		{Label: "一键自动续期 Cookie", Click: func(*mygo.MenuItem, *mygo.Window) { go a.runCapture(true) }},
		{Label: "立即扫描讲座", Click: func(*mygo.MenuItem, *mygo.Window) { go a.runScan() }},
		{Label: "在浏览器打开 WebUI", Click: func(*mygo.MenuItem, *mygo.Window) { go mygo.Shell.OpenExternal(a.cfg.ServerURL) }},
		mygo.Separator(),
		{Role: mygo.RoleQuit},
	})
	a.tray.OnClick(a.toggle)
	a.tray.OnRightClick(func() {
		a.win.Hide()
		a.tray.SetMenu(menu)
		defer a.tray.SetMenu(nil)
		a.tray.PopUpMenu()
	})

	mygo.App.OnWillQuit(func(*mygo.QuitEvent) {
		localSrv.stop()
		a.tray.Destroy()
	})

	if a.cfg.RunMode == "local" {
		_ = saveConfig(a.cfg)
		go func() {
			_ = localSrv.start(a.cfg)
			a.triggerPoll()
		}()
	}

	go func() {
		for {
			delay := a.pollOnce()
			timer := time.NewTimer(delay)
			select {
			case <-timer.C:
			case <-a.wakePollCh:
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
			}
		}
	}()
}

// trayIconPNG draws a minimalist 32x32 graduation-cap / lecture icon as a macOS template image.
func trayIconPNG() []byte {
	img := image.NewNRGBA(image.Rect(0, 0, 32, 32))
	ink := color.NRGBA{A: 255}
	for _, r := range []image.Rectangle{
		image.Rect(4, 11, 28, 14),
		image.Rect(8, 8, 24, 11),
		image.Rect(9, 15, 23, 24),
		image.Rect(25, 14, 27, 23),
	} {
		draw.Draw(img, r, image.NewUniform(ink), image.Point{}, draw.Src)
	}
	var b bytes.Buffer
	_ = png.Encode(&b, img)
	return b.Bytes()
}

func nonEmpty(s, fallback string) string {
	if strings.TrimSpace(s) == "" {
		return fallback
	}
	return s
}

func truncateRunes(s string, maxR int) string {
	r := []rune(s)
	if len(r) <= maxR {
		return s
	}
	return string(r[:maxR]) + "…"
}

func main() {
	app := newLectureApp()
	mygo.App.SetName("同济抢讲座助手")
	mygo.App.SetActivationPolicy(mygo.ActivationPolicyAccessory)
	mygo.App.OnBeforeQuit(func(*mygo.QuitEvent) { app.quitting = true })
	mygo.App.WhenReady(app.ready)
	if err := mygo.App.Run(); err != nil {
		log.Fatal(err)
	}
}
