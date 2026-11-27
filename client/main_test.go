package main

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/egoist/mygo/ui"
)

func TestClientViewAndTabs(t *testing.T) {
	app := newLectureApp()
	app.connected = true
	valid := true
	app.status.Cookie.Valid = &valid
	app.status.Engine.Running = true
	app.status.Engine.Round = 3
	app.status.Engine.Scanned = 120
	app.status.Cfg.Grab.YuanWatch = true
	app.status.Cfg.Grab.XiaoWatch = false

	tt := ui.NewTester(app.view, 440, 580)
	if !tt.HasText("同济高等讲堂助手") {
		t.Fatalf("missing header, texts=%q", tt.Texts())
	}
	if !tt.HasText("在线·有效") {
		t.Fatalf("missing valid badge, texts=%q", tt.Texts())
	}
	if err := tt.Click("电脑操控"); err != nil {
		t.Fatal(err)
	}
	if app.tab != 1 || !tt.HasText("Vision OCR 零坐标文字定位（推荐 · 移动/缩放窗口不失效）") {
		t.Fatalf("tab 1 not active, tab=%d texts=%q", app.tab, tt.Texts())
	}
	if err := tt.Click("设置"); err != nil {
		t.Fatal(err)
	}
	if app.tab != 2 || !tt.HasText("服务器与自动续期设置") {
		t.Fatalf("tab 2 not active, tab=%d texts=%q", app.tab, tt.Texts())
	}
}

func TestResolveClickPointRelative(t *testing.T) {
	winMoved := WeChatWindow{X: 300, Y: 120, W: 1000, H: 700}
	sidebarPt := ClickPoint{DX: 34, DY: 180, RX: 0.04, RY: 0.30, Anchor: "sidebar"}
	sx, sy := resolveClickPoint(sidebarPt, winMoved)
	if sx != 334 || sy != 330 {
		t.Fatalf("unexpected sidebar coords: %d,%d", sx, sy)
	}
	ratioPt := ClickPoint{RX: 0.50, RY: 0.50, Anchor: "ratio"}
	rx, ry := resolveClickPoint(ratioPt, winMoved)
	if rx != 800 || ry != 470 {
		t.Fatalf("unexpected ratio coords: %d,%d", rx, ry)
	}
}

func TestIdleOptimizationHelpers(t *testing.T) {
	if hasImminentCandidate([]Candidate{{Status: "waiting", Countdown: 600}}, 180) {
		t.Fatal("distant candidate should not trigger fast polling")
	}
	if !hasImminentCandidate([]Candidate{{Status: "waiting", Countdown: 120}}, 180) {
		t.Fatal("imminent candidate should trigger fast polling")
	}
	if !hasImminentCandidate([]Candidate{{Status: "grabbing", Countdown: 500}}, 180) {
		t.Fatal("grabbing candidate should trigger fast polling")
	}

	var s1, s2 ServerStatus
	v := true
	s1.Cookie.Valid = &v
	s2.Cookie.Valid = &v
	s1.Engine.Round = 10
	s2.Engine.Round = 10
	if statusChangedForUI(s1, s2) {
		t.Fatal("identical status should not force UI invalidation")
	}
	s2.Engine.Round = 11
	if !statusChangedForUI(s1, s2) {
		t.Fatal("round change should mark UI dirty")
	}
}

func TestMatchOCRHit(t *testing.T) {
	hits := []OCRHit{
		{Text: "关于近期同济高等讲堂报名通知的长标题公告", CX: 0.5, CY: 0.35},
		{Text: "高等讲堂", CX: 0.4, CY: 0.42},
	}
	h, txt, ok := matchOCRHit(hits, []string{"高等讲堂"}, 0.16, 0.68, 10)
	if !ok || txt != "高等讲堂" || h.CX != 0.4 {
		t.Fatalf("expected exact short pill match, got ok=%v txt=%q hit=%+v", ok, txt, h)
	}
	_, _, okLong := matchOCRHit(hits[:1], []string{"高等讲堂"}, 0.16, 0.68, 10)
	if okLong {
		t.Fatal("expected long headline exceeding maxRunes to be skipped")
	}
}

func TestLocalModeHelpers(t *testing.T) {
	var cfg ClientConfig
	if !ensureLocalSecrets(&cfg) || cfg.APIToken == "" || cfg.LocalPassword == "" {
		t.Fatalf("expected generated local secrets, got %+v", cfg)
	}
	if ensureLocalSecrets(&cfg) {
		t.Fatal("second call should be idempotent")
	}
	if p := parsePortOrDefault("http://127.0.0.1:9900", "8848"); p != "9900" {
		t.Fatalf("unexpected port: %s", p)
	}
	if p := parsePortOrDefault("http://127.0.0.1", "8848"); p != "8848" {
		t.Fatalf("unexpected fallback port: %s", p)
	}
}

func TestLoginAndFetchToken(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "tj_session", Value: "demo-sess", Path: "/"})
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	})
	mux.HandleFunc("/api/account", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("tj_session")
		if err != nil || c.Value != "demo-sess" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"username":"alice","api_token":"tok-alice-999"}`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	cli := newAPIClient()
	tok, err := cli.LoginAndFetchToken(ts.URL, "alice", "secret123")
	if err != nil || tok != "tok-alice-999" {
		t.Fatalf("expected token tok-alice-999, got tok=%q err=%v", tok, err)
	}
}

func TestCapturePortAndSanitizeProxy(t *testing.T) {
	orig := proxySnapshot{
		HTTPEnabled:  true,
		HTTPServer:   "127.0.0.1",
		HTTPPort:     "8080",
		HTTPSEnabled: true,
		HTTPSServer:  "10.0.0.2",
		HTTPSPort:    "7890",
	}
	sanitized := sanitizeOrigProxy(orig, 8080)
	if sanitized.HTTPEnabled {
		t.Fatal("expected leftover self HTTP proxy on 8080 to be cleared")
	}
	if !sanitized.HTTPSEnabled || sanitized.HTTPSServer != "10.0.0.2" {
		t.Fatalf("expected non-self HTTPS proxy to be preserved, got %+v", sanitized)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	busyPort := ln.Addr().(*net.TCPAddr).Port
	picked, err := pickCapturePort(busyPort)
	if err != nil {
		t.Fatalf("expected free fallback port, got err=%v", err)
	}
	if picked == busyPort || picked <= 0 {
		t.Fatalf("expected picked port != %d, got %d (port=%s)", busyPort, picked, strconv.Itoa(picked))
	}
}
