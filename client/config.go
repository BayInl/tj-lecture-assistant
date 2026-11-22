package main

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// ClickPoint records a position relative to the WeChat main window so moving or resizing WeChat keeps clicks accurate.
type ClickPoint struct {
	RX     float64 `json:"rx"`
	RY     float64 `json:"ry"`
	DX     int     `json:"dx"`
	DY     int     `json:"dy"`
	Anchor string  `json:"anchor"` // "sidebar" | "ratio"
	Note   string  `json:"note"`
}

// ClientConfig stores local client preferences.
type ClientConfig struct {
	RunMode          string       `json:"run_mode"` // "remote" | "local"
	ServerURL        string       `json:"server_url"`
	APIToken         string       `json:"api_token"`
	LocalPassword    string       `json:"local_password,omitempty"`
	ProjectDir       string       `json:"project_dir"`
	PollSec          int          `json:"poll_sec"`
	ProxyPort        int          `json:"proxy_port"`
	NetworkService   string       `json:"network_service"`
	AutoRegrabOnDead bool         `json:"auto_regrab_on_dead"`
	SearchKeyword    string       `json:"search_keyword"`
	OCRTargets       []string     `json:"ocr_targets"`
	ClickPoints      []ClickPoint `json:"click_points"`
}

func configDir() string {
	if runtime.GOOS == "windows" {
		if dir, err := os.UserConfigDir(); err == nil && dir != "" {
			return filepath.Join(dir, "tj-lecture-client")
		}
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".config", "tj-lecture-client")
}

func configPath() string {
	return filepath.Join(configDir(), "config.json")
}

func detectProjectDir() string {
	candidates := []string{}
	if wd, err := os.Getwd(); err == nil {
		candidates = append(candidates, wd, filepath.Dir(wd))
	}
	if exe, err := os.Executable(); err == nil {
		dir := filepath.Dir(exe)
		for range 5 {
			candidates = append(candidates, dir)
			dir = filepath.Dir(dir)
		}
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, "Desktop", "tj_lecture_full"))
	}
	for _, c := range candidates {
		if _, err := os.Stat(filepath.Join(c, "cookie-mac-linux", "token_sniffer.py")); err == nil {
			return c
		}
	}
	return ""
}

func readTokenBootstrap(projDir string) string {
	if projDir == "" {
		return ""
	}
	b, err := os.ReadFile(filepath.Join(projDir, "cookie-mac-linux", ".api_token"))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func defaultConfig() ClientConfig {
	proj := detectProjectDir()
	bootTok := readTokenBootstrap(proj)
	cfg := ClientConfig{
		RunMode:        "remote",
		ProjectDir:     proj,
		PollSec:        15,
		ProxyPort:      8080,
		NetworkService: "Wi-Fi",
		SearchKeyword:  "同济大学研究生院",
		OCRTargets:     []string{"高等讲堂", "同济高等讲堂", "讲座报名"},
	}
	if bootTok != "" {
		cfg.ServerURL = strings.TrimSpace(os.Getenv("TJ_SERVER_URL"))
		if cfg.ServerURL == "" {
			cfg.ServerURL = "http://127.0.0.1:8848"
		}
		cfg.APIToken = bootTok
		return cfg
	}
	if hasBundledLocalServer() {
		cfg.RunMode = "local"
		cfg.ServerURL = "http://127.0.0.1:8848"
		cfg.APIToken = randomHex(16)
		cfg.LocalPassword = randomHex(6)
	}
	return cfg
}

func loadConfig() ClientConfig {
	cfg := defaultConfig()
	b, err := os.ReadFile(configPath())
	if err == nil {
		_ = json.Unmarshal(b, &cfg)
	}
	if cfg.RunMode != "local" && cfg.RunMode != "remote" {
		cfg.RunMode = "remote"
	}
	if cfg.RunMode == "local" && strings.TrimSpace(cfg.ServerURL) == "" {
		cfg.ServerURL = "http://127.0.0.1:8848"
	}
	cfg.ServerURL = strings.TrimRight(strings.TrimSpace(cfg.ServerURL), "/")
	if cfg.ProjectDir == "" {
		cfg.ProjectDir = detectProjectDir()
	}
	if cfg.APIToken == "" && cfg.RunMode == "remote" {
		cfg.APIToken = readTokenBootstrap(cfg.ProjectDir)
	}
	if cfg.RunMode == "local" {
		ensureLocalSecrets(&cfg)
	}
	if cfg.PollSec < 5 {
		cfg.PollSec = 15
	}
	if cfg.ProxyPort <= 0 {
		cfg.ProxyPort = 8080
	}
	if cfg.NetworkService == "" {
		cfg.NetworkService = "Wi-Fi"
	}
	if strings.TrimSpace(cfg.SearchKeyword) == "" {
		cfg.SearchKeyword = "同济大学研究生院"
	}
	if len(cfg.OCRTargets) == 0 {
		cfg.OCRTargets = []string{"高等讲堂", "同济高等讲堂", "讲座报名"}
	}
	return cfg
}

func ensureLocalSecrets(cfg *ClientConfig) bool {
	changed := false
	if strings.TrimSpace(cfg.APIToken) == "" {
		cfg.APIToken = randomHex(16)
		changed = true
	}
	if strings.TrimSpace(cfg.LocalPassword) == "" {
		cfg.LocalPassword = randomHex(6)
		changed = true
	}
	return changed
}

func saveConfig(cfg ClientConfig) error {
	p := configPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	tmp := p + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, p)
}
