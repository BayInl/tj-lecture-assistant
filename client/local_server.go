package main

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"
)

type localServerTarget struct {
	bin  string
	args []string
	dir  string
}

type localServerMgr struct {
	mu      sync.Mutex
	cmd     *exec.Cmd
	running bool
	lastErr string
}

var localSrv localServerMgr

func findBundledServerBinary() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	exeDir := filepath.Dir(exe)
	names := []string{"tj-server"}
	if runtime.GOOS == "windows" {
		names = []string{"tj-server.exe"}
	}
	var cands []string
	for _, nm := range names {
		cands = append(cands,
			filepath.Join(exeDir, nm),
			filepath.Join(exeDir, "server", nm),
			filepath.Join(exeDir, "tj-server", nm),
			filepath.Join(exeDir, "..", "Resources", nm),
		)
	}
	for _, p := range cands {
		if info, err := os.Stat(p); err == nil && !info.IsDir() {
			return p
		}
	}
	return ""
}

func hasBundledLocalServer() bool {
	return findBundledServerBinary() != ""
}

func findLocalServerTarget(projDir string) *localServerTarget {
	if bin := findBundledServerBinary(); bin != "" {
		return &localServerTarget{bin: bin, dir: filepath.Dir(bin)}
	}
	if projDir != "" {
		srvDir := filepath.Join(projDir, "server")
		appPy := filepath.Join(srvDir, "server_app.py")
		if _, err := os.Stat(appPy); err == nil {
			py := filepath.Join(srvDir, "venv", "bin", "python")
			if runtime.GOOS == "windows" {
				py = filepath.Join(srvDir, "venv", "Scripts", "python.exe")
			}
			if _, err := os.Stat(py); err != nil {
				if p, err2 := exec.LookPath("python3"); err2 == nil {
					py = p
				} else if p, err2 := exec.LookPath("python"); err2 == nil {
					py = p
				} else {
					py = ""
				}
			}
			if py != "" {
				return &localServerTarget{bin: py, args: []string{appPy}, dir: srvDir}
			}
		}
	}
	return nil
}

func parsePortOrDefault(rawURL string, def string) string {
	u, err := url.Parse(rawURL)
	if err == nil && u.Port() != "" {
		return u.Port()
	}
	return def
}

func isLoopbackListening(port string) bool {
	c, err := net.DialTimeout("tcp", net.JoinHostPort("127.0.0.1", port), 150*time.Millisecond)
	if err != nil {
		return false
	}
	_ = c.Close()
	return true
}

func (m *localServerMgr) start(cfg ClientConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.running && m.cmd != nil && m.cmd.Process != nil {
		return nil
	}
	port := parsePortOrDefault(cfg.ServerURL, "8848")
	if isLoopbackListening(port) {
		m.lastErr = ""
		return nil
	}

	tgt := findLocalServerTarget(cfg.ProjectDir)
	if tgt == nil {
		m.lastErr = "未找到本地服务程序 (tj-server / server_app.py)"
		return fmt.Errorf("%s", m.lastErr)
	}

	dataDir := filepath.Join(configDir(), "server-data")
	_ = os.MkdirAll(dataDir, 0o700)

	cmd := exec.Command(tgt.bin, tgt.args...)
	cmd.Dir = tgt.dir
	configureBackgroundCmd(cmd)
	cmd.Env = append(os.Environ(),
		"PYTHONUNBUFFERED=1",
		"PYTHONIOENCODING=utf-8",
		"TJ_DATA_DIR="+dataDir,
		"TJ_HOST=127.0.0.1",
		"TJ_PORT="+port,
		"TJ_BOOTSTRAP_API_TOKEN="+cfg.APIToken,
		"TJ_BOOTSTRAP_USER=admin",
		"TJ_BOOTSTRAP_PASSWORD="+cfg.LocalPassword,
	)
	if logF, err := os.OpenFile(filepath.Join(dataDir, "server.log"), os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600); err == nil {
		cmd.Stdout = logF
		cmd.Stderr = logF
	}
	if err := cmd.Start(); err != nil {
		m.lastErr = err.Error()
		return err
	}
	m.cmd = cmd
	m.running = true
	m.lastErr = ""

	go func(c *exec.Cmd) {
		_ = c.Wait()
		m.mu.Lock()
		if m.cmd == c {
			m.running = false
			m.cmd = nil
		}
		m.mu.Unlock()
	}(cmd)

	deadline := time.Now().Add(4 * time.Second)
	for time.Now().Before(deadline) {
		if isLoopbackListening(port) {
			return nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	return nil
}

func (m *localServerMgr) stop() {
	m.mu.Lock()
	cmd := m.cmd
	m.mu.Unlock()
	if cmd == nil || cmd.Process == nil {
		return
	}
	done := make(chan error, 1)
	terminateProcess(cmd, done)
}

func (m *localServerMgr) statusText() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.running {
		return "运行中（本机托管）"
	}
	if m.lastErr != "" {
		return "未启动: " + m.lastErr
	}
	return "未运行"
}
