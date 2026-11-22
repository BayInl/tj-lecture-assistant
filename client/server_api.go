package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ServerStatus mirrors the JSON payload of GET /api/status.
type ServerStatus struct {
	Now  string `json:"now"`
	User struct {
		Username string `json:"username"`
		Role     string `json:"role"`
	} `json:"user"`
	Cookie struct {
		Present    bool   `json:"present"`
		SessionID  string `json:"session_id"`
		CapturedAt string `json:"captured_at"`
		Valid      *bool  `json:"valid"`
		LastCheck  string `json:"last_check"`
		AgeSec     *int   `json:"age_sec"`
		Student    struct {
			Name        string `json:"Name"`
			StudentID   string `json:"StudentId"`
			FacultyName string `json:"FacultyNmae"`
		} `json:"student"`
	} `json:"cookie"`
	Engine struct {
		Running    bool          `json:"running"`
		Round      int           `json:"round"`
		LastScan   string        `json:"last_scan"`
		Offset     float64       `json:"offset"`
		Scanned    int           `json:"scanned"`
		Fired      []string      `json:"fired"`
		Candidates []Candidate   `json:"candidates"`
		Won        []WonLecture  `json:"won"`
	} `json:"engine"`
	Events []ServerEvent `json:"events"`
	Cfg    struct {
		Grab struct {
			XiaoWatch bool   `json:"xiao_watch"`
			XiaoAuto  bool   `json:"xiao_auto"`
			YuanWatch bool   `json:"yuan_watch"`
			YuanAuto  bool   `json:"yuan_auto"`
			YuanCampus string `json:"yuan_campus"`
		} `json:"grab"`
	} `json:"cfg"`
}

// Candidate represents an active target in the waiting/grabbing list.
type Candidate struct {
	Did       string `json:"did"`
	Title     string `json:"title"`
	Lvl       string `json:"lvl"`
	Tsu       string `json:"tsu"`
	Ltime     string `json:"ltime"`
	Auto      bool   `json:"auto"`
	Manual    bool   `json:"manual"`
	Status    string `json:"status"`
	Countdown int    `json:"countdown"`
}

// WonLecture represents a successfully booked lecture.
type WonLecture struct {
	Did   string `json:"did"`
	Title string `json:"title"`
	Lvl   string `json:"lvl"`
	Ltime string `json:"ltime"`
	WonAt string `json:"won_at"`
}

// ServerEvent represents a push event recorded by the server.
type ServerEvent struct {
	Time  string `json:"t"`
	Event string `json:"event"`
	Text  string `json:"text"`
}

type apiClient struct {
	http *http.Client
}

func newAPIClient() *apiClient {
	return &apiClient{
		http: &http.Client{
			Timeout: 8 * time.Second,
			Transport: &http.Transport{
				MaxIdleConns:        4,
				MaxIdleConnsPerHost: 2,
				IdleConnTimeout:     60 * time.Second,
			},
		},
	}
}

func (c *apiClient) doJSON(cfg ClientConfig, method, path string, body any, out any) error {
	url := strings.TrimRight(cfg.ServerURL, "/") + path
	var rdr io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		rdr = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, url, rdr)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if cfg.APIToken != "" {
		req.Header.Set("X-API-Token", cfg.APIToken)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode == 401 {
		return fmt.Errorf("鉴权失败(401): 请检查 API Token")
	}
	if resp.StatusCode >= 400 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	if out != nil {
		return json.Unmarshal(raw, out)
	}
	return nil
}

func (c *apiClient) FetchStatus(cfg ClientConfig) (ServerStatus, error) {
	var st ServerStatus
	err := c.doJSON(cfg, http.MethodGet, "/api/status", nil, &st)
	return st, err
}

func (c *apiClient) TriggerScan(cfg ClientConfig) (int, error) {
	var res struct {
		OK    bool   `json:"ok"`
		Count int    `json:"count"`
		Msg   string `json:"msg"`
	}
	if err := c.doJSON(cfg, http.MethodPost, "/api/scan", map[string]any{}, &res); err != nil {
		return 0, err
	}
	if !res.OK {
		return 0, fmt.Errorf("%s", res.Msg)
	}
	return res.Count, nil
}

func (c *apiClient) UploadCookie(cfg ClientConfig, tok TokenPayload) error {
	body := map[string]any{
		"cookie":         tok.Cookie,
		"session_id":     tok.SessionID,
		"weixin_code_id": tok.WeixinCodeID,
		"captured_at":    tok.CapturedAt,
		"student":        tok.Student,
		"source":         "mygo-client",
	}
	var res struct {
		OK    bool `json:"ok"`
		Valid bool `json:"valid"`
	}
	if err := c.doJSON(cfg, http.MethodPost, "/api/cookie", body, &res); err != nil {
		return err
	}
	if !res.OK || !res.Valid {
		return fmt.Errorf("服务器校验 Cookie 未通过")
	}
	return nil
}
