package main

import "strings"

// WeChatWindow describes an on-screen WeChat window rectangle.
type WeChatWindow struct {
	ID    int     `json:"id"`
	Title string  `json:"title"`
	X     float64 `json:"x"`
	Y     float64 `json:"y"`
	W     float64 `json:"w"`
	H     float64 `json:"h"`
	Area  float64 `json:"area"`
}

// OCRHit describes a recognized line of text and its normalized center (top-left origin, 0..1).
type OCRHit struct {
	Text string  `json:"text"`
	CX   float64 `json:"cx"`
	CY   float64 `json:"cy"`
	W    float64 `json:"w"`
	H    float64 `json:"h"`
}

func resolveClickPoint(pt ClickPoint, w WeChatWindow) (int, int) {
	if pt.Anchor == "sidebar" {
		return int(w.X) + pt.DX, int(w.Y + pt.RY*w.H)
	}
	return int(w.X + pt.RX*w.W), int(w.Y + pt.RY*w.H)
}

// matchOCRHit finds the best OCR hit within [minCY, maxCY] preferring exact/short matches (e.g. pill buttons like "高等讲堂").
func matchOCRHit(hits []OCRHit, keywords []string, minCY, maxCY float64, maxRunes int) (OCRHit, string, bool) {
	for _, kw := range keywords {
		kw = strings.TrimSpace(kw)
		if kw == "" {
			continue
		}
		kwLow := strings.ToLower(kw)
		// Pass 1: exact match
		for _, h := range hits {
			if h.CY < minCY || h.CY > maxCY {
				continue
			}
			clean := strings.TrimSpace(h.Text)
			if strings.EqualFold(clean, kw) {
				return h, clean, true
			}
		}
		// Pass 2: short substring match (avoid matching long article headlines)
		for _, h := range hits {
			if h.CY < minCY || h.CY > maxCY {
				continue
			}
			clean := strings.TrimSpace(h.Text)
			if maxRunes > 0 && len([]rune(clean)) > maxRunes {
				continue
			}
			if strings.Contains(strings.ToLower(clean), kwLow) {
				return h, clean, true
			}
		}
	}
	return OCRHit{}, "", false
}
