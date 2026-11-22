//go:build darwin

package main

import (
	"fmt"
	"os/exec"
	"strings"
)

func fallbackNotify(title, body string) {
	esc := func(s string) string {
		s = strings.ReplaceAll(s, `\`, `\\`)
		s = strings.ReplaceAll(s, `"`, `\"`)
		s = strings.ReplaceAll(s, "\n", " ")
		if len([]rune(s)) > 200 {
			s = string([]rune(s)[:200]) + "…"
		}
		return s
	}
	script := fmt.Sprintf(`display notification "%s" with title "%s" sound name "Glass"`, esc(body), esc(title))
	_ = exec.Command("osascript", "-e", script).Run()
}
