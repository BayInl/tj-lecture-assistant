package main

import (
	"github.com/egoist/mygo"
)

// sendNotification dispatches a native notification when supported, falling back on Darwin.
func sendNotification(id, title, body string, onClick func()) {
	if mygo.NotificationsSupported() {
		n := mygo.NewNotification(mygo.NotificationOptions{
			ID:    id,
			Group: "tj-lecture",
			Title: title,
			Body:  body,
		})
		if onClick != nil {
			n.OnClick(func() {
				onClick()
				n.Close()
			})
		}
		if err := n.Show(); err == nil {
			return
		}
	}
	fallbackNotify(title, body)
}
