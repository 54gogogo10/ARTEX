package server

import (
	"log"
	"runtime/debug"
	"time"
)

// goRecover runs fn in a new goroutine. If fn panics, the panic is logged with
// a stack trace instead of crashing the whole process, and fn is retried after
// a fixed backoff. fn returning normally ends the retry cycle — long-lived
// loops exit on purpose (ctx done), and that exit must be preserved.
//
// Used for the always-on housekeeping loops (scheduler, notifier, logsink
// writer): they carry live task state, and one boundary panic (bad index, nil
// deref) must not take down every running task with the process. The start
// script would restart us, but mid-task hard kills lose real work.
func goRecover(name string, fn func()) {
	go func() {
		for {
			panicked := true
			func() {
				defer func() {
					if panicked {
						if r := recover(); r != nil {
							log.Printf("[guard] %s 循环 panic 已恢复，10s 后重试: %v\n%s", name, r, debug.Stack())
						}
					}
				}()
				fn()
				panicked = false
			}()
			if !panicked {
				return
			}
			time.Sleep(10 * time.Second)
		}
	}()
}
