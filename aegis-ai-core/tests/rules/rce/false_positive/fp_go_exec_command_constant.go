package rce

import (
	"net/http"
	"os/exec"
)

// FP: exec.Command 仅执行常量命令，不包含用户输入。
func HandlerFP(w http.ResponseWriter, r *http.Request) {
	_ = exec.Command("/bin/sh", "-c", "ls -la") // #nosec G204
}

