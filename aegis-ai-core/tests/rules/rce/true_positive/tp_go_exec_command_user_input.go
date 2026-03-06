package rce

import (
	"net/http"
	"os/exec"
)

// TP: 用户可控参数直接作为 exec.Command 的参数，存在命令注入风险。
func HandlerTP(w http.ResponseWriter, r *http.Request) {
	_ = exec.Command("/bin/sh", "-c", r.FormValue("cmd")) // #nosec G204
}

