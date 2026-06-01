package rce

import (
	"net/http"
	"os/exec"
)

// FP: fixed command with user input as an argv element does not invoke a shell command string.
func HandlerFPFixedCommandUserArg(w http.ResponseWriter, r *http.Request) {
	pattern := r.FormValue("pattern")
	_ = exec.Command("grep", pattern, "messages.log") // #nosec G204
}
