package rce

import (
	"net/http"
	"os/exec"
)

// TP: fixed interpreter with an eval flag executes user-controlled code.
func HandlerTPInterpreterEval(w http.ResponseWriter, r *http.Request) {
	_ = exec.Command("node", "-e", r.FormValue("code")) // #nosec G204
}
