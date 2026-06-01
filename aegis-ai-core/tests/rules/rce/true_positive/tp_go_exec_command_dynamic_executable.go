package rce

import (
	"net/http"
	"os/exec"
)

// TP: user-controlled executable path still allows command execution control.
func HandlerTPDynamicExecutable(w http.ResponseWriter, r *http.Request) {
	_ = exec.Command(r.FormValue("bin"), "status") // #nosec G204
}
