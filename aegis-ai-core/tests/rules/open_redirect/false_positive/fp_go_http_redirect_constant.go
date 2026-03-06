package openredirect

import (
	"net/http"
)

// FP: http.Redirect 的目标为常量路径，不受用户输入控制。
func HandlerFP(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/home", http.StatusFound)
}

