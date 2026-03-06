package openredirect

import (
	"net/http"
)

// TP: 用户可控参数直接作为 http.Redirect 的目标 URL。
func HandlerTP(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, r.FormValue("next"), http.StatusFound)
}

