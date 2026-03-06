package xss

import (
	"fmt"
	"net/http"
)

// TP: 用户输入未经转义直接通过 fmt.Fprintf 输出到响应。
func HandlerTP(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "<p>Hello %s</p>", r.FormValue("name"))
}

