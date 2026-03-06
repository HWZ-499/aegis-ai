package xss

import (
	"fmt"
	"html/template"
	"net/http"
)

// FP: 用户输入经过 template.HTMLEscapeString 转义后再输出。
func HandlerFP(w http.ResponseWriter, r *http.Request) {
	name := r.FormValue("name")
	safeName := template.HTMLEscapeString(name)
	fmt.Fprintf(w, "<p>Hello %s</p>", safeName)
}

