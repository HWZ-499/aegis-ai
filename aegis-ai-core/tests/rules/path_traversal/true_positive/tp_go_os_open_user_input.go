package pathtraversal

import (
	"net/http"
	"os"
)

// TP: 用户输入直接拼接到文件路径并传给 os.Open。
func HandlerTP(w http.ResponseWriter, r *http.Request) {
	f, _ := os.Open("/var/data/" + r.FormValue("file"))
	defer func() {
		if f != nil {
			_ = f.Close()
		}
	}()
}

