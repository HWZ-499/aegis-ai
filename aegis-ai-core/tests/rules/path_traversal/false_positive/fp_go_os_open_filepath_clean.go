package pathtraversal

import (
	"net/http"
	"os"
	"path/filepath"
)

// FP: 经过 filepath.Clean 规范化后的路径再传入 os.Open。
func HandlerFP(w http.ResponseWriter, r *http.Request) {
	filename := r.FormValue("file")
	safePath := filepath.Clean("/var/data/" + filename)
	f, _ := os.Open(safePath)
	defer func() {
		if f != nil {
			_ = f.Close()
		}
	}()
}

