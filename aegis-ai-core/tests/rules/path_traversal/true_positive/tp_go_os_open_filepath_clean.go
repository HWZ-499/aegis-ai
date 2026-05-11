package pathtraversal

import (
	"net/http"
	"os"
	"path/filepath"
)

// TP: filepath.Clean only normalizes the path; it does not prove the result
// remains inside /var/data.
func HandlerTP(w http.ResponseWriter, r *http.Request) {
	filename := r.FormValue("file")
	cleanPath := filepath.Clean("/var/data/" + filename)
	f, _ := os.Open(cleanPath)
	defer func() {
		if f != nil {
			_ = f.Close()
		}
	}()
}
