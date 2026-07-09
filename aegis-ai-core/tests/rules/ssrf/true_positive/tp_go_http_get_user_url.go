package samples

import "net/http"

func fetch(r *http.Request) {
	target := r.FormValue("url")
	http.Get(target)
}
