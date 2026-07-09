package samples

import "net/http"

func health() {
	http.Get("https://api.example.com/health")
}
