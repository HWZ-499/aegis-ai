package sqlinjection

import (
	"database/sql"
	"net/http"
)

// TP: placeholders bind values, but the ORDER BY SQL fragment is still
// concatenated from user input.
func HandlerTP(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	sort := r.FormValue("sort")
	id := r.FormValue("id")
	db.Query("SELECT * FROM users WHERE id = $1 ORDER BY "+sort, id)
}
