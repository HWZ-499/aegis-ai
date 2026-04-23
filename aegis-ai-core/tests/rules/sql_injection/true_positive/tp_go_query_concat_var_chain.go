package sqlinjection

import (
	"database/sql"
	"net/http"
)

// TP: 用户输入先赋值到变量，再拼接到 SQL 并传入 Query。
func HandlerTPVarChain(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	id := r.URL.Query().Get("id")
	q := "SELECT * FROM users WHERE id = " + id
	db.Query(q)
}
