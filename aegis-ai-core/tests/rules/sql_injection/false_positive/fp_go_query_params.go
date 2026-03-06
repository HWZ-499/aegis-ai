package sqlinjection

import (
	"database/sql"
	"net/http"
)

// FP: 使用常量 SQL 和参数绑定，不包含用户输入。
func HandlerFP(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	query := "SELECT * FROM users WHERE id = ?"
	db.Query(query, 42)
}

