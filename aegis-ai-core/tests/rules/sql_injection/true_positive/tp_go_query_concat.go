package sqlinjection

import (
	"database/sql"
	"net/http"
)

// TP: 用户输入直接拼接到 SQL 查询字符串，存在 SQL 注入风险。
func HandlerTP(w http.ResponseWriter, r *http.Request, db *sql.DB) {
	db.Query("SELECT * FROM users WHERE id = " + r.FormValue("id"))
}

