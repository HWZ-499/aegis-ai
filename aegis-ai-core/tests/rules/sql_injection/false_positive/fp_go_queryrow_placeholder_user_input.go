package sqlinjection

import (
    "database/sql"
    "net/http"
)

// FP: 使用占位符参数绑定（即便参数来自用户输入）不应报 SQL 注入。
func HandlerFPQueryRowUserInput(w http.ResponseWriter, r *http.Request, db *sql.DB) {
    username := r.FormValue("username")
    db.QueryRow("SELECT id, password FROM user WHERE username = ?", username)
}
