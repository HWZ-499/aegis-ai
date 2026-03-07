package nosqlinjection

import (
	"context"
	"net/http"
)

// FP: 使用常量构造 NoSQL 查询条件，不应视为 NoSQL 注入。
// 期望: 无 NOSQL_INJECTION
func HandlerFP(w http.ResponseWriter, r *http.Request, coll Collection) {
	_ = coll.Find(context.Background(), map[string]interface{}{
		"user": "admin",
	})
}

