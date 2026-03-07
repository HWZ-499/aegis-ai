package nosqlinjection

import (
	"context"
	"net/http"
)

// Collection 抽象 MongoDB 集合接口，便于测试。
type Collection interface {
	Find(ctx context.Context, filter interface{}) error
}

// TP: 使用 r.FormValue 直接构造 NoSQL 查询条件，存在注入风险。
// 期望检测: NOSQL_INJECTION (High)
func HandlerTP(w http.ResponseWriter, r *http.Request, coll Collection) {
	_ = coll.Find(context.Background(), map[string]interface{}{
		"user": r.FormValue("user"),
	})
}

