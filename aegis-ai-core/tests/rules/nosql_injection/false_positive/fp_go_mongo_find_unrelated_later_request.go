package nosqlinjection

import (
	"context"
	"net/http"
)

// FP: safe query and later unrelated request input must not be paired across statements.
func HandlerFPUnrelatedLaterRequest(w http.ResponseWriter, r *http.Request, coll Collection) {
	_ = coll.Find(context.Background(), map[string]interface{}{
		"role": "admin",
	})

	auditReason := r.FormValue("reason")
	_ = auditReason
}
