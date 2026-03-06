package deserialization

import (
	"encoding/json"
	"net/http"
)

// FP: 仅对常量 JSON 字符串执行 json.Unmarshal，不包含用户输入。
func HandlerFP(w http.ResponseWriter, r *http.Request) {
	raw := `{"safe": true}`
	var obj map[string]interface{}
	_ = json.Unmarshal([]byte(raw), &obj)
}

