package deserialization

import (
	"encoding/json"
	"net/http"
)

// TP: 用户输入直接传入 json.Unmarshal 进行反序列化。
func HandlerTP(w http.ResponseWriter, r *http.Request) {
	var obj map[string]interface{}
	_ = json.Unmarshal([]byte(r.FormValue("data")), &obj)
}

