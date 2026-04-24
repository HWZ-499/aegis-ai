package xss

import (
	"fmt"

	"github.com/gofiber/fiber/v2"
)

// TP: Fiber Query 参数进入 fmt.Sprintf 生成 HTML，再经 SendString 输出。
func HandlerTPFiberSendString(app *fiber.App) {
	app.Get("/search", func(c *fiber.Ctx) error {
		query := c.Query("query")
		html := fmt.Sprintf("<h2>Search Results for: %s</h2>", query)
		return c.Type("html").SendString(html)
	})
}
