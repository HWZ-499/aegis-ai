package xss

import "github.com/gofiber/fiber/v2"

// FP: 函数内虽然有用户输入变量，但常量 HTML 输出不应被判定为 XSS。
func HandlerFPFiberConstantHTML(c *fiber.Ctx) error {
	input := c.FormValue("input")
	_ = input
	html := `
	<html>
	<body>
		<input type="text" name="input" />
	</body>
	</html>
	`
	return c.Type("html").SendString(html)
}
