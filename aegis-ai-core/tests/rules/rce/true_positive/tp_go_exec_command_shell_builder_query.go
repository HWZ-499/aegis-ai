package rce

import (
	"os/exec"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// TP: 用户输入经模板渲染后进入 sh -c 动态命令执行。
func HandlerTPFiberShellBuilder(app *fiber.App) {
	app.Get("/execute", func(c *fiber.Ctx) error {
		userInput := c.Query("command")
		var builder strings.Builder
		builder.WriteString(userInput)
		_ = exec.Command("sh", "-c", builder.String()) // #nosec G204
		return c.SendString("ok")
	})
}
