package pathtraversal

import (
	"io/ioutil"
	"path/filepath"

	"github.com/gofiber/fiber/v2"
)

// TP: 用户输入参与路径拼接后传入 ioutil.ReadFile。
func HandlerTPFiberReadFile(app *fiber.App) {
	app.Get("/file", func(c *fiber.Ctx) error {
		filename := c.Query("filename")
		path := filepath.Join("files", filename)
		data, _ := ioutil.ReadFile(path) // #nosec G304
		return c.SendString(string(data))
	})
}
