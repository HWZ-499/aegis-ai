package pathtraversal

import (
	"path/filepath"

	"github.com/gofiber/fiber/v2"
)

// FP: 仅进行 filepath.Join 拼接但未触发文件系统访问，不应直接报路径穿越。
func HandlerFPJoinOnly(c *fiber.Ctx) error {
	filename := c.Query("filename")
	path := filepath.Join("files", filename)
	return c.SendString(path)
}
