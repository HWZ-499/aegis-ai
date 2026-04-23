package sqlinjection

import (
    "database/sql"

    "github.com/gofiber/fiber/v2"
)

// FP: Fiber 回调内使用占位符参数绑定，不应报 SQL 注入。
func HandlerFPFiberQueryRow(app *fiber.App, db *sql.DB) {
    app.Post("/loginapi", func(c *fiber.Ctx) error {
        username := c.FormValue("username")
        var userID string
        err := db.QueryRow("SELECT id FROM user WHERE username = ?", username).Scan(&userID)
        if err != nil {
            return c.Status(fiber.StatusInternalServerError).SendString("Internal server error")
        }
        return c.SendString("ok")
    })
}
