package main

import (
	"context"
	"sahibinden/templates"

	"github.com/labstack/echo"
)

func main() {
	e := echo.New()
	e.Static("/static", "static")

	e.GET("/", func(c echo.Context) error {
		return templates.Index().Render(context.Background(), c.Response().Writer)
		// return c.String(http.StatusOK, "Hello, World!")
	})

	e.Logger.Fatal(e.Start(":8080"))
}
