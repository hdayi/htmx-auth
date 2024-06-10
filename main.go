package main

import (
	"context"
	"htmx-jwt/dto"
	"htmx-jwt/services"
	"htmx-jwt/templates"
	"net/http"

	echojwt "github.com/labstack/echo-jwt/v4"
	"github.com/labstack/echo/v4"
)

func main() {
	e := echo.New()

	e.Static("/static", "static")

	e.GET("/", func(c echo.Context) error {
		return templates.Index().Render(context.Background(), c.Response().Writer)
	})

	// Bununla route "/content" ile baslayan butun routlari eklemis oluyoruz bu gruba
	guardedRoutes := e.Group("/content")
	guardedRoutes.Use(services.TokenRefresherMiddleware)
	guardedRoutes.Use(echojwt.WithConfig(echojwt.Config{
		SigningKey:   []byte(services.JwtSecretKey),
		TokenLookup:  "cookie:access-token",
		ErrorHandler: services.JWTErrorChecker,
	}))

	// content yazmaya gerek yok artk
	guardedRoutes.GET("", func(c echo.Context) error {
		return templates.Content().Render(context.Background(), c.Response().Writer)
	})

	e.POST("/login", func(c echo.Context) error {
		username := c.FormValue("username")
		password := c.FormValue("password")
		var loggedInUser *dto.UserDto
		// girilen bi;gi;er dogru mu  bakalim
		for _, user := range services.GetUsers() {
			if user.Username != username {
				continue
			}
			// bcrypt ile kontrol
			// err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
			if user.Password == password {
				loggedInUser = user
				break
			}
		}
		if loggedInUser == nil {
			return echo.NewHTTPError(http.StatusUnauthorized, "Invalid Credentials")
		}

		// Burada JWT uretmek gerekiyor
		err := services.GenerateTokenEndSetCookies(loggedInUser, c)
		if err != nil {
			return echo.NewHTTPError(http.StatusUnauthorized, "Invalid token")
		}

		return c.Redirect(http.StatusMovedPermanently, "/content")
	})

	e.Logger.Fatal(e.Start(":8080"))
}
