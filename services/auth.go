package services

import (
	"htmx-jwt/dto"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/labstack/echo/v4"
)

const (
	AccessTokenCookieName = "access-token"
	// bu burada olmamali gercekte .env'den falan alinmali
	JwtSecretKey           = "veryverysecret"
	RefreshTokenCookieName = "refresh-token"
	JwtRefreshSecretKey    = "thisIsAlsoVerySecret"
)

// JWT icine gommek istedigimiz claim'leri burada ekliyoruz
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func GenerateTokenEndSetCookies(user *dto.UserDto, c echo.Context) error {
	accessToken, exp, err := generateAccessToken(user)
	if err != nil {
		return err
	}
	setTokenCookie(AccessTokenCookieName, accessToken, exp, c)
	// bu refresh token ne ise yariyor??
	refreshToken, exp, err := generateRefreshToken(user)
	if err != nil {
		return err
	}
	setTokenCookie(RefreshTokenCookieName, refreshToken, exp, c)
	return nil
}

func generateAccessToken(user *dto.UserDto) (string, time.Time, error) {
	// Token 1 saat icin gecerli
	expirationTime := time.Now().Add(14 * time.Minute)
	return generateToken(user, expirationTime, []byte(JwtSecretKey))
}

func generateRefreshToken(user *dto.UserDto) (string, time.Time, error) {
	// bu ise 24 saat icin gecerli
	expirationTime := time.Now().Add(24 * time.Hour)
	return generateToken(user, expirationTime, []byte(JwtRefreshSecretKey))
}

func generateToken(user *dto.UserDto, expirationTime time.Time, secret []byte) (string, time.Time, error) {
	claims := &Claims{
		Username: user.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(secret)
	if err != nil {
		return "", time.Now(), err
	}
	return tokenString, expirationTime, nil
}

func setTokenCookie(AccessTokenCookieName, accessToken string, exp time.Time, c echo.Context) {
	cookie := new(http.Cookie)
	cookie.Name = AccessTokenCookieName
	cookie.Value = accessToken
	cookie.Expires = exp
	cookie.Path = "/"
	cookie.HttpOnly = true
	c.SetCookie(cookie)
}

func JWTErrorChecker(c echo.Context, err error) error {
	return c.Redirect(http.StatusMovedPermanently, "/")
}

func TokenRefresherMiddleware(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		// Kullanici login olmamis token yok ise
		if c.Get("user") == nil {
			return next(c)
		}
		u := c.Get("user").(*jwt.Token)
		claims := u.Claims.(*Claims)

		// burada asil token'nin expire olmasina 15 dakika kalmadi ise token refresh edilmiyor
		// 15 dakikadan az kaldi ise refresh ediyoruz
		if time.Until(time.Unix(claims.ExpiresAt, 0)) < 15*time.Minute {
			rc, err := c.Cookie(RefreshTokenCookieName)
			if err == nil && rc != nil {
				tkn, err := jwt.ParseWithClaims(rc.Value, claims, func(t *jwt.Token) (interface{}, error) {
					return []byte(JwtRefreshSecretKey), nil
				})
				if err != nil {
					if err == jwt.ErrSignatureInvalid {
						c.Response().Writer.WriteHeader(http.StatusUnauthorized)
					}
				}

				if tkn != nil && tkn.Valid {
					// token gecerli gorunuyor
					_ = GenerateTokenEndSetCookies(&dto.UserDto{
						Username: claims.Username,
					}, c)
				}
			}
		}
		return next(c)
	}
}
