package middleware

import (
	"context"
	"net/http"
	"os"
	"strings"

	"github.com/golang-jwt/jwt/v5"
)

type contextKey string

const UserClaimsKey contextKey = "user_claims"

type Claims struct {
	UserID       int    `json:"user_id"`
	Email        string `json:"email"`
	Role         string `json:"role"`
	TokenVersion int    `json:"token_version"`
	jwt.RegisteredClaims
}

var JWTSecret []byte

func InitJWT() {
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		secret = "super-secret-key-change-this-in-production-min-32-chars"
	}
	JWTSecret = []byte(secret)
}

type TokenVersionChecker func(ctx context.Context, userID int, version int) bool

func JWTMiddleware(next http.Handler, checkVersion TokenVersionChecker) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			http.Error(w, `{"error": "Отсутствует заголовок Authorization"}`, http.StatusUnauthorized)
			return
		}

		parts := strings.SplitN(authHeader, " ", 2)
		if len(parts) != 2 || parts[0] != "Bearer" {
			http.Error(w, `{"error": "Неверный формат заголовка Authorization"}`, http.StatusUnauthorized)
			return
		}

		tokenString := parts[1]
		claims := &Claims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, jwt.ErrSignatureInvalid
			}
			return JWTSecret, nil
		}, jwt.WithExpirationRequired())

		if err != nil || !token.Valid {
			http.Error(w, `{"error": "Недействительный или просроченный токен"}`, http.StatusUnauthorized)
			return
		}

		// Проверка версии токена (защита от использования отозванного токена)
		if checkVersion != nil && !checkVersion(r.Context(), claims.UserID, claims.TokenVersion) {
			http.Error(w, `{"error": "Сессия завершена, выполните вход заново"}`, http.StatusUnauthorized)
			return
		}

		ctx := context.WithValue(r.Context(), UserClaimsKey, claims)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func GetClaimsFromContext(ctx context.Context) *Claims {
	claims, ok := ctx.Value(UserClaimsKey).(*Claims)
	if !ok {
		return nil
	}
	return claims
}