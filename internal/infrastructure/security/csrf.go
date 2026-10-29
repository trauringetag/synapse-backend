package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"strings"
)

// IssueCSRF генерирует CSRF-токен по двухсоставной схеме: случайный nonce +
// HMAC-SHA256 подпись от секретного ключа (nonce.sig). Токен читается JS,
// а сервер сверяет его с cookie и подписью.
func IssueCSRF(secret []byte) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	nonce := base64.RawURLEncoding.EncodeToString(b)
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(nonce))
	return nonce + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// ValidCSRF проверяет подпись CSRF-токена относительно секрета.
func ValidCSRF(secret []byte, token string) bool {
	p := strings.Split(token, ".")
	if len(p) != 2 {
		return false
	}
	sig, err := base64.RawURLEncoding.DecodeString(p[1])
	if err != nil {
		return false
	}
	mac := hmac.New(sha256.New, secret)
	mac.Write([]byte(p[0]))
	return hmac.Equal(sig, mac.Sum(nil))
}
