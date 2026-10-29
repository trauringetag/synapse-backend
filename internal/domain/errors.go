package domain

import (
	"errors"
	"fmt"

	"github.com/google/uuid"
)

// Доменные ошибки (канонические значения). Инфраструктурные и transport-слои
// обязаны возвращать именно их — тесты проверяют поведение через эти sentinel-ошибки.
var (
	ErrNotFound           = errors.New("not found")
	ErrConflict           = errors.New("conflict")
	ErrProtected          = errors.New("protected user")
	ErrRefreshTokenReplay = errors.New("Обнаружено повторное использование Refresh-токена")
	ErrInactiveTokenUser  = errors.New("Refresh-токен: пользователь неактивен или токен отсутствует")
)

// UUIDFromString разбирает строку в uuid; ошибка доменная, без привязки к слою.
func UUIDFromString(s string) (uuid.UUID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil, fmt.Errorf("Неверный идентификатор")
	}
	return id, nil
}
