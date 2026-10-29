// Package usecase — слой сценариев использования (Application Layer).
//
// Сюда вынесена вся бизнес-логика, которая ранее находилась в HTTP-обработчиках
// (internal/delivery/http/handler): валидация и нормализация входных данных,
// хеширование паролей (через порт PasswordHasher), защита от timing-атак,
// проверка ролей и статусов,
// выпуск/ротация/отзыв JWT-пар, работа с refresh-токенами.
//
// HTTP-обработчики остаются «тонкими»: они только декодируют запрос, вызывают
// метод use-case и преобразуют результат (или ошибку) в HTTP-ответ.
package usecase

import (
	"errors"
	"fmt"
	"net/http"
)

// ErrorCode — классификация ошибок слоя use-case для HTTP-адаптера.
type ErrorCode int

const (
	// ErrCodeInternal — непредвиденная внутренняя ошибка (HTTP 500).
	ErrCodeInternal ErrorCode = iota
	// ErrCodeValidation — невалидные данные запроса (HTTP 400).
	ErrCodeValidation
	// ErrCodeUnauthorized — некорректные учетные данные / недействительный токен (HTTP 401).
	ErrCodeUnauthorized
	// ErrCodeForbidden — доступ запрещен политикой безопасности (HTTP 403).
	ErrCodeForbidden
	// ErrCodeNotFound — ресурс не найден (HTTP 404).
	ErrCodeNotFound
	// ErrCodeConflict — конфликт уникальности, например email уже используется (HTTP 409).
	ErrCodeConflict
	// ErrCodeUnavailable — сервис временно недоступен (HTTP 503).
	ErrCodeUnavailable
)

// UseCaseError — типизированная ошибка слоя use-case. Сообщения берутся из
// словаря internal/messages, а поле Details содержит ошибки валидации по полям
// (карта "имя поля -> список сообщений") — ровно тот формат, который отдаёт
// HTTP-слой в теле ответа.
type UseCaseError struct {
	Code    ErrorCode
	Message string
	Details map[string][]string
	Err     error // оригинальная (доменная/системная) ошибка, если есть
}

func (e *UseCaseError) Error() string {
	if e.Err != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Err)
	}
	return e.Message
}

// Unwrap позволяет использовать errors.Is для доменных sentinel-ошибок.
func (e *UseCaseError) Unwrap() error { return e.Err }

// HTTPStatus сопоставляет код ошибки с HTTP-статусом ответа.
func (c ErrorCode) HTTPStatus() int {
	switch c {
	case ErrCodeValidation:
		return http.StatusBadRequest
	case ErrCodeUnauthorized:
		return http.StatusUnauthorized
	case ErrCodeForbidden:
		return http.StatusForbidden
	case ErrCodeNotFound:
		return http.StatusNotFound
	case ErrCodeConflict:
		return http.StatusConflict
	case ErrCodeUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

func newErr(code ErrorCode, msg string) *UseCaseError {
	return &UseCaseError{Code: code, Message: msg}
}

func validationErr(msg string, details map[string][]string) *UseCaseError {
	return &UseCaseError{Code: ErrCodeValidation, Message: msg, Details: details}
}

func wrapErr(code ErrorCode, msg string, err error) *UseCaseError {
	return &UseCaseError{Code: code, Message: msg, Err: err}
}

// AsUseCaseError извлекает *UseCaseError из цепочки ошибок.
func AsUseCaseError(err error) (*UseCaseError, bool) {
	var ue *UseCaseError
	if errors.As(err, &ue) {
		return ue, true
	}
	return nil, false
}
