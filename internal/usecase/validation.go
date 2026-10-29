package usecase

import (
	"strings"

	"github.com/trauringetag/synapse-backend/internal/domain"
)

// Нормализация и валидация входных данных. Это бизнес-правила, а не детали
// HTTP-транспорта, поэтому они живут в слое use-case.

func normalizeEmail(s string) string { return strings.ToLower(strings.TrimSpace(s)) }
func normalizeName(s string) string  { return strings.TrimSpace(s) }
func normalizeToken(s string) string { return strings.TrimSpace(s) }
func normalizeLower(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

func validEmail(e string) bool {
	return e != "" && strings.Contains(e, "@") && len(e) <= 255
}

func validPassword(p string) bool {
	return len(p) >= 8 && len(p) <= 72
}

func validFirstName(n string) bool { return n != "" && len(n) <= 255 }
func validLastName(n string) bool  { return n != "" && len(n) <= 255 }
func validRole(r string) bool      { return r == domain.RoleUser || r == domain.RoleAdmin }
func validStatus(s string) bool    { return s == domain.StatusActive || s == domain.StatusInactive }

// addDetail добавляет сообщение об ошибке для поля в карту деталей.
func addDetail(details map[string][]string, field, msg string) {
	if details == nil {
		return
	}
	details[field] = append(details[field], msg)
}
