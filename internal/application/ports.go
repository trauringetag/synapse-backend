package application

import (
	"context"
	"time"

	"github.com/google/uuid"
	"github.com/trauringetag/synapse-backend/internal/domain"
)

type UserListFilter struct {
	Page   int
	Limit  int
	Search string
	Role   string
	Status string
}

type UserListResult struct {
	Items      []domain.User `json:"items"`
	Page       int           `json:"page"`
	Limit      int           `json:"limit"`
	Total      int64         `json:"total"`
	TotalPages int64         `json:"total_pages"`
}

type UserRepository interface {
	Create(context.Context, string, string, string, string, string) (*domain.User, error)
	GetByID(context.Context, uuid.UUID) (*domain.User, error)
	GetByEmail(context.Context, string) (*domain.User, error)
	List(context.Context, UserListFilter) (*UserListResult, error)
	ReplaceProfile(context.Context, uuid.UUID, string, string, string) (*domain.User, error)
	Update(context.Context, uuid.UUID, *string, *string, *string, *string, *string) (*domain.User, error)
	Replace(context.Context, uuid.UUID, string, string, string, string, string) (*domain.User, error)
	Delete(context.Context, uuid.UUID) error
}

type RefreshTokenRepository interface {
	Store(context.Context, uuid.UUID, string, time.Time) error
	Rotate(context.Context, string, uuid.UUID, func(*domain.User) (string, time.Time, error)) (*domain.User, error)
	Revoke(context.Context, string) error
	RevokeAllForUser(context.Context, uuid.UUID) error
}
