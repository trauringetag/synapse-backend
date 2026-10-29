package domain

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type UserListFilter struct {
	Page   int
	Limit  int
	Search string
	Role   string
	Status string
}

type UserListResult struct {
	Items      []User `json:"items"`
	Page       int    `json:"page"`
	Limit      int    `json:"limit"`
	Total      int64  `json:"total"`
	TotalPages int64  `json:"total_pages"`
}

type UserRepository interface {
	Create(context.Context, string, string, string, string, string) (*User, error)
	GetByID(context.Context, uuid.UUID) (*User, error)
	GetByEmail(context.Context, string) (*User, error)
	List(context.Context, UserListFilter) (*UserListResult, error)
	ReplaceProfile(context.Context, uuid.UUID, string, string, string) (*User, error)
	Update(context.Context, uuid.UUID, *string, *string, *string, *string, *string) (*User, error)
	Replace(context.Context, uuid.UUID, string, string, string, string, string) (*User, error)
	Delete(context.Context, uuid.UUID) error
}

type RefreshTokenRepository interface {
	Store(context.Context, uuid.UUID, string, time.Time) error
	Rotate(context.Context, string, uuid.UUID, func(*User) (string, time.Time, error)) (*User, error)
	Revoke(context.Context, string) error
	RevokeAllForUser(context.Context, uuid.UUID) error
}
