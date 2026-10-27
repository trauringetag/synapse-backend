package handler

import (
	"context"
	"time"

	"github.com/google/uuid"

	"github.com/trauringetag/synapse-backend/internal/application"
	"github.com/trauringetag/synapse-backend/internal/models"
)

type UserStore interface {
	Create(ctx context.Context, email, passwordHash, role, firstName, lastName string) (*models.User, error)
	GetByID(ctx context.Context, id uuid.UUID) (*models.User, error)
	GetByEmail(ctx context.Context, email string) (*models.User, error)
	List(ctx context.Context, f application.UserListFilter) (*application.UserListResult, error)
	ReplaceProfile(ctx context.Context, id uuid.UUID, email, firstName, lastName string) (*models.User, error)
	Update(ctx context.Context, id uuid.UUID, email, firstName, lastName, passwordHash, status *string) (*models.User, error)
	Replace(ctx context.Context, id uuid.UUID, email, firstName, lastName, passwordHash, status string) (*models.User, error)
	Delete(ctx context.Context, id uuid.UUID) error
}

type TokenStore interface {
	Store(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error
	Rotate(ctx context.Context, oldHash string, expectedUserID uuid.UUID, createSuccessor func(*models.User) (string, time.Time, error)) (*models.User, error)
	Revoke(ctx context.Context, tokenHash string) error
	RevokeAllForUser(ctx context.Context, userID uuid.UUID) error
}
