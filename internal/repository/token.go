package repository

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trauringetag/synapse-backend/internal/models"
)

var ErrRefreshTokenReplay = errors.New("Обнаружено повторное использование Refresh-токена")
var ErrInactiveTokenUser = errors.New("Refresh-токен: пользователь неактивен или токен отсутствует")

type TokenRepository struct {
	pool *pgxpool.Pool
}

func NewTokenRepository(pool *pgxpool.Pool) *TokenRepository {
	return &TokenRepository{pool: pool}
}

func (r *TokenRepository) Store(ctx context.Context, userID uuid.UUID, tokenHash string, expiresAt time.Time) error {
	_, err := r.pool.Exec(ctx, `
		INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
		VALUES ($1, $2, $3)
	`, userID, tokenHash, expiresAt)
	return err
}

func (r *TokenRepository) GetActive(ctx context.Context, tokenHash string) (*models.RefreshToken, error) {
	var t models.RefreshToken
	err := r.pool.QueryRow(ctx, `
		SELECT id, user_id, token_hash, expires_at, revoked, created_at
		FROM refresh_tokens
		WHERE token_hash = $1
	`, tokenHash).Scan(&t.ID, &t.UserID, &t.TokenHash, &t.ExpiresAt, &t.Revoked, &t.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (r *TokenRepository) Rotate(
	ctx context.Context,
	oldHash string,
	expectedUserID uuid.UUID,
	createSuccessor func(*models.User) (string, time.Time, error),
) (*models.User, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, fmt.Errorf("Начать обновление ротации: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var userID uuid.UUID
	err = tx.QueryRow(ctx, `
        UPDATE refresh_tokens
        SET revoked = TRUE
        WHERE token_hash = $1 AND revoked = FALSE AND expires_at > NOW()
        RETURNING user_id
    `, oldHash).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		var revoked bool
		var expiresAt time.Time
		lookupErr := tx.QueryRow(ctx, `SELECT revoked, expires_at FROM refresh_tokens WHERE token_hash = $1`, oldHash).Scan(&revoked, &expiresAt)
		if lookupErr == nil && revoked {
			return nil, ErrRefreshTokenReplay
		}
		if lookupErr != nil && !errors.Is(lookupErr, pgx.ErrNoRows) {
			return nil, fmt.Errorf("Проверьте refresh-токен после неудачного использования: %w", lookupErr)
		}
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, fmt.Errorf("Использовать refresh-токен: %w", err)
	}
	if userID != expectedUserID {
		return nil, ErrNotFound
	}

	var user models.User
	err = tx.QueryRow(ctx, `
        SELECT id, email, password_hash, role, status, first_name, last_name, created_at, updated_at
        FROM users WHERE id = $1 FOR UPDATE
    `, userID).Scan(&user.ID, &user.Email, &user.PasswordHash, &user.Role, &user.Status,
		&user.FirstName, &user.LastName, &user.CreatedAt, &user.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && user.Status != models.StatusActive) {
		if _, revokeErr := tx.Exec(ctx, `UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1 AND revoked = FALSE`, userID); revokeErr != nil {
			return nil, fmt.Errorf("Аннулировать refresh-токены неактивного пользователя: %w", revokeErr)
		}
		if commitErr := tx.Commit(ctx); commitErr != nil {
			return nil, fmt.Errorf("Применить отзыв прав для неактивного пользователя: %w", commitErr)
		}
		return nil, ErrInactiveTokenUser
	}
	if err != nil {
		return nil, fmt.Errorf("Загрузить refresh-токен для пользователя: %w", err)
	}

	newHash, expiresAt, err := createSuccessor(&user)
	if err != nil {
		return nil, fmt.Errorf("Cоздать новый токен обновления (refresh-токен): %w", err)
	}
	if _, err = tx.Exec(ctx, `INSERT INTO refresh_tokens (user_id, token_hash, expires_at) VALUES ($1, $2, $3)`, user.ID, newHash, expiresAt); err != nil {
		return nil, fmt.Errorf("Сохранить новый refresh-токен: %w", err)
	}
	if err = tx.Commit(ctx); err != nil {
		return nil, fmt.Errorf("Применить обновление ротации: %w", err)
	}
	return &user, nil
}

func (r *TokenRepository) Revoke(ctx context.Context, tokenHash string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE refresh_tokens SET revoked = TRUE WHERE token_hash = $1
	`, tokenHash)
	return err
}

func (r *TokenRepository) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE refresh_tokens SET revoked = TRUE WHERE user_id = $1 AND revoked = FALSE
	`, userID)
	return err
}
