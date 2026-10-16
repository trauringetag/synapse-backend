package repository

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trauringetag/synapse-backend/internal/models"
)

var ErrNotFound = errors.New("not found")
var ErrConflict = errors.New("conflict")

type UserRepository struct {
	pool *pgxpool.Pool
}

func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{pool: pool}
}

func (r *UserRepository) Create(ctx context.Context, email, passwordHash, role, name string) (*models.User, error) {
	var u models.User
	err := r.pool.QueryRow(ctx, `
		INSERT INTO users (email, password_hash, role, name)
		VALUES ($1, $2, $3, $4)
		RETURNING id, email, password_hash, role, name, created_at, updated_at
	`, email, passwordHash, role, name).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.Name, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrConflict
		}
		return nil, err
	}
	return &u, nil
}

func (r *UserRepository) GetByID(ctx context.Context, id uuid.UUID) (*models.User, error) {
	return r.scanOne(ctx, `SELECT id, email, password_hash, role, name, created_at, updated_at FROM users WHERE id = $1`, id)
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*models.User, error) {
	return r.scanOne(ctx, `SELECT id, email, password_hash, role, name, created_at, updated_at FROM users WHERE email = $1`, email)
}

func (r *UserRepository) List(ctx context.Context) ([]models.User, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, email, password_hash, role, name, created_at, updated_at
		FROM users ORDER BY created_at ASC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	users := make([]models.User, 0)
	for rows.Next() {
		var u models.User
		if err := rows.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.Name, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	return users, rows.Err()
}

func (r *UserRepository) Update(ctx context.Context, id uuid.UUID, email, name, role, passwordHash *string) (*models.User, error) {
	var u models.User
	err := r.pool.QueryRow(ctx, `
		UPDATE users SET
			email = COALESCE($2, email),
			name = COALESCE($3, name),
			role = COALESCE($4, role),
			password_hash = COALESCE($5, password_hash),
			updated_at = NOW()
		WHERE id = $1
		RETURNING id, email, password_hash, role, name, created_at, updated_at
	`, id, email, name, role, passwordHash).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.Name, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrConflict
		}
		return nil, err
	}
	return &u, nil
}

func (r *UserRepository) Replace(ctx context.Context, id uuid.UUID, email, name, role, passwordHash string) (*models.User, error) {
	var u models.User
	err := r.pool.QueryRow(ctx, `
		UPDATE users SET
			email = $2,
			name = $3,
			role = $4,
			password_hash = $5,
			updated_at = NOW()
		WHERE id = $1
		RETURNING id, email, password_hash, role, name, created_at, updated_at
	`, id, email, name, role, passwordHash).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.Name, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		if isUniqueViolation(err) {
			return nil, ErrConflict
		}
		return nil, err
	}
	return &u, nil
}

func (r *UserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (r *UserRepository) scanOne(ctx context.Context, q string, arg any) (*models.User, error) {
	var u models.User
	err := r.pool.QueryRow(ctx, q, arg).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.Name, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func isUniqueViolation(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505"
}

func UUIDFromString(s string) (uuid.UUID, error) {
	id, err := uuid.Parse(s)
	if err != nil {
		return uuid.Nil, fmt.Errorf("Неверный идентификатор")
	}
	return id, nil
}
