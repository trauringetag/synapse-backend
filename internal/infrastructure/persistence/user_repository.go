package persistence

import (
	"context"
	"errors"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/trauringetag/synapse-backend/internal/domain"
)

type UserRepository struct {
	pool *pgxpool.Pool
}

// Компиляционная проверка: реализация удовлетворяет порту из домена
// (единственный источник правды — internal/domain/ports.go).
var _ domain.UserRepository = (*UserRepository)(nil)

func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{pool: pool}
}

func (r *UserRepository) Create(ctx context.Context, email, passwordHash, role, firstName, lastName string) (*domain.User, error) {
	var u domain.User
	err := r.pool.QueryRow(ctx, `
		INSERT INTO users (email, password_hash, role, first_name, last_name)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, email, password_hash, role, status, first_name, last_name, created_at, updated_at
	`, email, passwordHash, role, firstName, lastName).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.Status, &u.FirstName, &u.LastName, &u.CreatedAt, &u.UpdatedAt,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return nil, domain.ErrConflict
		}
		return nil, err
	}
	return &u, nil
}

func (r *UserRepository) GetByID(ctx context.Context, id uuid.UUID) (*domain.User, error) {
	return r.scanOne(ctx, `SELECT id, email, password_hash, role, status, first_name, last_name, created_at, updated_at FROM users WHERE id = $1`, id)
}

func (r *UserRepository) GetByEmail(ctx context.Context, email string) (*domain.User, error) {
	return r.scanOne(ctx, `SELECT id, email, password_hash, role, status, first_name, last_name, created_at, updated_at FROM users WHERE email = $1`, email)
}

type UserListFilter = domain.UserListFilter

type UserListResult = domain.UserListResult

func (r *UserRepository) List(ctx context.Context, f UserListFilter) (*UserListResult, error) {
	where := ` WHERE ($1 = '' OR role = $1) 
				AND ($2 = '' OR status = $2) 
				AND ($3 = '' OR to_tsvector('simple', concat_ws(' ', email, first_name, last_name)) @@ plainto_tsquery('simple', $3) 
					OR email ILIKE '%' || $3 || '%' 
					OR first_name ILIKE '%' || $3 || '%' 
					OR last_name ILIKE '%' || $3 || '%' 
					OR (first_name || ' ' || last_name) ILIKE '%' || $3 || '%')`
	var total int64
	if err := r.pool.QueryRow(ctx, `SELECT COUNT(*) FROM users`+where, f.Role, f.Status, f.Search).Scan(&total); err != nil {
		return nil, err
	}
	rows, err := r.pool.Query(ctx, `SELECT id, email, password_hash, role, status, first_name, last_name, created_at, updated_at 
									FROM users`+where+` 
									ORDER BY created_at 
									ASC LIMIT $4 OFFSET $5`,
		f.Role, f.Status, f.Search, f.Limit, (f.Page-1)*f.Limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]domain.User, 0)
	for rows.Next() {
		var u domain.User
		if err := rows.Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.Status, &u.FirstName, &u.LastName, &u.CreatedAt, &u.UpdatedAt); err != nil {
			return nil, err
		}
		items = append(items, u)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	pages := total / int64(f.Limit)
	if total%int64(f.Limit) != 0 {
		pages++
	}
	return &UserListResult{Items: items, Page: f.Page, Limit: f.Limit, Total: total, TotalPages: pages}, nil
}

func (r *UserRepository) ReplaceProfile(ctx context.Context, id uuid.UUID, email, firstName, lastName string) (*domain.User, error) {
	var u domain.User
	err := r.pool.QueryRow(ctx, `
		UPDATE users 
		SET 
			updated_at = CASE 
				WHEN email IS DISTINCT FROM $2 
				OR first_name IS DISTINCT FROM $3 
				OR last_name IS DISTINCT FROM $4 
				THEN NOW() 
				ELSE updated_at 
			END,
			email = $2, 
			first_name = $3, 
			last_name = $4
		WHERE id = $1 
		RETURNING id, email, password_hash, role, status, first_name, last_name, created_at, updated_at
	`, id, email, firstName, lastName).Scan(&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.Status, &u.FirstName, &u.LastName, &u.CreatedAt, &u.UpdatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		if isUniqueViolation(err) {
			return nil, domain.ErrConflict
		}
		return nil, err
	}
	return &u, nil
}

func (r *UserRepository) Update(ctx context.Context, id uuid.UUID, email, firstName, lastName, passwordHash, status *string) (*domain.User, error) {
	var u domain.User
	err := r.pool.QueryRow(ctx, `
		UPDATE users SET
			email = COALESCE($2, email),
			first_name = COALESCE($3, first_name),
			last_name = COALESCE($4, last_name),
			password_hash = COALESCE($5, password_hash),
			status = COALESCE($6, status),
			updated_at = CASE WHEN email IS DISTINCT FROM COALESCE($2, email)
				OR first_name IS DISTINCT FROM COALESCE($3, first_name)
				OR last_name IS DISTINCT FROM COALESCE($4, last_name)
				OR password_hash IS DISTINCT FROM COALESCE($5, password_hash)
				OR status IS DISTINCT FROM COALESCE($6, status)
				THEN NOW() ELSE updated_at END
		WHERE id = $1
		RETURNING id, email, password_hash, role, status, first_name, last_name, created_at, updated_at
	`, id, email, firstName, lastName, passwordHash, status).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.Status, &u.FirstName, &u.LastName, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		if isUniqueViolation(err) {
			return nil, domain.ErrConflict
		}
		return nil, err
	}
	return &u, nil
}

func (r *UserRepository) Replace(ctx context.Context, id uuid.UUID, email, firstName, lastName, passwordHash, status string) (*domain.User, error) {
	var u domain.User
	err := r.pool.QueryRow(ctx, `
		UPDATE users SET
			email = $2,
			first_name = $3,
			last_name = $4,
			password_hash = $5,
			status = $6,
			updated_at = NOW()
		WHERE id = $1
		RETURNING id, email, password_hash, role, status, first_name, last_name, created_at, updated_at
	`, id, email, firstName, lastName, passwordHash, status).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.Status, &u.FirstName, &u.LastName, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		if isUniqueViolation(err) {
			return nil, domain.ErrConflict
		}
		return nil, err
	}
	return &u, nil
}

func (r *UserRepository) Delete(ctx context.Context, id uuid.UUID) error {
	tag, err := r.pool.Exec(ctx, `DELETE FROM users WHERE id = $1 AND role <> $2`, id, domain.RoleAdmin)
	if err != nil {
		return err
	}
	if tag.RowsAffected() > 0 {
		return nil
	}

	var role string
	err = r.pool.QueryRow(ctx, `SELECT role FROM users WHERE id = $1`, id).Scan(&role)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.ErrNotFound
	}
	if err != nil {
		return err
	}
	if role == domain.RoleAdmin {
		return domain.ErrProtected
	}
	return domain.ErrNotFound
}

func (r *UserRepository) scanOne(ctx context.Context, q string, arg any) (*domain.User, error) {
	var u domain.User
	err := r.pool.QueryRow(ctx, q, arg).Scan(
		&u.ID, &u.Email, &u.PasswordHash, &u.Role, &u.Status, &u.FirstName, &u.LastName, &u.CreatedAt, &u.UpdatedAt,
	)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, domain.ErrNotFound
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
