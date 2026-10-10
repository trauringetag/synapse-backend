package repository

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID                    int       `json:"id"`
	FirstName             string    `json:"first_name"`
	LastName              string    `json:"last_name"`
	Email                 string    `json:"email"`
	PasswordHash          string    `json:"-"`
	Role                  string    `json:"role"`
	RefreshToken          string    `json:"-"`
	RefreshTokenExpiresAt time.Time `json:"-"`
	TokenVersion          int       `json:"-"`
}

type UserRepository interface {
	GetAll(ctx context.Context) ([]User, error)
	GetByID(ctx context.Context, id int) (*User, error)
	Create(ctx context.Context, u *User) error
	Delete(ctx context.Context, id int) (bool, error)
	FindByEmail(ctx context.Context, email string) (*User, error)
	FindByRefreshToken(ctx context.Context, token string) (*User, error)
	UpdateRefreshToken(ctx context.Context, userID int, token string, expiresAt time.Time) error
	ClearRefreshToken(ctx context.Context, userID int) error
	GetTokenVersion(ctx context.Context, userID int) (int, error)
	IncrementTokenVersion(ctx context.Context, userID int) error
}

type postgresUserRepository struct {
	db *pgxpool.Pool
}

func NewUserRepository(db *pgxpool.Pool) UserRepository {
	return &postgresUserRepository{db: db}
}

func (r *postgresUserRepository) GetAll(ctx context.Context) ([]User, error) {
	query := `SELECT id, first_name, last_name, email, role FROM users ORDER BY id DESC LIMIT 50`
	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.FirstName, &u.LastName, &u.Email, &u.Role); err != nil {
			return nil, err
		}
		users = append(users, u)
	}
	if err = rows.Err(); err != nil {
		return nil, err
	}
	if users == nil {
		users = []User{}
	}
	return users, nil
}

func (r *postgresUserRepository) GetByID(ctx context.Context, id int) (*User, error) {
	query := `SELECT id, first_name, last_name, email, role FROM users WHERE id = $1`
	var u User
	err := r.db.QueryRow(ctx, query, id).Scan(&u.ID, &u.FirstName, &u.LastName, &u.Email, &u.Role)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *postgresUserRepository) Create(ctx context.Context, u *User) error {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.PasswordHash), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.PasswordHash = string(hashedPassword)
	if u.Role == "" {
		u.Role = "user"
	}
	query := `INSERT INTO users (first_name, last_name, email, password_hash, role) 
	          VALUES ($1, $2, $3, $4, $5) RETURNING id`
	return r.db.QueryRow(ctx, query, u.FirstName, u.LastName, u.Email, u.PasswordHash, u.Role).Scan(&u.ID)
}

func (r *postgresUserRepository) Delete(ctx context.Context, id int) (bool, error) {
	query := `DELETE FROM users WHERE id = $1`
	result, err := r.db.Exec(ctx, query, id)
	if err != nil {
		return false, err
	}
	return result.RowsAffected() > 0, nil
}

func (r *postgresUserRepository) FindByEmail(ctx context.Context, email string) (*User, error) {
	query := `SELECT id, first_name, last_name, email, password_hash, role, token_version FROM users WHERE email = $1`
	var u User
	err := r.db.QueryRow(ctx, query, email).Scan(&u.ID, &u.FirstName, &u.LastName, &u.Email, &u.PasswordHash, &u.Role, &u.TokenVersion)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *postgresUserRepository) FindByRefreshToken(ctx context.Context, token string) (*User, error) {
	query := `SELECT id, first_name, last_name, email, password_hash, role, refresh_token, refresh_token_expires_at, token_version FROM users WHERE refresh_token = $1`
	var u User
	err := r.db.QueryRow(ctx, query, token).Scan(&u.ID, &u.FirstName, &u.LastName, &u.Email, &u.PasswordHash, &u.Role, &u.RefreshToken, &u.RefreshTokenExpiresAt, &u.TokenVersion)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *postgresUserRepository) UpdateRefreshToken(ctx context.Context, userID int, token string, expiresAt time.Time) error {
	query := `UPDATE users SET refresh_token = $1, refresh_token_expires_at = $2 WHERE id = $3`
	_, err := r.db.Exec(ctx, query, token, expiresAt, userID)
	return err
}

func (r *postgresUserRepository) ClearRefreshToken(ctx context.Context, userID int) error {
	query := `UPDATE users SET refresh_token = NULL, refresh_token_expires_at = NULL WHERE id = $1`
	_, err := r.db.Exec(ctx, query, userID)
	return err
}

func (r *postgresUserRepository) GetTokenVersion(ctx context.Context, userID int) (int, error) {
	query := `SELECT token_version FROM users WHERE id = $1`
	var version int
	err := r.db.QueryRow(ctx, query, userID).Scan(&version)
	if err != nil {
		return 0, err
	}
	return version, nil
}

func (r *postgresUserRepository) IncrementTokenVersion(ctx context.Context, userID int) error {
	query := `UPDATE users SET token_version = token_version + 1 WHERE id = $1`
	_, err := r.db.Exec(ctx, query, userID)
	return err
}