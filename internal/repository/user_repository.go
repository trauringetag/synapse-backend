package repository

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID           int    `json:"id"`
	FirstName    string `json:"first_name"`
	LastName     string `json:"last_name"`
	Email        string `json:"email"`
	PasswordHash string `json:"-"` // "-" скрывает поле при сериализации в JSON
	Role         string `json:"role"`
}

type UserRepository interface {
	GetAll(ctx context.Context) ([]User, error)
	GetByID(ctx context.Context, id int) (*User, error)
	Create(ctx context.Context, u *User) error
	Delete(ctx context.Context, id int) (bool, error)
	FindByEmail(ctx context.Context, email string) (*User, error)
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

	// Хэшируем пароль перед сохранением
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(u.PasswordHash), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	u.PasswordHash = string(hashedPassword)

	// Если роль не указана, ставим "user" по умолчанию
	if u.Role == "" {
		u.Role = "user"
	}

	query := `INSERT INTO users (first_name, last_name, email, password_hash, role) 
	          VALUES ($1, $2, $3, $4, $5) RETURNING id`

	err = r.db.QueryRow(ctx, query, u.FirstName, u.LastName, u.Email, u.PasswordHash, u.Role).Scan(&u.ID)
	if err != nil {
		return err
	}

	return nil
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

	query := `SELECT id, first_name, last_name, email, password_hash, role FROM users WHERE email = $1`

	var u User

	err := r.db.QueryRow(ctx, query, email).Scan(&u.ID, &u.FirstName, &u.LastName, &u.Email, &u.PasswordHash, &u.Role)
	if err != nil {
		return nil, err
	}

	return &u, nil
}
