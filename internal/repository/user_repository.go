package repository

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
)

// User представляет сущность пользователя (дублируем или импортируем из handlers/domain)
// Для простоты оставим структуру здесь, но в больших проектах она выносится в пакет `domain` или `models`.
type User struct {
	ID        int    `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Email     string `json:"email"`
}

// UserRepository определяет контракт для работы с пользователями в БД.
// Использование интерфейса позволяет легко подменить БД на мок (mock) при тестировании.
type UserRepository interface {
	GetAll(ctx context.Context) ([]User, error)
	Create(ctx context.Context, u *User) error
	Delete(ctx context.Context, id int) (bool, error) // возвращает true, если строка была удалена
}

type postgresUserRepository struct {
	db *pgxpool.Pool
}

// NewUserRepository создает новый экземпляр репозитория
func NewUserRepository(db *pgxpool.Pool) UserRepository {
	return &postgresUserRepository{db: db}
}

func (r *postgresUserRepository) GetAll(ctx context.Context) ([]User, error) {
	query := `SELECT id, first_name, last_name, email FROM users ORDER BY id DESC LIMIT 50`
	rows, err := r.db.Query(ctx, query)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var users []User
	for rows.Next() {
		var u User
		if err := rows.Scan(&u.ID, &u.FirstName, &u.LastName, &u.Email); err != nil {
			return nil, err
		}
		users = append(users, u)
	}

	// КРИТИЧЕСКИ ВАЖНО: проверяем ошибки, возникшие во время итерации
	if err = rows.Err(); err != nil {
		return nil, err
	}

	// Если пользователей нет, возвращаем пустой слайс, а не nil (лучшая практика для JSON)
	if users == nil {
		users = []User{}
	}

	return users, nil
}

func (r *postgresUserRepository) Create(ctx context.Context, u *User) error {
	query := `INSERT INTO users (first_name, last_name, email) VALUES ($1, $2, $3) RETURNING id`

	err := r.db.QueryRow(ctx, query, u.FirstName, u.LastName, u.Email).Scan(&u.ID)
	if err != nil {
		// Здесь можно добавить проверку на pgx.ErrNoRows или специфичные коды ошибок PostgreSQL (например, уникальный email)
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
