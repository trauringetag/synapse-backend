package auth

import (
	"golang.org/x/crypto/bcrypt"

	"github.com/trauringetag/synapse-backend/internal/usecase"
)

// BcryptHasher — инфраструктурная реализация порта usecase.PasswordHasher
// на базе внешней библиотеки golang.org/x/crypto/bcrypt. Пакет имеет имя
// auth (package auth), хотя каталог называется security — так исторически
// объявлены все файлы этого пакета. Благодаря этому слою-адаптеру слой
// use-case не импортирует bcrypt напрямую и соблюдается
// Dependency Rule Clean Architecture: зависимости направлены внутрь, к
// абстракциям (портам), а не к конкретным реализациям.
type BcryptHasher struct{}

// NewBcryptHasher создает новый экземпляр хешерa паролей на базе bcrypt.
func NewBcryptHasher() *BcryptHasher {
	return &BcryptHasher{}
}

// Проверка реализации порта на этапе компиляции.
var _ usecase.PasswordHasher = (*BcryptHasher)(nil)

// Hash хеширует пароль с боевой стоимостью bcrypt (DefaultCost) и возвращает
// строковое представление хеша.
func (h *BcryptHasher) Hash(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// Compare сравнивает открытый пароль с сохраненным bcrypt-хешем.
// Возвращает ошибку, если пароль не совпадает с хешем.
func (h *BcryptHasher) Compare(hash, password string) error {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
}
