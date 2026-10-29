package usecase

// PasswordHasher - порт для хеширования паролей.
// Реализация (например, на базе bcrypt) находится в инфраструктурном слое
// (internal/infrastructure/security.BcryptHasher), что соблюдает Dependency
// Rule Clean Architecture: внутренний круг (Use Case) не зависит от внешних
// библиотек и фреймворков.
type PasswordHasher interface {
	// Hash хеширует пароль и возвращает строковое представление хеша
	Hash(password string) (string, error)
	// Compare сравнивает пароль с хешем. Возвращает ошибку при несовпадении.
	Compare(hash, password string) error
}
