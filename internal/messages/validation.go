package messages

const (
	InvalidEmail     = "Укажите действительный email"
	EmailAlreadyUsed = "Email уже используется"

	PasswordTooShort = "Пароль должен содержать не менее 8 символов (либо была зафиксирована попытка ввести слишком длинный пароль)"

	FirstNameRequired = "Имя обязательно для заполнения"
	LastNameRequired  = "Фамилия обязательна для заполнения"

	CheckRequiredFields = "Проверьте обязательные поля пользователя"

	RoleInvalidValue   = "Допустимые значения: user, admin"
	StatusInvalidValue = "Допустимые значения: active, inactive"
)
