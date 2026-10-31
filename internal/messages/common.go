package messages

const (
	InvalidJSONBody = "Некорректное тело JSON"

	RequestEntityTooLarge = "Размер тела запроса превышает допустимый лимит"

	FailedToHashPassword = "Не удалось хешировать пароль"

	TokensRefreshed         = "Токены обновлены"
	LoggedOut               = "Вышли из системы"
	AuthorizationSuccessful = "Авторизация успешна"
	RegistrationSuccessful  = "Регистрация успешна"

	InvalidOrigin      = "Недопустимый Origin"
	InvalidCSRFToken   = "Недействительный CSRF-токен"
	MultipleJSONValues = "Несколько значений JSON"
)
