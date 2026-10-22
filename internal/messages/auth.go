package messages

const (
	InvalidCredentials = "Неверные данные авторизации (email или пароль)"

	Unauthorized              = "Не авторизован"
	AuthenticationUnavailable = "Проверка авторизации временно недоступна"
	AuthorizationRequired     = "Необходима авторизация для получения доступа"
	InsufficientPermissions   = "Недостаточно прав"

	FailedToIssueTokens         = "Не удалось выпустить токены"
	FailedToRevokeRefreshToken  = "Не удалось завершить сессию. Повторите попытку позже"
	InvalidSubjectToken         = "Недопустимый токен субъекта"
	InvalidOrExpiredAccessToken = "Недействительный или просроченный токен доступа"

	MissingRefreshTokenCookie    = "Отсутствует cookie-файл токена обновления"
	InvalidOrExpiredRefreshToken = "Недействительный или просроченный токен обновления"
	RevokedOrUnknownRefreshToken = "Токен обновления отозван или неизвестен"

	InvalidAdminToken = "Токен регистрации администратора не передан, либо является недействительным"
)
