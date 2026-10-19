package messages

const (
	InvalidCredentials = "Неверные данные авторизации (email или пароль)"

	Unauthorized            = "Не авторизован"
	AuthorizationRequired   = "Необходима авторизация для получения доступа"
	InsufficientPermissions = "Недостаточно прав"

	FailedToIssueTokens = "Не удалось выпустить токены"
	InvalidSubjectToken = "Недопустимый токен субъекта"

	MissingRefreshTokenCookie    = "Отсутствует cookie-файл токена обновления"
	InvalidOrExpiredRefreshToken = "Недействительный или просроченный токен обновления"
	RevokedOrUnknownRefreshToken = "Токен обновления отозван или неизвестен"

	InvalidAdminToken = "Токен регистрации администратора не передан, либо является недействительным"
)
