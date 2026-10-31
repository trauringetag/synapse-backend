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
	InvalidOrExpiredAccessToken = "Недействительный или просроченный Access-токен"

	MissingRefreshTokenCookie    = "Отсутствует Cookie-файл Refresh-токена"
	InvalidOrExpiredRefreshToken = "Недействительный или просроченный Refresh-токен"
	RevokedOrUnknownRefreshToken = "Refresh-токен отозван или неизвестен"

	// MixedCredentialsNotAllowed — запрос содержит одновременно auth-cookie и
	// Authorization: Bearer (или refresh_token в теле). Контрактом разрешён
	// ровно один источник credentials: смешивание исключает неоднозначность
	// формата ответа и блокирует эксфильтрацию cookie-сессии в мобильный
	// JSON-формат через подмену X-Client-Platform.
	MixedCredentialsNotAllowed = "Одновременное использование Cookie и Authorization заголовка не допускается"

	InvalidAdminToken = "Доступ к данному контуру ограничен"

	UnexpectedSigningMethod = "Неожиданный метод подписания"
	InvalidToken            = "Недопустимый токен"
	InvalidTokenPurpose     = "Недопустимое назначение токена"

	FailedToPrepareCSRFProtection = "Не удалось подготовить CSRF-защиту запроса"
)
