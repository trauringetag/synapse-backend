package messages

const (
	UserNotFound         = "Пользователь не найден"
	FailedToCreateUser   = "Не удалось создать пользователя"
	FailedToGetUser      = "Не удалось получить пользователя"
	FailedToGetUsersList = "Не удалось получить список пользователей"
	FailedToUpdateUser   = "Не удалось обновить пользователя"
	FailedToDeleteUser   = "Не удалось удалить пользователя"

	InvalidUserID          = "Неверный идентификатор пользователя"
	EmptyUpdateData        = "Пустые данные обновления"
	SpecifyAtLeastOneField = "Укажите хотя бы одно поле"

	AdminCannotDeleteSelf    = "Администратор не может удалить собственную учетную запись"
	CannotDeleteAdminAccount = "Нельзя удалить учетную запись администратора"

	// Сообщения сценария самоудаления (DELETE /users/me, hard delete аккаунта).
	AccountAlreadyInactive = "Учетная запись уже деактивирована"
)
