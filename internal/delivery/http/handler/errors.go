package handler

import (
	"errors"
	"net/http"

	"github.com/trauringetag/synapse-backend/internal/delivery/http/response"
	"github.com/trauringetag/synapse-backend/internal/domain"
	"github.com/trauringetag/synapse-backend/internal/messages"
	"github.com/trauringetag/synapse-backend/internal/usecase"
)

// respondError — единая точка преобразования ошибок в HTTP-ответ.
//
// Тонкий HTTP-слой не знает бизнес-правил: он получает *usecase.UseCaseError,
// у которой код ошибки уже классифицирован слоем use-case, и отображает его
// на HTTP-статус + сообщение + детали валидации по полям.
//
// Если ошибка не является UseCaseError (например, доменный sentinel, возникший
// вне слоя use-case), применяется запасное отображение domain-ошибок.
func respondError(w http.ResponseWriter, err error) {
	if ucErr, ok := usecase.AsUseCaseError(err); ok {
		response.Error(w, ucErr.Code.HTTPStatus(), ucErr.Message, ucErr.Details)
		return
	}
	switch {
	case errors.Is(err, domain.ErrNotFound):
		response.Error(w, http.StatusNotFound, messages.UserNotFound, nil)
	case errors.Is(err, domain.ErrConflict):
		response.Error(w, http.StatusConflict, messages.EmailAlreadyUsed, nil)
	default:
		response.Error(w, http.StatusInternalServerError, messages.FailedToGetUser, nil)
	}
}
