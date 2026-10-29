package handler

import (
	"errors"
	"net/http"

	"github.com/trauringetag/synapse-backend/internal/delivery/http/response"
	"github.com/trauringetag/synapse-backend/internal/domain"
	"github.com/trauringetag/synapse-backend/internal/messages"
	"github.com/trauringetag/synapse-backend/internal/usecase"
)

// handleUseCaseError — helper для маппинга ошибок слоя use-case на HTTP-ответ.
//
// Тонкий HTTP-слой не знает бизнес-правил: он получает *usecase.UseCaseError,
// у которой код ошибки уже классифицирован слоем use-case (Code), и отображает
// её на HTTP-статус (через ErrorCode.HTTPStatus) + сообщение + детали
// валидации по полям (Details).
//
// Возвращает true, если ошибка является *usecase.UseCaseError и ответ сформирован.
func handleUseCaseError(w http.ResponseWriter, err error) bool {
	ucErr, ok := usecase.AsUseCaseError(err)
	if !ok {
		return false
	}
	response.Error(w, ucErr.Code.HTTPStatus(), ucErr.Message, ucErr.Details)
	return true
}

// respondError — единая точка преобразования ошибок в HTTP-ответ.
//
// Сначала применяется helper handleUseCaseError (основной путь для тонких
// handlers). Если ошибка не является UseCaseError (например, доменный
// sentinel, возникший вне слоя use-case), применяется запасное отображение
// domain-ошибок.
func respondError(w http.ResponseWriter, err error) {
	if handleUseCaseError(w, err) {
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
