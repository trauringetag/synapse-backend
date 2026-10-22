package httputil

import (
	"encoding/json"
	"net/http"
)

type ErrorBody struct {
	Error   string              `json:"error"`
	Message string              `json:"message"`
	Details map[string][]string `json:"details,omitempty"`
}

func JSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func Error(w http.ResponseWriter, status int, msg string, details map[string][]string) {
	title := "REQUEST_FAILED"
	switch status {
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		title = "VALIDATION_FAILED"
	case http.StatusUnauthorized:
		title = "UNAUTHORIZED"
	case http.StatusForbidden:
		title = "FORBIDDEN"
	case http.StatusNotFound:
		title = "NOT_FOUND"
	case http.StatusConflict:
		title = "CONFLICT"
	case http.StatusInternalServerError:
		title = "INTERNAL_SERVER_ERROR"
	case http.StatusServiceUnavailable:
		title = "SERVICE_UNAVAILABLE"
	}

	JSON(w, status, ErrorBody{
		Error:   title,
		Message: msg,
		Details: details,
	})
}

func Decode(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}
