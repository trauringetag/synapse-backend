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

func Error(w http.ResponseWriter, status int, msg string) {
	title := "Request Failed"
	switch status {
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		title = "Validation Failed"
	case http.StatusUnauthorized:
		title = "Unauthorized"
	case http.StatusForbidden:
		title = "Forbidden"
	case http.StatusNotFound:
		title = "Not Found"
	case http.StatusConflict:
		title = "Conflict"
	case http.StatusInternalServerError:
		title = "Internal Server Error"
	}
	JSON(w, status, ErrorBody{Error: title, Message: msg})
}

func ValidationError(w http.ResponseWriter, status int, msg string, details map[string][]string) {
	JSON(w, status, ErrorBody{Error: "Validation Failed", Message: msg, Details: details})
}

func Decode(r *http.Request, dst any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(dst)
}
