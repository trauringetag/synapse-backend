package handler

// Тонкий HTTP-слой аутентификации: обработчики только декодируют запрос,
// вызывают метод use-case (internal/usecase) и формируют HTTP-ответ.
// Вся бизнес-логика — валидация, bcrypt, JWT-ротация, CSRF, проверка ролей
// и статусов — перенесена в слой use-case. Ошибки маппятся через
// respondError/handleUseCaseError (errors.go).

import (
	"net/http"

	"github.com/trauringetag/synapse-backend/internal/delivery/http/response"
	"github.com/trauringetag/synapse-backend/internal/domain"
	"github.com/trauringetag/synapse-backend/internal/infrastructure/config"
	auth "github.com/trauringetag/synapse-backend/internal/infrastructure/security"
	"github.com/trauringetag/synapse-backend/internal/messages"
	"github.com/trauringetag/synapse-backend/internal/usecase"
)

// AuthHandler — тонкий HTTP-обработчик поверх usecase.AuthUseCase.
// Хранит cfg только как транспортную деталь: конфигурация cookie
// (Secure/SameSite/Path) нужна при установке cookie из DTO use-case.
// UserStore/TokenStore и бизнес-логика сюда больше не передаются.
type AuthHandler struct {
	cfg *config.Config
	uc  usecase.AuthUseCase
}

func NewAuthHandler(cfg *config.Config, uc usecase.AuthUseCase) *AuthHandler {
	return &AuthHandler{cfg: cfg, uc: uc}
}

// registerRequest — тело POST /register и POST /register-admin.
type registerRequest struct {
	Email     string `json:"email"`
	Password  string `json:"password"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
}

type loginRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type messageResponse struct {
	Message string `json:"message"`
}

// registeredResponse — ответ веб-клиента: сообщение + профиль.
// Токенов в теле нет (риск XSS): веб-клиент входит отдельно через /login.
type registeredResponse struct {
	Message string       `json:"message"`
	User    *domain.User `json:"user"`
}

// respondRegister — общий вывод ответа регистрации для обоих форматов:
//   - X-Client-Platform: mobile -> пользователь сразу входит, токены в
//     JSON-теле (cookie НЕ ставятся);
//   - web (включая отсутствие заголовка — обратная совместимость) -> только
//     профиль пользователя, сессия выпускается на /login.
func (h *AuthHandler) respondRegister(w http.ResponseWriter, r *http.Request, res *usecase.SessionResult, status int) {
	if isMobilePlatform(r) && res.Pair != nil {
		response.JSON(w, status, newTokenResponse(res.Pair, res.User))
		return
	}
	response.JSON(w, status, registeredResponse{Message: messages.RegistrationSuccessful, User: res.User})
}

func (h *AuthHandler) Register(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := response.Decode(r, &req); err != nil {
		response.DecodeError(w, err)
		return
	}
	res, err := h.uc.Register(r.Context(), usecase.RegisterInput{
		Email:     req.Email,
		Password:  req.Password,
		FirstName: req.FirstName,
		LastName:  req.LastName,
	}, isMobilePlatform(r))
	if err != nil {
		respondError(w, err)
		return
	}
	h.respondRegister(w, r, res, http.StatusCreated)
}

func (h *AuthHandler) RegisterAdmin(w http.ResponseWriter, r *http.Request) {
	var req registerRequest
	if err := response.Decode(r, &req); err != nil {
		response.DecodeError(w, err)
		return
	}
	res, err := h.uc.RegisterAdmin(r.Context(), usecase.RegisterInput{
		Email:      req.Email,
		Password:   req.Password,
		FirstName:  req.FirstName,
		LastName:   req.LastName,
		AdminToken: r.Header.Get("X-Admin-Token"),
	}, isMobilePlatform(r))
	if err != nil {
		respondError(w, err)
		return
	}
	h.respondRegister(w, r, res, http.StatusCreated)
}

func (h *AuthHandler) Login(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := response.Decode(r, &req); err != nil {
		response.DecodeError(w, err)
		return
	}
	res, err := h.uc.Login(r.Context(), usecase.LoginInput{Email: req.Email, Password: req.Password})
	if err != nil {
		respondError(w, err)
		return
	}

	// Формат ответа определяется X-Client-Platform (только формат, не безопасность).
	if isMobilePlatform(r) {
		// Мобильный / серверный клиент: токены в теле, cookie НЕ ставим.
		response.JSON(w, http.StatusOK, newTokenResponse(res.Pair, res.User))
		return
	}

	// Веб-клиент (включая отсутствие заголовка — обратная совместимость):
	// HttpOnly cookie, токенов в теле НЕТ (риск XSS).
	setTokenCookies(w, h.cfg, res.Pair)
	response.JSON(w, http.StatusOK, loginResponse{
		Message: messages.AuthorizationSuccessful,
		User:    res.User,
	})
}

func (h *AuthHandler) Refresh(w http.ResponseWriter, r *http.Request) {
	// Вход: cookie refresh_token (веб) ИЛИ Authorization: Bearer <refresh>
	// (мобильные) ИЛИ {"refresh_token": "..."} в теле (альтернатива для
	// мобильных). Приоритет источников фиксирован, смешивание исключено.
	raw, _ := refreshCredential(r)
	mobile := isMobilePlatform(r)

	res, err := h.uc.Refresh(r.Context(), usecase.RefreshInput{RawRefreshToken: raw})
	if err != nil {
		// Внутренняя ошибка ротации: auth-cookie сбрасываются только
		// веб-клиентам (мобильный клиент без cookie получает чистый JSON-ответ).
		if res != nil && res.ClearCookies && !mobile {
			auth.ClearTokenCookies(w, h.cfg)
		}
		respondError(w, err)
		return
	}
	if res.Pair == nil {
		// Use-case классифицировал ротацию как отказ (просрочен/отозван/replay).
		if !mobile {
			auth.ClearTokenCookies(w, h.cfg)
		}
		response.Error(w, http.StatusUnauthorized, messages.InvalidOrExpiredRefreshToken, nil)
		return
	}

	if mobile {
		// Мобильный клиент: новые токены в JSON-теле, cookie НЕ ставятся.
		// ВАЖНО: ротация атомарна, старый refresh отозван — клиент обязан
		// перезаписать ОБА токена, иначе повторная отправка старого refresh
		// приведёт к replay-детекту и отзыву всех сессий.
		response.JSON(w, http.StatusOK, newTokenResponse(res.Pair, nil))
		return
	}

	setTokenCookies(w, h.cfg, res.Pair)
	response.JSON(w, http.StatusOK, messageResponse{Message: messages.TokensRefreshed})
}

func (h *AuthHandler) Logout(w http.ResponseWriter, r *http.Request) {
	// Для мобильных refresh-токен принимается из Bearer или JSON-тела
	// ({"refresh_token": "..."}), поскольку cookie нет. Если токен отсутствует —
	// logout всё равно возвращает 200, но сессия в БД не отзывается.
	raw, hasToken := refreshCredential(r)
	mobile := isMobilePlatform(r)

	if err := h.uc.Logout(r.Context(), usecase.LogoutInput{
		RawRefreshToken: raw,
		HasCookie:       hasToken,
	}); err != nil {
		if !mobile {
			auth.ClearTokenCookies(w, h.cfg)
		}
		respondError(w, err)
		return
	}
	if !mobile {
		auth.ClearTokenCookies(w, h.cfg)
	}
	response.JSON(w, http.StatusOK, messageResponse{Message: messages.LoggedOut})
}

func (h *AuthHandler) CSRFToken(w http.ResponseWriter, r *http.Request) {
	res, err := h.uc.IssueCSRF()
	if err != nil {
		respondError(w, err)
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name:     "csrf_token",
		Value:    res.Token,
		Path:     "/api/v1/",
		Secure:   h.cfg.CookieSecure,
		HttpOnly: false,
		SameSite: h.cfg.CookieSameSite,
		MaxAge:   3600,
	})
	response.JSON(w, http.StatusOK, map[string]string{"csrf_token": res.Token})
}

// setTokenCookies — единственный мост между DTO слоя use-case (usecase.TokenPair)
// и инфраструктурным форматом cookie (auth.Pair). Это деталь транспорта,
// поэтому живёт в HTTP-слое.
func setTokenCookies(w http.ResponseWriter, cfg *config.Config, pair *usecase.TokenPair) {
	if pair == nil {
		return
	}
	auth.SetTokenCookies(w, cfg, &auth.Pair{
		AccessToken:  pair.AccessToken,
		RefreshToken: pair.RefreshToken,
		AccessExp:    pair.AccessExp,
		RefreshExp:   pair.RefreshExp,
	})
}
