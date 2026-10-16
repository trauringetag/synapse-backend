# Synapse REST API (Go + PostgreSQL)

Бэкенд REST API с регистрацией пользователей, аутентификацией через JWT в **HttpOnly Cookie** (access + refresh-токены) и управлением доступом на основе ролей (`user` / `admin`).

## Требования

- Docker и Docker Compose **/** Go 1.23+ и PostgreSQL 16
- Файл `.env` (скопируйте из `.env.example`)

## Настройте `.env`

```bash
cp .env.example .env
```

| Переменная | Задача |
|---|---|
| `DATABASE_URL` / `POSTGRES_*` | Подключение к PostgreSQL |
| `JWT_SECRET` | Секретный ключ HMAC для JWT-токенов доступа и обновления |
| `ACCESS_TOKEN_TTL` | Короткий срок действия токена доступа (по умолчанию — `15 мин.`) |
| `REFRESH_TOKEN_TTL` | Длительный срок действия токена обновления (по умолчанию `168 ч` = 7 дней) |
| `ADMIN_REGISTER_TOKEN` | Для вызова `POST /api/v1/register-admin` требуется секретный ключ |
| `COOKIE_SECURE` | В рабочей среде должно быть установлено значение `true` (только HTTPS). Для локальной среды (HTTP) используйте `false`. |
| `COOKIE_SAMESITE` | `Lax` (рекомендуется) или `Strict` |
| `CORS_ORIGINS` | Источники (origins) фронтенда, разделенные запятыми. Передача учётных данных (credentials) включена всегда. |
| `API_HOST_PORT` | Порт хоста, который открывает Docker (по умолчанию `8080`) |

При установленном значении `COOKIE_SECURE=true` файлы Cookie всегда создаются с параметрами `HttpOnly`, `Path=/api/v1/`, `SameSite` и `Secure`.

## Запуск с помощью Docker Compose

```bash
docker compose up --build
```

- API: http://localhost:8080
- Swagger UI: http://localhost:8080/docs
- OpenAPI: http://localhost:8080/openapi.yaml
- PostgreSQL: http://localhost:5432

Таблицы схемы (`users`, `refresh_tokens`) создаются автоматически при запуске.

## Запуск локально (Без Docker для API)

1. Запустите PostgreSQL (или `docker compose up postgres`).
2. Укажите `localhost` в качестве значения `DATABASE_URL` вместо `postgres`.
3. Запустить:

```bash
go run ./cmd/api
```

## Версионирование API

Все конечные точки для бизнес-процессов находятся в каталоге `/api/v1/`.

### Авторизация (Отсутствует Cookie доступа)

| Метод | Путь | Примечания |
|---|---|---|
| `POST` | `/api/v1/register` | Создаёт роль `user` |
| `POST` | `/api/v1/register-admin` | Заголовок `X-Admin-Token` или JSON-поле `admin_token` |
| `POST` | `/api/v1/login` | Устанавливает файлы cookie `access_token` и `refresh_token` |
| `POST` | `/api/v1/refresh` | **Требуется `refresh_token` Cookie**; Обновляет оба файла Cookie |
| `POST` | `/api/v1/logout` | Удаляет файлы Cookie и вносит токен обновления (refresh token) в черный список в PostgreSQL |

### Пользователи (Требуется файл Cookie `access_token`)

| Метод | Путь | Роли |
|---|---|---|
| `GET` | `/api/v1/users/me` | `user`, `admin` |
| `GET` | `/api/v1/users` | `admin` |
| `GET` | `/api/v1/users/{id}` | `admin` |
| `PUT` | `/api/v1/users/{id}` | `admin` (полная замена) |
| `PATCH` | `/api/v1/users/{id}` | `admin` (частичное обновление) |
| `DELETE` | `/api/v1/users/{id}` | `admin` |

Swagger документирует требования к файлам Cookie для каждой защищенной операции (`cookieAuth` / `refreshCookie`).

## Пример (curl)

Зарегистрируйтесь и войдите в систему. Файлы Cookie сохраняются в `cookies.txt` (HttpOnly; браузеры делают это автоматически).

```bash
curl -s -c cookies.txt -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "secret123", "name": "Пользователь"}' \
  http://localhost:8080/api/v1/register

curl -s -c cookies.txt -b cookies.txt -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "password": "secret123"}' \
  http://localhost:8080/api/v1/login

curl -s -b cookies.txt http://localhost:8080/api/v1/users/me
```

Регистрация администратора:

```bash
curl -s -H "Content-Type: application/json" -H "X-Admin-Token: dev-admin-register-token" \
  -d '{"email": "admin@example.com", "password": "secret123", "name":"Администратор"}' \
  http://localhost:8080/api/v1/register-admin
```

## Frontend / CORS

Токены невозможно прочитать из JavaScript. Браузер должен отправлять файлы Cookie:

```js
fetch("http://localhost:8080/api/v1/users/me", { credentials: "include" });
```

API устанавливает заголовок `Access-Control-Allow-Credentials: true` и разрешает запросы только от источников, перечисленных в `CORS_ORIGINS` (использование `*` исключено).

## Заметки о REST

- **Stateless:** сервер не хранит сессии; каждый запрос содержит файлы Cookie или JWT.
- **Кэшируемость:** Ответы `/api/v1` содержат заголовок `Cache-Control: no-store` (JSON-данные аутентификации и заголовок `Set-Cookie` не должны кэшироваться). Ресурсы `/docs` и `/openapi.yaml` доступны для кэширования.
- **Многослойность:** стандартный HTTP; балансировщики нагрузки / прокси-серверы работают при условии, что они передают дальше заголовки `Cookie` и `Set-Cookie`.
- **Logout:** срок действия файлов Cookie истекает немедленно, а хеш токена обновления (refresh token) помечается в PostgreSQL как «отозванный» (`revoked`).

## Безопасность

Не добавляйте в репозиторий файл `.env`, предназначенный для рабочей среды. Обновите значения `JWT_SECRET` и `ADMIN_REGISTER_TOKEN`. При использовании HTTPS включите параметр `COOKIE_SECURE=true`.