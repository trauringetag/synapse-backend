# Synapse Backend

Go REST API (HTTP-сервер на `chi`) с PostgreSQL для регистрации, аутентификации и
ролевого управления пользователями. Актуальная версия — **1.0.29.2**.

- Модуль: `github.com/trauringetag/synapse-backend`
- Go: **1.23** (`go.mod`: `go 1.23.0`, Dockerfile: `golang:1.23-alpine`)
- HTTP: `github.com/go-chi/chi/v5` + `github.com/go-chi/cors`
- JWT: `github.com/golang-jwt/jwt/v5` (только HS256)
- Пароли: `golang.org/x/crypto/bcrypt` (`bcrypt.DefaultCost`)
- БД: `github.com/jackc/pgx/v5` (`pgxpool`, пул 10 соединений)
- Конфигурация: переменные окружения + `.env` через `github.com/joho/godotenv`
- OpenAPI-спецификация встроена в бинарник директивой `//go:embed` (`docs/embed.go`)

Полная машинночитаемая документация API — в `docs/openapi.yaml`; она же доступна из
запущенного сервиса (`GET /openapi.yaml`, интерфейс `GET /docs`).

---

## Содержание

1. [Быстрый старт](#быстрый-старт)
2. [Требования и установка](#требования-и-установка)
3. [Конфигурация (переменные окружения)](#конфигурация-переменные-окружения)
4. [Запуск и управление сервисом](#запуск-и-управление-сервисом)
5. [Схема базы данных и миграция](#схема-базы-данных-и-миграция)
6. [Модель доступа](#модель-доступа)
7. [REST API](#rest-api)
8. [Формат ошибок и словарь сообщений](#формат-ошибок-и-словарь-сообщений)
9. [Безопасность](#безопасность)
10. [Ограничение частоты запросов](#ограничение-частоты-запросов)
11. [Структура проекта](#структура-проекта)
12. [Тесты, сборка, CI и релизы](#тесты-сборка-ci-и-релизы)
13. [Эксплуатационные ограничения](#эксплуатационные-ограничения)
14. [Что изменилось относительно предыдущей документации](#что-изменилось-относительно-предыдущей-документации)

---

## Быстрый старт

```bash
git clone <repository-url> synapse-backend
cd synapse-backend

cp .env.example .env
# обязательно отредактируйте .env: JWT_SECRET (>= 32 символов) и ADMIN_REGISTER_TOKEN
${EDITOR:-nano} .env

docker compose up --build -d          # postgres + api
curl http://localhost:8080/health     # -> {"status":"OK"}
```

Документация: `http://localhost:8080/docs` (Swagger UI), спецификация —
`http://localhost:8080/openapi.yaml`. Корневой путь `GET /` выполняет редирект `301` на `/docs`.

Первый администратор создаётся через `POST /api/v1/register-admin` с заголовком
`X-Admin-Token` (значение `ADMIN_REGISTER_TOKEN`); предзаполнения админа в SQL нет.

---

## Требования и установка

| Компонент                  | Версия           | Комментарий                                                           |
| -------------------------- | ---------------- | --------------------------------------------------------------------- |
| Go                         | 1.23+            | требуется для локального запуска и unit-тестов                        |
| Docker Engine + Compose v2 | любая актуальная | `docker compose` (с дефисом), образ `postgres:16-alpine`              |
| PostgreSQL                 | 16               | нужен `pgcrypto` (`gen_random_uuid()`) и `to_tsvector('simple', ...)` |
| curl / jq                  | —                | удобно для ручных проверок                                            |

Проверка окружения:

```bash
go version            # go version go1.23.x linux/amd64
docker compose version
```

Зависимости Go фиксируются в `go.mod` / `go.sum`; при изменении зависимостей
выполните `make tidy` (`go mod tidy`).

---

## Конфигурация (переменные окружения)

Приложение читает конфигурацию в `internal/infrastructure/config/config.go`: сначала
`godotenv.Load()` загружает `.env` в текущем рабочем каталоге (если файл отсутствует —
это не ошибка), затем значения берутся из окружения. Переменные окружения имеют приоритет
над `.env`. Файл `.env` **не закомментирован** в `.gitignore` (секреты не должны попадать в git).

### Обязательные переменные (без них сервис не стартует)

| Переменная             | Требование                   | Ошибка запуска                                                                                                             |
| ---------------------- | ---------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| `JWT_SECRET`           | не менее 32 символов (HS256) | `Необходимо указать JWT_SECRET` / `JWT_SECRET должен содержать не менее 32 символов для безопасной работы алгоритма HS256` |
| `ADMIN_REGISTER_TOKEN` | непустая строка              | `Необходимо указать ADMIN_REGISTER_TOKEN`                                                                                  |

`ADMIN_REGISTER_TOKEN` сравнивается constant-time со значением заголовка `X-Admin-Token`
(пробелы по краям входного значения обрезаются). Валидация тела запроса выполняется
**до** проверки секрета, поэтому неверный секрет даёт `403`, а невалидные поля — `400`.

### HTTP и окружение

| Переменная      | По умолчанию      | Назначение                                                      |
| --------------- | ----------------- | --------------------------------------------------------------- |
| `APP_PORT`      | `8080`            | порт, который слушает процесс (`:APP_PORT`)                     |
| `APP_ENV`       | `synapse-backend` | метка окружения, пишется в стартовый лог                        |
| `API_HOST_PORT` | `8080`            | **только** docker-compose: порт хоста, проброшенный в контейнер |

В `docker-compose.yml` сервис `api` принудительно получает `APP_PORT=8080` внутри контейнера;
наружу публикуется `${API_HOST_PORT}:8080`.

### База данных

| Переменная          | По умолчанию               | Назначение                                           |
| ------------------- | -------------------------- | ---------------------------------------------------- |
| `DATABASE_URL`      | пусто → конструируется     | полный DSN pgx                                       |
| `POSTGRES_USER`     | `synapse-default-user`     | часть DSN и env контейнера postgres                  |
| `POSTGRES_PASSWORD` | `synapse-default-password` | часть DSN и env контейнера postgres                  |
| `POSTGRES_DB`       | `synapse-default-db`       | часть DSN и env контейнера postgres                  |
| `POSTGRES_HOST`     | `localhost`                | часть DSN (в compose переопределяется на `postgres`) |
| `POSTGRES_PORT`     | `5432`                     | часть DSN                                            |

Если `DATABASE_URL` пуст, DSN собирается как
`postgres://USER:PASSWORD@HOST:PORT/DB?sslmode=disable`.

Примеры:

```dotenv
# локальная отладка (БД на хосте)
DATABASE_URL=postgres://synapse-default-user:synapse-default-password@localhost:5432/synapse-default-db?sslmode=disable
# внутри docker compose (хост postgres)
DATABASE_URL=postgres://synapse-default-user:synapse-default-password@postgres:5432/synapse-default-db?sslmode=disable
```

Важно: в `.env.example` и `.env` в строке `DATABASE_URL` указаны имена
`synapse-backend` / `synapse-backend-db`, которые **не совпадают** со значениями
`POSTGRES_*` в том же файле. При запуске вне Docker используйте один согласованный DSN,
иначе подключение упадёт с `База данных: база данных не существует` или `password authentication failed`.
В docker-compose итоговый DSN всё равно пересобирается из `POSTGRES_USER/PASSWORD/DB`
(`DATABASE_URL` из `env_file` переопределяется блоком `environment`), поэтому там
несоответствие безопасно.

Пул соединений (`internal/infrastructure/database/db.go`): `MaxConns=10`, `MinConns=1`,
`MaxConnIdleTime=5m`, обязательный `Ping` при старте (30 секунд на весь контекст инициализации).
При старте выполняются идемпотентные DDL: `CREATE TABLE IF NOT EXISTS api_rate_limits (...)`
и `CREATE INDEX IF NOT EXISTS idx_api_rate_limits_updated ...`. Если эти DDL не выполнены —
запуск прерывается с `Не удалось подготовить Rate-limiter: ...`.

### JWT

| Переменная          | По умолчанию | Назначение                                                 |
| ------------------- | ------------ | ---------------------------------------------------------- |
| `ACCESS_TOKEN_TTL`  | `15m`        | срок access-токена (`exp`, `Max-Age` cookie)               |
| `REFRESH_TOKEN_TTL` | `168h`       | срок refresh-токена и записи в `refresh_tokens.expires_at` |

Значения парсятся `time.ParseDuration`; некорректный формат — ошибка конфигурации
(`ACCESS_TOKEN_TTL: ...`). Claims токена: `sub` (UUID пользователя), `jti` (случайный UUID),
`iat`, `exp`, `iss=synapse-backend`, `aud=["access"]` или `["refresh"]`, плюс `email` и `role`.
Разбор токена требует HS256, издателя, audience и наличия `exp` (`jwt.WithExpirationRequired`).

### Cookies и CORS

| Переменная        | По умолчанию            | Назначение                                           |
| ----------------- | ----------------------- | ---------------------------------------------------- |
| `COOKIE_SECURE`   | `true`                  | флаг `Secure`; значение `true` (ровно) включает флаг |
| `COOKIE_SAMESITE` | `Lax`                   | `Lax` / `Strict` / `None` (регистронезависимо)       |
| `COOKIE_DOMAIN`   | пусто                   | атрибут `Domain` (пусто — cookie для текущего хоста) |
| `CORS_ORIGINS`    | `http://localhost:3000` | allow-list источников через запятую                  |

Путь cookie жёстко задан в коде: `/api/v1/`. Для `COOKIE_SAMESITE=None` браузерам
требуется `COOKIE_SECURE=true` и HTTPS. Значение по умолчанию `COOKIE_SECURE=true`
совместимо с `http://localhost`, но не с доступом по `http://<IP-хоста>` — в таком
локальном сценарии временно ставьте `COOKIE_SECURE=false` (как в `.env.example`).

`CORS_ORIGINS` используется двояко: списком `AllowedOrigins` в `cors.Handler` **и** как
allow-list для CSRF/Origin-проверок. Сравнение точное (после `TrimSpace` и снятия
завершающего `/`), без wildcard.

### Лимиты запросов

| Переменная                 | По умолчанию | Окно применения                         |
| -------------------------- | ------------ | --------------------------------------- |
| `LOGIN_RATE_LIMIT`         | `10`         | 15 минут (IP+email) **и** 1 час (email) |
| `REGISTER_RATE_LIMIT`      | `10`         | 1 час (IP)                              |
| `REFRESH_RATE_LIMIT`       | `30`         | 1 минута (hash cookie / IP)             |
| `LOGOUT_RATE_LIMIT`        | `10`         | 1 минута (IP)                           |
| `AUTHENTICATED_RATE_LIMIT` | `600`        | 1 минута (user ID / IP)                 |

Значения меньше 1 или неразбираемые молча заменяются default (`intEnv`). Все окна —
fixed window, пороги считаются **запросами**, а не «неудачными попытками».

---

## Запуск и управление сервисом

### Вариант A. Docker Compose (рекомендуемый)

```bash
cp .env.example .env && ${EDITOR:-nano} .env   # JWT_SECRET, ADMIN_REGISTER_TOKEN
docker compose up --build -d                   # или make docker
```

Что происходит: поднимается `postgres:16-alpine` (том `pgdata`, порт `127.0.0.1:5432`),
после прохождения healthcheck стартует `api` (multi-stage build, финальный образ
`alpine:3.21`, пользователь `nobody`, `EXPOSE 8080`).

Полезные команды:

```bash
docker compose ps                              # статус и health
docker compose logs -f api                     # логи приложения
docker compose logs -f postgres
docker compose restart api                     # перезапуск без пересборки
docker compose up --build -d                   # пересборка образа после изменений кода
docker compose stop                            # остановить, сохранить данные
docker compose down                            # удалить контейнеры (том pgdata остаётся)
docker compose down -v                         # УДАЛИТЬ ТОМ С ДАННЫМИ БД
docker compose exec postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB"   # консоль БД
docker compose exec api wget -qO- http://127.0.0.1:8080/health
```

Healthcheck'и compose: для `postgres` — `pg_isready` (каждые 5 с, 10 попыток),
для `api` — `wget -qO- http://127.0.0.1:8080/health` (каждые 10 с, 10 попыток).
Образ содержит `wget` именно для этой цели.

### Вариант B. Локально с PostgreSQL в Docker

```bash
docker compose up -d postgres                  # только БД на localhost:5432
cp .env.example .env
${EDITOR:-nano} .env    # DATABASE_URL -> localhost, COOKIE_SECURE=false, CORS_ORIGINS -> ваш origin
go run ./cmd/api        # или make run
```

Для такого режима в `.env` раскомментируйте отладочный `DATABASE_URL`
(`...@localhost:5432/...`) и закомментируйте docker-вариант с хостом `postgres`.

### Вариант C. Полностью локально (системный PostgreSQL)

```bash
createdb synapse-default-db
psql -d synapse-default-db -f internal/infrastructure/database/init.sql
cp .env.example .env && ${EDITOR:-nano} .env
go run ./cmd/api
```

### Makefile

Цели: `run` (`go run ./cmd/api`), `tidy` (`go mod tidy`), `docker`
(`docker compose up --build -d`).

### Таймауты HTTP-сервера и graceful shutdown

`ReadHeaderTimeout=5s`, `ReadTimeout=15s`, `WriteTimeout=15s`, `IdleTimeout=60s`.
По сигналу `SIGINT`/`SIGTERM` вызывается `srv.Shutdown` с контекстом на 10 секунд,
затем `pool.Close()` (defer). Ин-flight запросы дожидаются завершения, новые соединения
перестают приниматься.

### Публикация за reverse proxy

Сервис не доверяет `X-Forwarded-For` глобально: в начале стека стоит `chimw.RealIP`,
который берёт адрес из этих заголовков **наивно**. Поэтому прокси обязан перезаписывать
`X-Forwarded-For`/`X-Real-IP` и быть единственным источником входа. Иначе ключи
rate-limiting (`ip:...`, `login:<IP>:...`) можно подделать, а `ClientIP` вернёт адрес прокси.
Дополнительно включите `COOKIE_SECURE=true` (HTTPS) и добавьте публичный origin в `CORS_ORIGINS`.
Заголовок `Strict-Transport-Security` отдаётся всегда, включая HTTP-ответы, — это особенность
приложения, а не прокси.

---

## Схема базы данных и миграция

Единственный источник схемы — `internal/infrastructure/database/init.sql`. Он монтируется в
контейнер postgres как `/docker-entrypoint-initdb.d/10-init.sql:ro` и применяется
**только при первой инициализации тома** (пустой каталог данных). Идемпотентность обеспечивается
через `IF NOT EXISTS` / `ADD COLUMN IF NOT EXISTS`.

Таблицы:

- `users` — `id UUID PK DEFAULT gen_random_uuid()`, `email VARCHAR(255) UNIQUE NOT NULL`,
  `password_hash TEXT NOT NULL`, `role VARCHAR(20) CHECK IN ('user','admin')`,
  `status VARCHAR(20) DEFAULT 'active' CHECK IN ('active','inactive')`,
  `first_name`/`last_name VARCHAR(255) NOT NULL`, `created_at`/`updated_at TIMESTAMPTZ`;
  индекс `idx_users_role_status (role, status)`.
- `refresh_tokens` — `id UUID PK`, `user_id UUID REFERENCES users(id) ON DELETE CASCADE`,
  `token_hash TEXT UNIQUE NOT NULL` (SHA-256 hex), `expires_at TIMESTAMPTZ`,
  `revoked BOOLEAN DEFAULT FALSE`, `created_at`; индексы `idx_refresh_tokens_user`,
  `idx_refresh_tokens_hash`.
- `api_rate_limits` — `bucket_key TEXT PK`, `window_start TIMESTAMPTZ`,
  `hits INTEGER CHECK (hits > 0)`, `updated_at`; индекс `idx_api_rate_limits_updated`.
  Создаётся и `init.sql`, и приложением при старте.

Отдельной таблицы blacklist access-токенов нет: досрочный отзыв короткоживущего access-токена
невозможен (см. [Эксплуатационные ограничения](#эксплуатационные-ограничения)).

Пересоздание схемы вручную (dev/staging!):

```bash
docker compose exec postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
  -f /docker-entrypoint-initdb.d/10-init.sql
# либо полностью пересоздать том (данные будут потеряны):
docker compose down -v && docker compose up --build -d
```

---

## Модель доступа

| Роль           | Возможности                                                                                                        |
| -------------- | ------------------------------------------------------------------------------------------------------------------ |
| аноним / гость | `POST /register`, `POST /register-admin` (с секретом), `POST /login`, `POST /refresh`, `POST /logout`, `GET /csrf` |
| `user`         | `GET/PUT/PATCH /users/me`                                                                                          |
| `admin`        | `GET/PUT/PATCH /users/me` + `GET/POST /users`, `GET/PUT/PATCH/DELETE /users/{id}`                                  |

- Роли — ровно два значения (`domain.RoleUser`, `domain.RoleAdmin`); статусы — `active`/`inactive`.
- Проверка роли выполняется middleware по **роли из БД**, а не из claim'ов токена, поэтому
  понижение/повышение роли действует немедленно, независимо от срока access-токена.
- Статус также проверяется в middleware: `inactive` или удалённый пользователь не проходит
  аутентификацию (`401 Не авторизован`).
- Пользователь не может изменить себе роль или статус (`PUT/PATCH /users/me` их не принимают).
- Роль существующего пользователя нельзя изменить ни `PUT`, ни `PATCH /users/{id}`
  (поле `role` игнорируется). Создание админа возможно только через `POST /users` (админом)
  или `POST /register-admin` (по секрету).
- Администратор не может удалить свою учётную запись (`403`), и любой аккаунт с ролью
  `admin` защищён от удаления (`403`, `domain.ErrProtected`).
- Вход разрешён только активным пользователям; неактивный пользователь не может обновить
  профиль через защищённые маршруты (middleware отклонит запрос).

---

## REST API

Базовый префикс — `/api/v1`. Все запросы и ответы — JSON в UTF-8; неизвестные поля в теле
отклоняются (`DisallowUnknownFields`), тело ограничено 1 MiB. Токены передаются **только**
в HttpOnly cookie `access_token` / `refresh_token` (`Path=/api/v1/`), заголовок
`Authorization` не используется. Изменяющие запросы требуют CSRF-пары
(cookie `csrf_token` + заголовок `X-CSRF-Token`) и разрешённого источника.

### Таблица маршрутов

| Метод   | Путь                     | Доступ                            | Успешный ответ                                      | Основные ошибки                       |
| ------- | ------------------------ | --------------------------------- | --------------------------------------------------- | ------------------------------------- |
| GET     | `/health`                | публично (вне `/api/v1`)          | `200 {"status":"OK"}`                               | —                                     |
| GET     | `/`                      | публично                          | `301` → `/docs`                                     | —                                     |
| GET     | `/docs`                  | публично                          | `200` HTML (Swagger UI)                             | —                                     |
| GET     | `/openapi.yaml`          | публично                          | `200` YAML                                          | —                                     |
| OPTIONS | `/api/v1/*`              | CORS preflight                    | `204`/`200` с CORS-заголовками                      | —                                     |
| GET     | `/api/v1/csrf`           | публично + Origin/Referer         | `200 {"csrf_token":"..."}` + cookie                 | `403`                                 |
| POST    | `/api/v1/register`       | публично + CSRF                   | `201 User`                                          | `400 403 409 413 429 500 503`         |
| POST    | `/api/v1/register-admin` | публично + CSRF + `X-Admin-Token` | `201 User`                                          | `400 403 409 413 429 500 503`         |
| POST    | `/api/v1/login`          | публично + CSRF                   | `200 {"message","user"}` + cookie                   | `400 401 403 413 429 500 503`         |
| POST    | `/api/v1/refresh`        | cookie `refresh_token` + CSRF     | `200 {"message":"Токены обновлены"}` + cookie       | `401 403 429 500 503`                 |
| POST    | `/api/v1/logout`         | публично + CSRF                   | `200 {"message":"Вышли из системы"}` + сброс cookie | `403 429 500 503`                     |
| GET     | `/api/v1/users/me`       | user, admin                       | `200 User`                                          | `401 404 429 500 503`                 |
| PUT     | `/api/v1/users/me`       | user, admin + CSRF                | `200 User`                                          | `400 401 403 404 409 413 429 500 503` |
| PATCH   | `/api/v1/users/me`       | user, admin + CSRF                | `200 User`                                          | `400 401 403 404 409 413 429 500 503` |
| GET     | `/api/v1/users`          | admin                             | `200 UserListResponse`                              | `400 401 403 429 500 503`             |
| POST    | `/api/v1/users`          | admin + CSRF                      | `201 User`                                          | `400 401 403 409 413 429 500 503`     |
| GET     | `/api/v1/users/{id}`     | admin                             | `200 User`                                          | `400 401 403 404 429 500 503`         |
| PUT     | `/api/v1/users/{id}`     | admin + CSRF                      | `200 User`                                          | `400 401 403 404 409 413 429 500 503` |
| PATCH   | `/api/v1/users/{id}`     | admin + CSRF                      | `200 User`                                          | `400 401 403 404 409 413 429 500 503` |
| DELETE  | `/api/v1/users/{id}`     | admin + CSRF                      | `204` без тела                                      | `400 401 403 404 413 429 500 503`     |

### Модель ответа `User`

```json
{
  "id": "5f0c7c2e-6b1a-4f3d-9a1d-2c7b6a5e4d31",
  "email": "ada@example.com",
  "role": "user",
  "status": "active",
  "first_name": "Ada",
  "last_name": "Lovelace",
  "created_at": "2026-01-01T00:00:00Z",
  "updated_at": "2026-01-01T00:00:00Z"
}
```

`password_hash` в JSON никогда не возвращается (`json:"-"`).

### Правила валидации полей

| Поле         | Правило                                                                  | Сообщение при ошибке                                                                                          |
| ------------ | ------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------- |
| `email`      | непустой, содержит `@`, ≤ 255 символов, нормализуется (trim + lowercase) | `Укажите действительный email`                                                                                |
| `password`   | от 8 и до 72 байт (лимит bcrypt)                                         | `Пароль должен содержать не менее 8 символов (либо была зафиксирована попытка ввести слишком длинный пароль)` |
| `first_name` | непустой после trim, ≤ 255                                               | `Имя обязательно для заполнения`                                                                              |
| `last_name`  | непустой после trim, ≤ 255                                               | `Фамилия обязательна для заполнения`                                                                          |
| `role`       | `user` или `admin` (регистронезависимо)                                  | `Допустимые значения: user, admin`                                                                            |
| `status`     | `active` или `inactive` (регистронезависимо)                             | `Допустимые значения: active, inactive`                                                                       |
| `page`       | целое ≥ 1, default `1`                                                   | `Значение должно быть положительным числом`                                                                   |
| `limit`      | целое 1..100, default `10`                                               | `Значение должно быть от 1 до 100`                                                                            |
| `search`     | ≤ 200 символов после trim                                                | `Недопустимое значение параметра`                                                                             |

Ошибки нескольких полей возвращаются вместе в `details`.

### GET /api/v1/csrf

Выдача CSRF-токена. Возвращает `{"csrf_token": "<nonce>.<HMAC-SHA256(nonce, JWT_SECRET)>"}`
и устанавливает cookie `csrf_token` (`Path=/api/v1/`, `Max-Age=3600`, `HttpOnly=false` —
намеренно читаемая из JS, `SameSite`/`Secure` по конфигурации). Маршрут защищён
`RequireAllowedOrigin`: обязателен `Origin` из `CORS_ORIGINS`; если `Origin` полностью
отсутствует, допускается origin из `Referer`. Оба варианта не подошли → `403 FORBIDDEN`
(`Недопустимый Origin`). Access/refresh-аутентификация не требуется, лимитер не применяется.

### POST /api/v1/register

Создаёт пользователя с ролью `user` и статусом `active`, пароль хешируется bcrypt.
Cookie не устанавливаются. Требуются CSRF и разрешённый Origin/Referer; лимитер —
10 запросов в час на IP.

```bash
CSRF=$(curl -s -X GET http://localhost:8080/api/v1/csrf \
  -H 'Origin: http://localhost:3000' -c jar.txt | jq -r .csrf_token)

curl -s -X POST http://localhost:8080/api/v1/register \
  -H 'Content-Type: application/json' -H "Origin: http://localhost:3000" \
  -H "X-CSRF-Token: $CSRF" -b jar.txt -c jar.txt \
  -d '{"email":"ada@example.com","password":"a-long-password","first_name":"Ada","last_name":"Lovelace"}'
```

Ответы: `201` + `User`; `400` (валидация/JSON); `403` (CSRF/Origin); `409` (`Email уже используется`);
`413`; `429`; `500` (`Не удалось хешировать пароль`, `Не удалось создать пользователя`);
`503` (ошибка хранилища лимитов).

### POST /api/v1/register-admin

Как `register`, но роль `admin` и обязателен заголовок `X-Admin-Token` = `ADMIN_REGISTER_TOKEN`.
Порядок проверок: сначала валидация полей (`400`), затем секрет (`403`,
`Доступ к данному контуру ограничен`). Секрет в JSON-теле не принимается.

```bash
curl -s -X POST http://localhost:8080/api/v1/register-admin \
  -H 'Content-Type: application/json' -H "Origin: http://localhost:3000" \
  -H "X-CSRF-Token: $CSRF" -H "X-Admin-Token: $ADMIN_REGISTER_TOKEN" \
  -b jar.txt -c jar.txt \
  -d '{"email":"root@example.com","password":"a-long-password","first_name":"Grace","last_name":"Hopper"}'
```

### POST /api/v1/login

Проверяет учётные данные (bcrypt, с защитой от timing-атак: при неизвестном/неактивном
пользователе сравнение выполняется с фиктивным хешем), убеждается что пользователь `active`,
выпускает JWT-пару и сохраняет SHA-256 хеш refresh-токена. При успехе — `Set-Cookie`
с `access_token` и `refresh_token` и тело:

```json
{ "message": "Авторизация успешна", "user": { "...": "User" } }
```

JWT в теле не возвращаются. Неверный пароль, неизвестный пользователь и неактивный
пользователь дают одинаковый `401 Неверные данные авторизации (email или пароль)`.
Дополнительные лимиты длины: `email` > 255 или `password` > 72 байт → `400`
(`Некорректное тело JSON`).

```bash
curl -s -X POST http://localhost:8080/api/v1/login \
  -H 'Content-Type: application/json' -H "Origin: http://localhost:3000" \
  -H "X-CSRF-Token: $CSRF" -b jar.txt -c auth-cookies.txt \
  -d '{"email":"ada@example.com","password":"a-long-password"}'
```

### POST /api/v1/refresh

Ротация пары токенов. **Требуется cookie `refresh_token`** (body не читается).
В транзакции: отзыв старого токена по хешу (`revoked = FALSE AND expires_at > NOW()`),
загрузка пользователя `FOR UPDATE`, проверка активности, выпуск новой пары, запись нового хеша.
При успехе — новая пара cookie и `{"message":"Токены обновлены"}`.

Отказ (пустая/невалидная/просроченная cookie, неизвестный хеш, replay, неактивный или
удалённый пользователь) → `401` **и всегда сброс auth-cookie**
(`Max-Age=-1`). Повторное использование отозванного токена дополнительно отзывает все
сессии пользователя и логируется как `security_event=refresh_token_reuse`.
Внутренняя ошибка ротации → `500 INTERNAL_SERVER_ERROR` (`Не удалось выпустить токены`) + сброс cookie.

```bash
curl -s -X POST http://localhost:8080/api/v1/refresh \
  -H "Origin: http://localhost:3000" -H "X-CSRF-Token: $CSRF" \
  -b auth-cookies.txt -c auth-cookies.txt
```

### POST /api/v1/logout

Очищает cookie `access_token` и `refresh_token`. Если cookie `refresh_token` присутствует,
отзывает токен в БД; **без cookie вызов всё равно завершается `200`** и ничего не отзывается.
Ошибка отзыва в БД → `500` (`Не удалось завершить сессию. Повторите попытку позже`),
cookie при этом всё равно очищаются.

### GET/PUT/PATCH /api/v1/users/me

- `GET` — профиль текущего пользователя из БД.
- `PUT` — полная замена профиля: обязательны `email`, `first_name`, `last_name`.
  Поля `password`, `role`, `status` в теле не принимаются → `400` (`Некорректное тело JSON`).
  `updated_at` меняется только при фактическом отличии значений.
- `PATCH` — частичное обновление тех же трёх полей; пустое тело → `400`
  (`Пустые данные обновления`, `details.body = ["Укажите хотя бы одно поле"]`).

Все три метода доступны ролям `user` и `admin`, действуют CSRF (для PUT/PATCH) и общий
лимитер авторизованных запросов.

```bash
curl -s -X PATCH http://localhost:8080/api/v1/users/me \
  -H 'Content-Type: application/json' -H "Origin: http://localhost:3000" \
  -H "X-CSRF-Token: $CSRF" -b auth-cookies.txt \
  -d '{"first_name":"Ada King"}'
```

### GET /api/v1/users (admin)

Пагинация и фильтры: `page` (default 1), `limit` (default 10, максимум 100),
`role`, `status`, `search`. Значения `role`/`status` нормализуются (trim + lowercase),
недопустимые → `400` (`Недопустимое значение параметра`). Сортировка — `created_at ASC`.
`search` ищет по `email ILIKE '%...%'`, `first_name`, `last_name`, комбинации
«имя фамилия» и полнотекстовому `to_tsvector('simple', ...)`.

```json
{
  "items": [ { "id": "...", "email": "ada@example.com", "role": "user", "status": "active", "first_name": "Ada", "last_name": "Lovelace", "created_at": "...", "updated_at": "..." } ],
  "page": 1,
  "limit": 10,
  "total": 1,
  "total_pages": 1
}
```

`total_pages = ceil(total / limit)`; при `total = 0` равен 0.

### POST /api/v1/users (admin)

Создание пользователя с указанной ролью (`user` по умолчанию; `admin` тоже разрешён —
контроль над этим полем означает контроль над привилегиями). Статус всегда `active`.
Ответ `201` + `User`; конфликт email → `409`.

### GET/PUT/PATCH/DELETE /api/v1/users/{id} (admin)

- `GET` — карточка пользователя; невалидный UUID → `400`
  (`Неверный идентификатор пользователя`), отсутствие → `404`.
- `PUT` — полная замена редактируемых полей: обязательны `email`, `password`,
  `first_name`, `last_name`, `status`. Принятое, но **игнорируемое** поле `role`.
  Хеш пароля перезаписывается всегда, сессии при этом **не** отзываются.
- `PATCH` — частичное обновление (`email`, `password`, `first_name`, `last_name`,
  `status`), минимум одно поле; `role` игнорируется. При смене пароля все
  refresh-токены пользователя отзываются (сбой отзыва логируется, ответ остаётся `200`).
- `DELETE` — `204` без тела; self-delete → `403`
  (`Администратор не может удалить собственную учетную запись`), удаление администратора →
  `403` (`Нельзя удалить учетную запись администратора`), отсутствие → `404`.
  Refresh-токены удаляются каскадно (`ON DELETE CASCADE`).

### Служебные маршруты вне `/api/v1`

| Путь                | Ответ                                                                                                           |
| ------------------- | --------------------------------------------------------------------------------------------------------------- |
| `GET /health`       | `200 {"status":"OK"}`, `Cache-Control: no-store`. Проверяет только HTTP-сервер, состояние БД **не** тестируется |
| `GET /`             | `301` → `/docs`                                                                                                 |
| `GET /docs`         | `200` HTML Swagger UI (CDN `swagger-ui-dist@5`), `Cache-Control: public, max-age=300`                           |
| `GET /openapi.yaml` | `200` YAML из встроенного файла `docs/openapi.yaml`, `Cache-Control: public, max-age=300`                       |

Эти маршруты не покрыты middleware `/api/v1` (нет CSRF/аутентификации), но получают
глобальные security-заголовки, CORS, `RequestID`, `RealIP` и `Recoverer`. Swagger UI
грузится из интернета — в изолированном стенде открывайте `/openapi.yaml` напрямую.

---

## Формат ошибок и словарь сообщений

Единая форма (`response.ErrorBody`):

```json
{
  "error": "VALIDATION_FAILED",
  "message": "Проверьте обязательные поля пользователя",
  "details": { "email": ["Укажите действительный email"] }
}
```

`details` отсутствует при отсутствии деталей. Категория (`error`) выбирается по HTTP-коду:

| Код  | Категория               | Типовые сообщения                                                                                                                                                                                                                                                            |
| ---- | ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 400  | `VALIDATION_FAILED`     | `Некорректное тело JSON`, `Проверьте обязательные поля пользователя`, `Пустые данные обновления`, `Недопустимое значение параметра`, `Недопустимые параметры ограничения количества страниц`, `Неверный идентификатор пользователя`, `Несколько значений JSON`               |
| 401  | `UNAUTHORIZED`          | `Необходима авторизация для получения доступа`, `Недействительный или просроченный Access-токен`, `Недопустимый токен субъекта`, `Не авторизован`, `Неверные данные авторизации (email или пароль)`, `Недействительный или просроченный Refresh-токен`                       |
| 403  | `FORBIDDEN`             | `Недопустимый Origin`, `Недействительный CSRF-токен`, `Недостаточно прав`, `Доступ к данному контуру ограничен`, `Администратор не может удалить собственную учетную запись`, `Нельзя удалить учетную запись администратора`                                                 |
| 404  | `NOT_FOUND`             | `Пользователь не найден`                                                                                                                                                                                                                                                     |
| 409  | `CONFLICT`              | `Email уже используется`                                                                                                                                                                                                                                                     |
| 413  | `PAYLOAD_TOO_LARGE`     | `Размер тела запроса превышает допустимый лимит`                                                                                                                                                                                                                             |
| 429  | `RATE_LIMITED`          | `Слишком много запросов` (+ `Retry-After`)                                                                                                                                                                                                                                   |
| 500  | `INTERNAL_SERVER_ERROR` | `Не удалось создать/получить/обновить/удалить пользователя`, `Не удалось получить список пользователей`, `Не удалось хешировать пароль`, `Не удалось выпустить токены`, `Не удалось завершить сессию. Повторите попытку позже`, `Не удалось подготовить CSRF-защиту запроса` |
| 503  | `SERVICE_UNAVAILABLE`   | `Проверка авторизации временно недоступна`                                                                                                                                                                                                                                   |
| иной | `REQUEST_FAILED`        | —                                                                                                                                                                                                                                                                            |

Сообщения централизованы в пакете `internal/messages` (подпакеты `auth`, `common`,
`pagination`, `user`, `validation`); слой use-case классифицирует ошибку через
`usecase.ErrorCode` (`ErrCodeValidation` → 400, `ErrCodeUnauthorized` → 401,
`ErrCodeForbidden` → 403, `ErrCodeNotFound` → 404, `ErrCodeConflict` → 409,
`ErrCodeUnavailable` → 503, иначе 500).

---

## Безопасность

Реализовано:

- **Хранение паролей**: bcrypt (`DefaultCost`), `password_hash` не покидает JSON.
- **Timing-защита входа**: при неизвестном/неактивном пользователе выполняется сравнение
  с фиктивным bcrypt-хешем (`dummyPassword`), время ответа не выдаёт существование аккаунта.
- **JWT**: строго HS256 (`WithValidMethods`), проверка `iss`, `aud`, обязательного `exp`;
  назначение токена (`access`/`refresh`) отделяет друг друга, подписанный `alg=none` отвергается.
- **HttpOnly cookie** для access/refresh; `SameSite=Lax` по умолчанию, `Secure` включаемый.
- **CSRF (double-submit)**: для всех изменяющих методов сверяются cookie `csrf_token`,
  заголовок `X-CSRF-Token` и HMAC-подпись токена (`hmac.Equal`); дополнительно проверяется
  allow-list источников (`Origin`, при его отсутствии — `Referer`). Разрешённый `Referer`
  не может переопределить явно запрещённый `Origin`.
- **Constant-time** сравнение секрета админской регистрации (`subtle.ConstantTimeCompare`).
- **Refresh-token rotation** с детектом повторного использования: replay отзывает все сессии
  пользователя; в БД хранится только SHA-256 хеш токена.
- **Отзыв сессий при смене пароля** (`PATCH /users/{id}`), при реplay-атаке, при переходе
  пользователя в `inactive` во время ротации.
- **RBAC по роли из БД** + проверка статуса на каждом защищённом запросе.
- **Mass assignment защита**: неизвестные поля отклоняются декодером; роль нельзя повысить
  через `PUT/PATCH /users/{id}` или `PUT/PATCH /users/me`.
- **Rate limiting** (fail-closed) и лимит тела 1 MiB; таймауты сервера.
- **Заголовки**: `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`,
  `Referrer-Policy: strict-origin-when-cross-origin`, `Strict-Transport-Security`,
  `Cache-Control: no-store, no-cache, must-revalidate, private` + `Pragma: no-cache` для `/api/v1`.
- **Идемпотентный отказ** `POST /logout` (не раскрывает наличие/отсутствие токена).

Что НЕ реализовано (планировалось, но в коде отсутствует):

- **Нет** middleware `RequireSecureAuth`: обязательность HTTPS и запрет `SameSite=None`
  без `Secure` на уровне приложения не проверяются. Ответственность за корректные
  `COOKIE_SECURE`/`COOKIE_SAMESITE` и TLS лежит на операторе/прокси.
- **Нет** отдельного Origin-middleware для публичных маршрутов: проверку источника выполняют
  `RequireAllowedOrigin` (только `GET /csrf`) и `CSRF` (все изменяющие запросы).
- **Нет** rate limiting на `GET /csrf`, `GET /health`, `/docs`, `/openapi.yaml`.
- **Нет** отзыва access-токенов (stateless JWT, blacklist отсутствует).
- **Нет** автоматического удаления строк `api_rate_limits` (таблица растёт за счёт новых ключей).

Чек-лист перед продакшном:

```bash
openssl rand -hex 32   # значение JWT_SECRET (>= 32 символов)
openssl rand -hex 24   # значение ADMIN_REGISTER_TOKEN
```

- задать уникальные `JWT_SECRET` и `ADMIN_REGISTER_TOKEN`, не использовать значения из примеров;
- включить TLS и `COOKIE_SECURE=true`; при кросс-доменном фронтенде — `COOKIE_SAMESITE=None`
  (требует `Secure=true`) и точный список `CORS_ORIGINS`;
- убедиться, что reverse proxy перезаписывает `X-Forwarded-For`;
- закрыть прямой доступ к порту 5432 (compose публикует его только на `127.0.0.1`);
- не хранить `.env` в репозитории и не коммитить его.

---

## Ограничение частоты запросов

Хранилище счётчиков — PostgreSQL, таблица `api_rate_limits` (порт `domain.RateLimitStore`,
реализация `persistence.RateLimitRepository`). Это позволяет нескольким экземплярам
приложения разделять одни и те же счётчики. Механизм — **fixed window**: граница окна
вычисляется как `floor(now / window) * window` от Unix epoch, поэтому экземплярам не нужна
синхронизация. Атомарный `INSERT ... ON CONFLICT DO UPDATE` увеличивает `hits` или
сбрасывает окно, если `window_start + window <= now()`.

| Маршрут                          | Окно     | Порог (env)                      | Ключ счётчика                                        |
| -------------------------------- | -------- | -------------------------------- | ---------------------------------------------------- |
| `POST /api/v1/login` (limiter 1) | 15 минут | `LOGIN_RATE_LIMIT` (10)          | `login:<IP>:<email>`                                 |
| `POST /api/v1/login` (limiter 2) | 1 час    | `LOGIN_RATE_LIMIT` (10)          | `login_global:<email>` / `login_global:invalid:<IP>` |
| `POST /api/v1/register`          | 1 час    | `REGISTER_RATE_LIMIT` (10)       | `ip:<IP>`                                            |
| `POST /api/v1/register-admin`    | 1 час    | `REGISTER_RATE_LIMIT` (10)       | `ip:<IP>`                                            |
| `POST /api/v1/refresh`           | 1 минута | `REFRESH_RATE_LIMIT` (30)        | `refresh:<base64(SHA-256 cookie)>` / `refresh:<IP>`  |
| `POST /api/v1/logout`            | 1 минута | `LOGOUT_RATE_LIMIT` (10)         | `ip:<IP>`                                            |
| защищённые `/api/v1/users*`      | 1 минута | `AUTHENTICATED_RATE_LIMIT` (600) | `user:<UUID>` / `ip:<IP>`                            |

Особенности реализации, о которых нужно знать:

- Пороги считаются **запросами**, а не неудачными попытками: счётчик увеличивается и на
  успешный вход. Реализация **не эквивалентна** политике «10 неуспешных попыток за 15 минут».
- Логин закрыт двумя последовательными окнами; сработает то, которое переполнится первым.
- Email для ключа извлекается из JSON-тела (не более 1 MiB); тело сохраняется для обработчика.
- При недоступном хранилище, нулевом пороге или некорректном окне middleware отвечает
  `503 SERVICE_UNAVAILABLE` (fail-closed), а не пропускает запрос.
- Превышение → `429 RATE_LIMITED` с `Retry-After` в секундах (длительность окна).
- Строки таблицы не удаляются автоматически; периодическую очистку устаревших бакетов
  нужно добавлять отдельным заданием.

Локальная проверка (требует PostgreSQL):

```bash
for i in $(seq 1 12); do
  curl -s -o /dev/null -w "%{http_code}\n" -X POST http://localhost:8080/api/v1/register \
    -H 'Content-Type: application/json' -H "Origin: http://localhost:3000" \
    -H "X-CSRF-Token: $CSRF" -b jar.txt \
    -d "{\"email\":\"u$i@example.com\",\"password\":\"a-long-password\",\"first_name\":\"A\",\"last_name\":\"B\"}"
done
# ожидаем серию 201, затем 429; в таблице api_rate_limits виден рост hits
docker compose exec postgres psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" \
  -c 'SELECT bucket_key, window_start, hits FROM api_rate_limits ORDER BY updated_at DESC;'
```

---

## Структура проекта

```text
cmd/api/main.go                                  Composition Root: конфиг, БД, репозитории,
                                                 use-case, роутер, http.Server, graceful shutdown
docs/openapi.yaml                                OpenAPI 3.0.3 (встраивается в бинарник)
docs/embed.go                                    //go:embed openapi.yaml -> docs.OpenAPI
internal/domain/                                 Ядро: сущности User/RefreshToken, sentinel-ошибки,
                                               порты UserRepository / RefreshTokenRepository / RateLimitStore
internal/usecase/                                Слой сценариев: auth_usecase.go, user_usecase.go,
                                               dto.go, errors.go (ErrorCode -> HTTP), validation.go,
                                               порт PasswordHasher
internal/delivery/http/handler/                  Тонкие HTTP-обработчики + Swagger UI + маппинг ошибок
internal/delivery/http/response/                 Единый JSON/ошибочный вывод, декодер с DisallowUnknownFields
internal/infrastructure/config/                  Чтение и валидация ENV/.env
internal/infrastructure/database/                db.go (pgxpool + подготовка limiter-таблицы), init.sql
internal/infrastructure/persistence/             UserRepository, TokenRepository, RateLimitRepository
internal/infrastructure/security/                Пакет объявлен как `package auth`: jwt.go, cookies.go,
                                               csrf.go, password_hasher.go, usecase_adapter.go
internal/infrastructure/middleware/              Аутентификация, RBAC, CSRF/Origin, лимиты, заголовки
internal/infrastructure/transport/router.go      chi-router, CORS, порядок middleware, маршрут-группы
internal/messages/                               Словарь сообщений ответа (RU), разбит по подпакетам
docs/openapi.yaml, README.md                     Внешняя документация
Dockerfile, docker-compose.yml, Makefile         Сборка и запуск
.env.example                                     Шаблон конфигурации (копируется в .env)
.vscode/                                         Настройки/launch для разработки
```

Архитектура Clean Architecture: зависимости направлены внутрь (domain ← usecase ← delivery/infra),
порты объявлены в домене, инфраструктура их реализует; HTTP-слой не содержит бизнес-правил.

---

## Тесты, сборка, CI и релизы

```bash
go test ./...                      # все unit-тесты
go test ./internal/usecase/... -v  # сценарии (моки портов, без БД)
go test ./internal/infrastructure/middleware/... -v
go test ./internal/delivery/http/handler/... -v
go vet ./...
gofmt -l .                          # пустой вывод = код отформатирован
go build -o bin/api ./cmd/api
```

Unit-тесты покрывают слой use-case (моки `domain`-портов), middleware (аутентификация,
RBAC, CSRF/Origin, лимиты, ключи счётчиков) и HTTP-обработчики (полные сценарии
жизненного цикла токенов, RBAC/IDOR, mass-assignment, timing-защита). Тесты не требуют
реальной PostgreSQL. Интеграционные тесты с реальной БД в репозитории отсутствуют.

CI (GitHub Actions, `.github/workflows/ci.yml`): push и pull request на `main`,
матрица `ubuntu / macos / windows` × Go `1.23.x / 1.24.x`; шаги — checkout,
`setup-go` с кешированием модулей, `go vet ./...`, `go test ./...`,
сборка `CGO_ENABLED=0 go build -o bin/api ./cmd/api`, запуск собранного бинарника
с smoke-проверкой `GET /health` (ожидается `200`).

Релизы (`.github/workflows/release.yml`): тег вида `vMAJOR.MINOR.PATCH[.BUILD]`
(например `v1.0.29.2`) собирает кросс-платформенные артефакты (`linux/amd64`,
`linux/arm64`, `windows/amd64`, `darwin/amd64`, `darwin/arm64`) и создаёт GitHub Release.
Версия приложения в `docs/openapi.yaml` (`info.version`) обновляется вручную и должна
совпадать с тегом релиза.

---

## Эксплуатационные ограничения

Известные следствия текущей реализации, которые важно учитывать при эксплуатации:

- **Короткоживущий access-токен остаётся валидным до истечения `ACCESS_TOKEN_TTL`** даже
  после выхода, смены пароля или отзыва refresh-токена: blacklist access-токенов отсутствует.
  Относительно долгий срок (15 минут) — осознанный компромисс.
- **`GET /health` не проверяет PostgreSQL.** Контейнер может оставаться `healthy` при падении БД.
- **Пороги лимитов считаются запросами**, включая успешные; при высокой плотности NAT-клиентов
  ключ `ip:<IP>` для регистрации может приводить к ложным `429`.
- **`chimw.RealIP` доверяет `X-Forwarded-For` без настроек** — при прямом (не через доверяемый
  прокси) доступе ключи лимитов подделываемы.
- **Таблица `api_rate_limits` не очищается автоматически.**
- **`PUT /users/{id}` не отзывает сессии** при смене пароля (в отличие от `PATCH /users/{id}`).
- **`POST /users` принимает роль `admin`** — право создавать администраторов равно сильному привилегированию.
- **Swagger UI загружается из CDN** и недоступен без внешнего интернета.
- **`Strict-Transport-Security` отправляется и на HTTP**; при небезопасном стенде учитывайте
  агрессивность HSTS в браузерах.
- **`init.sql` применяется только при первой инициализации тома**; изменения схемы требуют
  ручного выполнения SQL или пересоздания тома.
- **В `.env`/`.env.example` имя БД в `DATABASE_URL` расходится с `POSTGRES_*`** — при запуске
  вне Docker DSN нужно согласовать вручную.

---

## Что изменилось относительно предыдущей документации

Этот README и `docs/openapi.yaml` приведены в соответствие с фактической реализацией
ветки `main` (версия 1.0.29.2). Исправленные расхождения прежней редакции:

1. **Стек**: вместо «Spring Boot / Java» описан Go 1.23 + chi + pgx + golang-jwt + bcrypt;
   модель доступа — две роли (`user`, `admin`) и два статуса (`active`, `inactive`),
   а не `ROLE_ANONYMOUS/USER/ADMIN/SUPER_ADMIN`.
2. **Префикс маршрутов**: `/api/v1/auth/*` и `/api/v1/admin/users*` заменены реальными
   `/api/v1/register`, `/register-admin`, `/login`, `/refresh`, `/logout`, `/csrf`,
   `/users/me`, `/users`, `/users/{id}`.
3. **Передача токенов**: убраны варианты `Authorization: Bearer` и `refreshToken` в JSON.
   Токены ходят только в HttpOnly cookie; в ответах — только `message` и объект пользователя.
4. **Логирование**: описание Logback/JSON-аппендера и `logging.level.*` удалено — приложение
   пишет стандартный `log` в stdout/stderr, уровень настраивается не конфигурацией.
5. **Actuator / Prometheus**: упоминания Spring Actuator и Micrometer заменены реальным
   `GET /health` (`{"status":"OK"}`, без проверки БД) и служебными `/`, `/docs`, `/openapi.yaml`.
6. **Безопасность**: удалены ссылки на несуществующие `SecurityFilterChain`, `RequireSecureAuth`,
   `RequireAllowedOrigin` для публичных маршрутов, `JwtAccessCookie`, `JwtRefreshCookie`,
   `RestAuthenticationEntryPoint`, `MessageCodesResolver`, `GlobalControllerExceptionHandler`,
   `JdbcBlacklistService`, `InMemoryRateLimiter`, таблицу `jwt_access_blacklist`,
   `springdoc.api-docs.path`, `management.endpoints.web.exposure.include`,
   `app.security.rate-limit.*` и `app.security.admin-register.secret`.
   Вместо них описаны фактические middleware chi, cookie-атрибуты из `security/cookies.go`,
   CSRF-схема `nonce.HMAC` и PostgreSQL-хранилище лимитов.
7. **Лимиты**: исправлено «10 неуспешных попыток» — реализованы fixed window по числу
   запросов, два окна для логина, fail-closed поведение и реальные ключи счётчиков;
   добавлена таблица окон/порогов и переменные `LOGIN_/REGISTER_/REFRESH_/LOGOUT_/AUTHENTICATED_RATE_LIMIT`.
8. **Конфигурация**: перечислены реальные переменные (`APP_PORT`, `API_HOST_PORT`, `APP_ENV`,
   `DATABASE_URL`, `POSTGRES_*`, `JWT_SECRET`, `ACCESS_TOKEN_TTL`, `REFRESH_TOKEN_TTL`,
   `ADMIN_REGISTER_TOKEN`, `COOKIE_SECURE`, `COOKIE_SAMESITE`, `COOKIE_DOMAIN`, `CORS_ORIGINS`),
   их defaults и правила валидации; указано, что путь cookie (`/api/v1/`) задан в коде.
9. **Схема БД**: `internal/db/init.sql` → `internal/infrastructure/database/init.sql`;
   добавлены `api_rate_limits`, индексы, `ON DELETE CASCADE`, идемпотентный DDL при старте
   и предупреждение о применении init.sql только при первой инициализации тома.
10. **OpenAPI**: версия спецификации синхронизирована с релизом (1.0.8 → 1.0.29.2),
    описаны все 15 операций `/api/v1`, схемы запросов/ответов, заголовки `Set-Cookie`,
    `Cache-Control`, `Retry-After`, все используемые сообщения об ошибках и примеры ответов.
11. **Прочее**: добавлены разделы по управлению сервисом (docker compose, make, graceful
    shutdown, reverse proxy), тестированию, CI/релизам, структуре проекта и эксплуатационным
    ограничениям; устранены дублирующиеся куски текста старой версии README.
