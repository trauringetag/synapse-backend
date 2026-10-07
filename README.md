# 🚀 Golang REST API

Современный REST API сервис на **Go** с аутентификацией JWT, ролевой моделью (RBAC) и PostgreSQL. Проект построен по принципам чистой архитектуры с разделением на слои.

## Возможности

- **JWT-аутентификация** с токенами и хэшированием паролей (bcrypt)
- **Ролевая модель** (Admin / User) с разграничением прав доступа
- **Docker & Docker Compose** для быстрого развертывания
- **PostgreSQL** с автоматическими миграциями при старте
- ️**Чистая архитектура**: Handlers → Repository → Database
- **Полная поддержка UTF-8** (корректная работа с кириллицей)
- **Нативный роутинг Go 1.22+** без сторонних зависимостей

## ️ Технологии

| Технология | Назначение |
|------------|------------|
| [Go 1.22+](https://go.dev/) | Язык программирования |
| [PostgreSQL 15](https://www.postgresql.org/) | Реляционная база данных |
| [pgx/v5](https://github.com/jackc/pgx) | Высокопроизводительный драйвер PostgreSQL |
| [golang-jwt/jwt/v5](https://github.com/golang-jwt/jwt) | JWT-токены |
| [bcrypt](https://pkg.go.dev/golang.org/x/crypto/bcrypt) | Хэширование паролей |
| [godotenv](https://github.com/joho/godotenv) | Загрузка переменных окружения |
| Docker & Docker Compose | Контейнеризация |

## 🚀 Быстрый старт

### Предварительные требования

- [Docker](https://www.docker.com/products/docker-desktop/) и Docker Compose
- Go 1.22+ (опционально, для локальной разработки)

### Установка и запуск

**1. Склонируйте репозиторий:**

```bash
git clone https://github.com/trauringetag/golang-rest-api.git
```

**2. Перейдите в папку с проектом:**

```bash
cd golang-rest-api
```

**3. Создайте файл .env в корне проекта (или отредактируйте существующий):**

```bash
APP_PORT=8080

POSTGRES_USER=app_user
POSTGRES_PASSWORD=secret_password
POSTGRES_DB=app_db
DB_HOST=db
DB_PORT=5432

JWT_SECRET=your-super-secret-key-change-this-in-production-min-32-chars
JWT_EXPIRATION_HOURS=24
```

Обязательно замените JWT_SECRET на случайную строку длиной минимум 32 символа в продакшене!

**4. Запустите проект:**

```bash
docker-compose up --build
```

**5. Проверьте работоспособность:**

```bash
curl http://localhost:8080/health
```

Корректный результат выполнения: «OK»

## 📚 API Документация

### Базовая информация

- Base URL: http://localhost:8080
- Content-Type: application/json; charset=utf-8
- Аутентификация: JWT Bearer Token в заголовке «Authorization: Bearer ЗДЕСЬ_ВАШ_ТОКЕН»

### Публичные эндпоинты (без токена)

#### 1. Регистрация пользователя
    
    POST /auth/register

Создает нового пользователя. Если роль не указана, по умолчанию назначается user.

**Запрос:**

    {
      "first_name": "Иван",
      "last_name": "Иванов",
      "email": "ivan@example.com",
      "password": "securePassword123",
      "role": "admin"
    }

**Успешный ответ (201 Created):**

    {
      "message": "Пользователь успешно зарегистрирован",
      "user_id": 1,
      "role": "admin"
    }

**Ошибки:**

400 Bad Request — невалидный JSON, пустые поля, пароль < 6 символов, неверная роль
