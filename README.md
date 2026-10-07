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

- 400 Bad Request — невалидный JSON, пустые поля, пароль < 6 символов, неверная роль

#### 2. Вход в систему (получение токена)
    
    POST /auth/login

Создает нового пользователя. Если роль не указана, по умолчанию назначается user.

**Запрос:**

    {
      "email": "ivan@example.com",
      "password": "securePassword123"
    }

**Успешный ответ (200 OK):**

    {
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
      "role": "admin"
    }

**Ошибки:**

- 401 Unauthorized — неверный email или пароль

### Защищенные эндпоинты (требуют JWT)

**Все запросы должны содержать заголовок:**

    Authorization: Bearer ЗДЕСЬ_ВАШ_ТОКЕН

#### 3. Получение списка пользователей
    
    GET /users

**Логика доступа:**

- Admin — видит всех пользователей (до 50)
- User — видит только свои данные

**Успешный ответ (200 OK):**

    [
      {
        "id": 2,
        "first_name": "Иван",
        "last_name": "Иванов",
        "email": "ivan@example.com",
        "role": "user"
      },
      {
        "id": 1,
        "first_name": "Админ",
        "last_name": "Системы",
        "email": "admin@example.com",
        "role": "admin"
      }
    ]

**Ошибки:**

- 401 Unauthorized — токен отсутствует или недействителен

#### 4. Создание пользователя (только Admin)
    
    POST /users

**Запрос:**

    {
      "first_name": "Мария",
      "last_name": "Петрова",
      "email": "maria@example.com",
      "role": "user"
    }

**Успешный ответ (201 Created):**

    {
      "id": 3,
      "first_name": "Мария",
      "last_name": "Петрова",
      "email": "maria@example.com",
      "role": "user"
    }

**Ошибки:**

- 403 Forbidden — у пользователя нет прав администратора
- 400 Bad Request — невалидные данные или email уже существует

#### 5. Удаление пользователя (только Admin)
    
    DELETE /users/{id}

Администратор может удалить любого пользователя, кроме самого себя.

**Успешный ответ (200 OK):**

    {
      "message": "Пользователь успешно удален"
    }

**Ошибки:**

- 400 Bad Request — админ пытается удалить сам себя
- 403 Forbidden — у пользователя нет прав администратора
- 404 Not Found — пользователь с таким ID не найден

### Системные эндпоинты
    
    GET /health

Проверка работоспособности сервиса. Не требует аутентификации.

**Ответ (200 OK):**

    OK

## Архитектура

<img width="487" height="211" alt="image" src="https://github.com/user-attachments/assets/53908e42-de9f-4a99-a9a5-3c9104a40b26" />

## Безопасность

- Пароли хэшируются алгоритмом bcrypt с cost factor 10
- JWT-токены подписаны секретным ключом (HS256)
- Токены имеют срок действия (настраивается через JWT_EXPIRATION_HOURS)
- Поле password_hash никогда не возвращается в API-ответах (тег json:"-")
- SQL-инъекции предотвращены через параметризованные запросы pgx
- Валидация входных данных на уровне приложения

## Планы развития

- Добавить refresh tokens для обновления сессий без повторного логина
- Реализовать эндпоинт PUT /users/{id} для обновления данных
- Добавить пагинацию и фильтрацию в GET /users
- Интегрировать логгер (slog / zap)
- Написать юнит-тесты с моками репозитория
- Добавить rate limiting
- Настроить CI/CD через GitHub Actions
