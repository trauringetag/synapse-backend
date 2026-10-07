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

**1. Перейдите в папку с проектом:**

```bash
cd golang-rest-api
