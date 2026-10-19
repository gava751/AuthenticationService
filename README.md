# Authentication Service (InnoBoard)

## Конфигурация

| Переменная | По умолчанию (local) | Описание |
|---|---|---|
| `DB_URL` | `jdbc:postgresql://localhost:5432/auth_service` | URL БД |
| `DB_USERNAME` / `DB_PASSWORD` | `auth_service` / `auth_service` | Креды БД |
| `JWT_SECRET` | dev-заглушка | Секрет подписи JWT (HS256, ≥ 32 символов) |
| `JWT_ACCESS_TTL` | `15m` | Время жизни access-токена |
| `JWT_REFRESH_TTL` | `7d` | Время жизни refresh-токена |
| `SERVER_PORT` | `8081` | Порт сервиса |

Профили: `local` (по умолчанию), `docker` (хост `postgres`).

## Запуск

```bash
# локальная инфраструктура
docker compose up -d postgres

# приложение локально
export JAVA_HOME="/c/Users/gava751/.jdks/temurin-25.0.4.1"
./mvnw spring-boot:run

# всё в докере
docker compose up -d --build
```

Порт сервиса — **8081** (8080 занят user-service). Postgres наружу — **5433** (5432 занят user-service).
