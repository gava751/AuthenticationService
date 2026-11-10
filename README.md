# Authentication Service (InnoBoard)

## Эндпоинты

| Метод | Путь | Доступ | Описание |
|---|---|---|---|
| `POST` | `/api/auth/register` | public | Регистрация: создаёт пользователя в User Service и креды локально |
| `POST` | `/api/auth/login` | public | Логин, выдача пары токенов |
| `POST` | `/api/auth/refresh` | public | Обновление пары токенов по refresh-токену |
| `GET` | `/api/auth/me` | authenticated | Текущий пользователь (user_id, роль) |
| `GET` | `/api/auth/credentials/{userId}` | ADMIN | Креды пользователя по user_id |
| `GET` | `/.well-known/jwks.json` | public | Публичный RSA-ключ (JWKS) для проверки подписи токенов |

Токены подписываются RS256 (приватный ключ только в этом сервисе); остальные сервисы проверяют подпись через JWKS.

## Конфигурация

| Переменная | По умолчанию (local) | Описание |
|---|---|---|
| `DB_URL` | `jdbc:postgresql://localhost:5432/auth_service` | URL БД |
| `DB_USERNAME` / `DB_PASSWORD` | **обязательны, без дефолта** | Креды БД; приложение падает при старте, если не заданы (локальные значения — в `.env`) |
| `JWT_KEY_ID` | `auth-service-1` | `kid` в заголовке токена и в JWKS |
| `JWT_PRIVATE_KEY_PATH` | **обязательна, без дефолта** | Путь к приватному RSA-ключу (PKCS#8, подпись токенов) |
| `JWT_PUBLIC_KEY_PATH` | **обязательна, без дефолта** | Путь к публичному RSA-ключу (X.509, JWKS) |
| `USER_SERVICE_URL` | `http://localhost:8082` | URL User Service для регистрации |
| `INTERNAL_SERVICE_TOKEN` | **обязателен, без дефолта** | Общий секрет для `/internal/**` User Service; должен совпадать со значением в user-service (локальное значение — в `.env`) |
| `JWT_ACCESS_TTL` | `15m` | Время жизни access-токена |
| `JWT_REFRESH_TTL` | `7d` | Время жизни refresh-токена |
| `SERVER_PORT` | `8081` | Порт сервиса |

Профили: `local` (по умолчанию), `docker` (хост `postgres`).

## Ключи

Ключи в `keys/` не коммитятся (`.gitignore`). Генерация пары:

```bash
mkdir -p keys
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out keys/jwt-private.pem
openssl pkey -in keys/jwt-private.pem -pubout -out keys/jwt-public.pem
```

## Запуск

Требуется JDK 25.

```bash
cp .env.example .env
```

`.env` читает только docker compose — Spring его не читает. Для локального запуска экспортируйте переменные (можно целиком: `set -a; source .env; set +a`):

```bash
# 1. инфраструктура (Postgres наружу на 5433)
docker compose up -d postgres

# 2. переменные окружения
export DB_USERNAME=... DB_PASSWORD=...
export JWT_PRIVATE_KEY_PATH="$PWD/keys/jwt-private.pem"
export JWT_PUBLIC_KEY_PATH="$PWD/keys/jwt-public.pem"
export DB_URL=jdbc:postgresql://localhost:5433/auth_service
export INTERNAL_SERVICE_TOKEN=...

# 3. ключи (см. раздел «Ключи»)
mkdir -p keys
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out keys/jwt-private.pem
openssl pkey -in keys/jwt-private.pem -pubout -out keys/jwt-public.pem

# 4. приложение локально
./mvnw spring-boot:run

# всё в докере
docker compose up -d --build

# тесты (нужен Docker для Testcontainers)
./mvnw verify
```

Порт сервиса — **8081** (8080 занят API Gateway, user-service на 8082). Postgres наружу — **5433** (5432 занят user-service), поэтому `DB_URL` выше указывает на 5433.
