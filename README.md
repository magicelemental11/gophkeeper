# GophKeeper

Клиент-серверный менеджер паролей: хранит логины и пароли, текст, бинарные данные, банковские карты и TOTP-генераторы и синхронизирует их между клиентами одного владельца. Сервер — gRPC поверх TLS с PostgreSQL, клиент — CLI и терминальный интерфейс под Windows, Linux и macOS.

## Безопасность

Сервер никогда не видит открытые данные и ключ шифрования (zero-knowledge).

- Логин не зависит от регистра. Пользователь вводит один мастер-пароль. Клиент считает `master = Argon2id(пароль, соль = sha256("gophkeeper:" + логин в нижнем регистре), t=3, m=64 МиБ, p=4)`.
- Из него через HKDF-SHA256 выводятся два ключа: `auth_key` (info `auth`) уходит на сервер вместо пароля, сервер хранит только `bcrypt(auth_key)`; `enc_key` (info `enc`) остаётся на клиенте.
- Каждая запись целиком (тип, имя, метаинформация, данные) сериализуется и шифруется AES-256-GCM: случайный nonce в начале шифротекста, `id` записи как additional data, поэтому шифротекст нельзя подставить в чужую запись.
- Ключ не хранится на диске. CLI спрашивает мастер-пароль скрытым вводом (или берёт из `GOPHKEEPER_PASSWORD`), TUI держит ключ в памяти на время сессии. Правильность пароля проверяется офлайн по контрольному значению, зашифрованному тем же ключом.
- Транспорт — TLS. Токен доступа — JWT HS256 на 24 часа в метаданных `authorization: Bearer <token>`; секрет обязателен, без него сервер не стартует.
- Каждый запрос к записям фильтруется по пользователю из токена; на чужой `id` сервер отвечает `NotFound`, не раскрывая существование записи.

## Синхронизация и конфликты

У каждого пользователя монотонный счётчик `revision`. Любое изменение записи в одной транзакции увеличивает его и записывает в запись, поэтому `Sync(since_revision)` одним запросом по индексу отдаёт всё, что изменилось после последней синхронизации, включая удаления (tombstone).

Запись на сервере имеет `version` для оптимистической блокировки: клиент шлёт версию, на которой основано изменение (0 для новой). Если на сервере версия другая, ответ — `ABORTED` с актуальной записью в деталях статуса.

Алгоритм клиента:

1. Отправить локально изменённые записи. При конфликте побеждает серверная версия, а локальная сохраняется новой записью с именем `<имя> (conflict <дата время>)` — ничего не теряется. Конфликтующее локальное удаление отбрасывается.
2. Запросить изменения после последней известной ревизии и применить их к локальному кэшу.
3. Запомнить новую ревизию.

Локальный кэш хранит те же зашифрованные блобы, что и сервер, поэтому данные можно читать офлайн. Изменения без связи с сервером сохраняются локально и уходят при следующей синхронизации; команды изменения синхронизируются автоматически, если сервер доступен.

## Запуск сервера

```sh
docker run -d --name gophkeeper-pg -e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=gophkeeper -p 5432:5432 postgres:16
make certs
make build
./bin/gophkeeper-server \
  -d 'postgres://postgres:postgres@localhost:5432/gophkeeper?sslmode=disable' \
  -j "$(openssl rand -hex 32)" \
  -tls-cert certs/server.crt -tls-key certs/server.key
```

`make certs` (скрипт `scripts/gencert.sh`) выпускает самоподписанный CA и серверный сертификат для `localhost` и `127.0.0.1` в каталог `certs/`. Миграции применяются при старте. Сервер останавливается корректно по SIGINT/SIGTERM.

Конфигурация сервера (переменная окружения важнее флага):

| Флаг | Переменная | По умолчанию | |
|---|---|---|---|
| `-a` | `ADDRESS` | `:3200` | адрес gRPC |
| `-d` | `DATABASE_DSN` | — | обязательно |
| `-j` | `JWT_SECRET` | — | обязательно |
| `-tls-cert` | `TLS_CERT` | — | обязательно без `-insecure` |
| `-tls-key` | `TLS_KEY` | — | обязательно без `-insecure` |
| `-insecure` | `INSECURE` | `false` | без TLS, только для локальных тестов |

## Клиент

Сборка под текущую систему — `make build` (`bin/gophkeeper`), под все платформы — `make release`: в `dist/` появятся `gophkeeper-linux-amd64`, `gophkeeper-linux-arm64`, `gophkeeper-darwin-amd64`, `gophkeeper-darwin-arm64`, `gophkeeper-windows-amd64.exe`.

Глобальные флаги клиента:

| Флаг | Переменная | По умолчанию | |
|---|---|---|---|
| `-s`, `--server` | `GOPHKEEPER_SERVER` | `localhost:3200` | адрес сервера для `register` и `login` |
| `--ca` | `GOPHKEEPER_CA` | системные корни | сертификат CA для проверки сервера |
| `--data-dir` | `GOPHKEEPER_DATA_DIR` | `<конфиг пользователя>/gophkeeper` | локальный кэш и сессия |
| `--insecure` | — | `false` | без TLS, только для локальных тестов |

Мастер-пароль спрашивается скрытым вводом или берётся из `GOPHKEEPER_PASSWORD` (для скриптов).

### Новый пользователь

```sh
export GOPHKEEPER_CA=certs/ca.crt
gophkeeper version
gophkeeper register --login alice
echo 's3cret' | gophkeeper add credentials --name github --login alice --meta 'https://github.com' --password-stdin
gophkeeper add text --name recovery --file codes.txt
gophkeeper add binary --name passport --file passport.pdf --meta 'скан паспорта'
gophkeeper add card --name visa --number '4111 1111 1111 1111' --holder 'ALICE' --expiry 12/30 --meta 'Банк'
gophkeeper add otp --name gitlab --uri 'otpauth://totp/GitLab:alice?secret=JBSWY3DPEHPK3PXP'
```

### Существующий пользователь на другом устройстве

```sh
gophkeeper --data-dir ~/phone login --login alice
gophkeeper --data-dir ~/phone list
gophkeeper --data-dir ~/phone show github            # пароль скрыт
gophkeeper --data-dir ~/phone show github --reveal
gophkeeper --data-dir ~/phone get-file passport -o passport.pdf
gophkeeper --data-dir ~/phone otp gitlab
```

### Остальные команды

- `sync` — отправить локальные изменения и получить чужие, печатает отчёт.
- `list [--kind credentials|text|binary|card|otp]` — таблица без секретов.
- `show <id|имя> [--reveal]` — карточка записи; пароль, CVV, номер карты и секрет OTP скрыты без `--reveal`. Истёкшая карта помечается `(expired)`.
- `edit <id|имя>` — флаги как у `add` для этого типа, меняются только переданные поля (`--password` и `--cvv` спрашивают новое значение).
- `delete <id|имя> [--yes]` — с подтверждением.
- `get-file <id|имя> -o путь [--force]` — сохранить бинарные данные (права 0600, без `--force` не перезаписывает).
- `otp <id|имя>` — текущий одноразовый код и сколько секунд он действует.
- `tui` — интерактивный интерфейс: вход, список с поиском (`/`) и фильтром по типу (`f`), карточка записи (`r` — показать секреты, живой код OTP), добавление (`a`), правка (`e`), удаление (`d`), синхронизация (`s`) и фоновая синхронизация раз в 30 секунд.
- `logout` — удалить сессию и локальный кэш.

Запись можно указать полным ID, его префиксом (из `list`) или точным именем; при нескольких совпадениях клиент выведет их список.

Локальный каталог (права 0700) содержит `session.json` (адрес сервера, логин, токен, последняя ревизия) и `vault.json` (зашифрованные записи); оба файла с правами 0600 и пишутся атомарно.

## Протокол

gRPC-схема — [api/proto/gophkeeper.proto](api/proto/gophkeeper.proto), сгенерированный код — `internal/proto` (`make proto`). Описание в формате Swagger/OpenAPI 2.0 — [api/openapi/gophkeeper.swagger.json](api/openapi/gophkeeper.swagger.json), генерируется из того же proto. Посмотреть в Swagger UI:

```sh
docker run --rm -p 8080:8080 -e SWAGGER_JSON=/spec/gophkeeper.swagger.json -v "$PWD/api/openapi:/spec" swaggerapi/swagger-ui
```

Сервисы:

- `AuthService.Register`, `AuthService.Login` — логин и `auth_key` (32 байта), ответ — токен.
- `VaultService.Upsert(id, base_version, payload)`, `Delete(id, base_version)`, `Get(id)`, `Sync(since_revision)` — только с токеном. Большой ответ `Sync` делится на страницы: пока `has_more`, клиент повторяет запрос с полученной ревизией. Лимит сообщения 16 МБ, зашифрованная запись — до 11 МБ, бинарные данные — до 10 МБ (клиент проверяет до шифрования).

## Тесты

```sh
make test     # go test -race -p 1 ./...
make cover    # покрытие без сгенерированного .pb.go
```

Тесты хранилища, сервера и интеграционный тест (настоящий сервер с PostgreSQL и TLS, сертификаты генерируются во временном каталоге, два клиента проходят полный сценарий с конфликтом и удалением) запускаются при заданной `TEST_DATABASE_DSN`, иначе пропускаются:

```sh
TEST_DATABASE_DSN='postgres://postgres:postgres@localhost:5432/gophkeeper?sslmode=disable' make cover
```

Флаг `-p 1` нужен, потому что тесты разных пакетов используют одну базу. Клиентские тесты поднимают сервер с хранилищем в памяти через `bufconn`; функциональный тест собирает бинарник клиента и запускает его через `os/exec`.
