# Chateau Bot

Telegram бот для обработки вебхуков и отправки уведомлений в каналы. Оптимизирован для развертывания на Vercel и других serverless платформах с **промышленным уровнем безопасности**.

## Возможности

- 🔗 **Обработка вебхуков**: Принимает POST запросы от внешних сервисов
- 📱 **Отправка в Telegram**: Автоматическая отправка сообщений в каналы
- ⚡ **Serverless**: Работает на Vercel без необходимости постоянного сервера
- 🎨 **Форматирование**: Автоматическое форматирование JSON данных в читаемые сообщения
- 🔧 **Конфигурация**: Простая настройка через переменные окружения
- 🔐 **Безопасность**: HMAC подпись, валидация входных данных, защищенное логирование

## 🔐 Безопасность

### Аутентификация webhook
```bash
# Обязательно установите секрет для подписи webhook
WEBHOOK_SECRET=your_random_secret_here
```

Бот проверяет подпись HMAC-SHA256 для всех входящих webhook:
- Заголовок `X-Webhook-Signature` или `X-Hub-Signature-256`
- Формат: `sha256=<подпись>` или просто `<подпись>`

### Защищенное логирование
- Автоматическое маскирование токенов, паролей, ключей в логах
- Ограничение размера логируемых данных
- Логирование IP адресов для аудита

### Валидация входных данных
- Ограничение размера payload (по умолчанию 1MB)
- Проверка Content-Type заголовков
- Валидация HTTPS соединений
- Защита от XSS и injection атак

### Безопасные заголовки
```
X-Content-Type-Options: nosniff
X-Frame-Options: DENY
X-XSS-Protection: 1; mode=block
```

## Быстрый старт

### 1. Создание Telegram бота

1. Напишите [@BotFather](https://t.me/BotFather) в Telegram
2. Создайте нового бота командой `/newbot`
3. Получите токен бота
4. Добавьте бота в ваш канал как администратора

### 2. Развертывание на Vercel

#### Автоматическое развертывание

[![Deploy with Vercel](https://vercel.com/button)](https://vercel.com/new/clone?repository-url=https://github.com/your-username/chateau-bot)

#### Ручное развертывание

1. Форкните этот репозиторий
2. Подключите репозиторий к Vercel
3. Настройте переменные окружения (см. ниже)
4. Разверните проект

### 3. Настройка переменных окружения

В Vercel dashboard добавьте следующие переменные:

```bash
# Обязательные
TELEGRAM_TOKEN=your_bot_token_here
DEFAULT_CHANNEL_ID=-1001234567890

# Безопасность (настоятельно рекомендуется)
WEBHOOK_SECRET=your_strong_random_secret_here

# Опциональные
ALLOWED_CHANNELS=[{"id":"-1001234567890","name":"Main Channel"}]
ALLOWED_ORIGINS=https://your-trusted-domain.com,https://api.service.com
MAX_PAYLOAD_SIZE=1048576
LOG_LEVEL=info
```

### 4. Получение ID канала

Чтобы узнать ID канала:

1. Добавьте бота [@userinfobot](https://t.me/userinfobot) в ваш канал
2. Он покажет ID канала (начинается с `-100`)
3. Удалите бота из канала

## Использование

### Webhook URL

После развертывания ваш webhook будет доступен по адресу:
```
https://your-app.vercel.app/api/webhook
```

### Проверка статуса

Проверить статус бота можно по адресу:
```
https://your-app.vercel.app/api/status
```

### Отправка webhook с подписью

```bash
# Генерация подписи (пример на bash)
PAYLOAD='{"event": "test", "message": "Hello from webhook!"}'
SECRET="your_webhook_secret"
SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$SECRET" | cut -d' ' -f2)

# Отправка с подписью
curl -X POST https://your-app.vercel.app/api/webhook \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Signature: sha256=$SIGNATURE" \
  -d "$PAYLOAD"
```

### Отправка без подписи (только если WEBHOOK_SECRET не установлен)

```bash
curl -X POST https://your-app.vercel.app/api/webhook \
  -H "Content-Type: application/json" \
  -d '{"event": "test", "message": "Hello from webhook!"}'
```

## Форматы сообщений

Бот поддерживает различные форматы входящих данных:

### Структурированные данные

```json
{
  "event": "order_created",
  "source": "e-commerce",
  "timestamp": "2024-01-01T12:00:00Z",
  "data": {
    "order_id": "12345",
    "customer": "John Doe",
    "amount": 99.99
  }
}
```

### Произвольный JSON

```json
{
  "type": "notification",
  "user": "admin",
  "message": "Server restarted"
}
```

### Обычный текст

Любые текстовые данные будут отправлены как есть.

## Конфигурация

### Переменные окружения

| Переменная | Обязательная | Описание |
|------------|--------------|----------|
| `TELEGRAM_TOKEN` | Да | Токен Telegram бота |
| `DEFAULT_CHANNEL_ID` | Да | ID канала по умолчанию |
| `WEBHOOK_SECRET` | Рекомендуется | Секрет для HMAC подписи webhook |
| `ALLOWED_CHANNELS` | Нет | JSON массив разрешенных каналов |
| `ALLOWED_ORIGINS` | Нет | Список разрешенных источников через запятую |
| `MAX_PAYLOAD_SIZE` | Нет | Максимальный размер payload в байтах (по умолчанию 1MB) |
| `LOG_LEVEL` | Нет | Уровень логирования: debug, info, warn, error |

### Пример ALLOWED_CHANNELS

```json
[
  {"id": "-1001234567890", "name": "Main Channel"},
  {"id": "-1001234567891", "name": "Alerts Channel"}
]
```

### Пример ALLOWED_ORIGINS

```
https://api.github.com,https://hooks.stripe.com,https://your-app.herokuapp.com
```

## Интеграция с популярными сервисами

### GitHub Actions с подписью

```yaml
- name: Notify Telegram
  env:
    WEBHOOK_URL: ${{ secrets.WEBHOOK_URL }}
    WEBHOOK_SECRET: ${{ secrets.WEBHOOK_SECRET }}
  run: |
    PAYLOAD='{"event": "deploy", "source": "github", "status": "success", "commit": "${{ github.sha }}"}'
    SIGNATURE=$(echo -n "$PAYLOAD" | openssl dgst -sha256 -hmac "$WEBHOOK_SECRET" | cut -d' ' -f2)
    curl -X POST "$WEBHOOK_URL" \
      -H "Content-Type: application/json" \
      -H "X-Webhook-Signature: sha256=$SIGNATURE" \
      -d "$PAYLOAD"
```

### Stripe webhook (автоматическая подпись)

Stripe автоматически добавляет подпись в заголовок `Stripe-Signature`. Настройте endpoint:
```
https://your-app.vercel.app/api/webhook
```

### Docker Hub

Настройте webhook в Docker Hub на ваш URL с соответствующим секретом.

## Безопасность в деталях

### Проверка подписи HMAC

Бот использует HMAC-SHA256 для проверки подлинности webhook:

```go
// Пример генерации подписи в Go
import (
    "crypto/hmac"
    "crypto/sha256"
    "encoding/hex"
)

func generateSignature(payload []byte, secret string) string {
    mac := hmac.New(sha256.New, []byte(secret))
    mac.Write(payload)
    return hex.EncodeToString(mac.Sum(nil))
}
```

### Маскирование логов

Автоматически маскируются поля содержащие:
- `token`, `password`, `secret`, `key`
- `authorization`, `api_key`, `access_token`
- `jwt`, `private_key`, `certificate`

Пример лога:
```
Webhook received from 192.168.1.1 (size: 156 bytes): {"event":"login","user":"john","password":"***MASKED***"}
```

### Валидация входных данных

- **Размер payload**: Ограничение по умолчанию 1MB
- **Content-Type**: Только разрешенные типы контента
- **HTTPS**: Принудительное использование HTTPS
- **IP логирование**: Отслеживание источников запросов

## Развертывание на других платформах

### Railway.app

1. Подключите GitHub репозиторий
2. Настройте переменные окружения
3. Railway автоматически определит Go приложение

### Render.com

1. Создайте новый Web Service
2. Подключите GitHub репозиторий
3. Установите Build Command: `go build -o main ./cmd/bot/main.go`
4. Установите Start Command: `./main`

### Fly.io

1. Установите fly CLI
2. Выполните `fly launch`
3. Настройте переменные: `fly secrets set TELEGRAM_TOKEN=your_token WEBHOOK_SECRET=your_secret`

## Мониторинг и алерты

### Логирование событий безопасности

Все подозрительные события логируются:
```
Security: Invalid method attempted: GET from 192.168.1.1
Security: Request validation failed from 192.168.1.1: payload too large
Security: Invalid webhook signature from 192.168.1.1
```

### Метрики производительности

В ответе webhook возвращается время обработки:
```json
{
  "status": "success",
  "message": "Webhook processed successfully",
  "duration_ms": 234
}
```

## Тестирование безопасности

### Проверка подписи

```bash
# Правильная подпись
echo -n '{"test": "data"}' | openssl dgst -sha256 -hmac "secret" | cut -d' ' -f2

# Тест с правильной подписью
curl -X POST https://your-app.vercel.app/api/webhook \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Signature: sha256=YOUR_SIGNATURE" \
  -d '{"test": "data"}'

# Тест с неправильной подписью (должен вернуть 401)
curl -X POST https://your-app.vercel.app/api/webhook \
  -H "Content-Type: application/json" \
  -H "X-Webhook-Signature: sha256=invalid" \
  -d '{"test": "data"}'
```

### Проверка лимитов

```bash
# Тест большого payload (должен вернуть 400)
curl -X POST https://your-app.vercel.app/api/webhook \
  -H "Content-Type: application/json" \
  -d "$(head -c 2000000 /dev/zero | tr '\0' 'a')"
```

## Лимиты и ограничения

### Vercel
- Время выполнения: 10 секунд (Hobby), 15 минут (Pro)
- Память: до 1GB
- Запросы: 100GB bandwidth в месяц (Hobby)

### Telegram
- Максимум 30 сообщений в секунду на бота
- Максимум 20 сообщений в минуту в группу/канал

### Безопасность
- Максимальный размер payload: 1MB (настраивается до 10MB)
- Время жизни подписи: без ограничений (зависит от источника)
- Rate limiting: обеспечивается Vercel

## Устранение неполадок

### Webhook отклоняется с 401
1. Проверьте правильность подписи HMAC
2. Убедитесь, что используете правильный секрет
3. Проверьте формат заголовка подписи

### Payload отклоняется с 400
1. Проверьте размер данных (максимум 1MB по умолчанию)
2. Убедитесь в правильности Content-Type
3. Проверьте что используете HTTPS

### Логи показывают маскированные данные
Это нормально! Чувствительные данные автоматически маскируются для безопасности.

## Аудит безопасности

### Регулярные проверки

1. **Ротация секретов**: Меняйте WEBHOOK_SECRET каждые 90 дней
2. **Проверка логов**: Ищите подозрительную активность
3. **Обновление зависимостей**: `go mod tidy && go mod download`
4. **Мониторинг токенов**: Убедитесь что токены не попали в логи

### Контрольный список безопасности

- [ ] WEBHOOK_SECRET установлен и сложный
- [ ] TELEGRAM_TOKEN не попадает в логи или код
- [ ] Источники webhook ограничены (ALLOWED_ORIGINS)
- [ ] Размер payload ограничен разумными рамками
- [ ] Мониторинг подозрительной активности настроен
- [ ] Регулярная ротация секретов

## Лицензия

MIT License - смотрите файл LICENSE для деталей. 