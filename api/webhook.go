package handler

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// Handler обрабатывает webhook запросы для Vercel
func Handler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	
	// Устанавливаем безопасные заголовки
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Methods", "POST")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Webhook-Signature")

	// Обрабатываем OPTIONS запрос
	if r.Method == http.MethodOptions {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Принимаем только POST запросы
	if r.Method != http.MethodPost {
		log.Printf("Security: Invalid method attempted: %s from %s", r.Method, getClientIP(r))
		http.Error(w, `{"error":"Method not allowed"}`, http.StatusMethodNotAllowed)
		return
	}

	// Получаем переменные окружения
	telegramToken := os.Getenv("TELEGRAM_TOKEN")
	webhookSecret := os.Getenv("WEBHOOK_SECRET")
	channelID := os.Getenv("TELEGRAM_CHANNEL_ID")

	if telegramToken == "" {
		log.Printf("Security: Telegram token not configured")
		http.Error(w, `{"error":"Bot not configured"}`, http.StatusInternalServerError)
		return
	}

	if channelID == "" {
		log.Printf("Error: No channel configured")
		http.Error(w, `{"error":"No channel configured"}`, http.StatusInternalServerError)
		return
	}

	// Ограничиваем размер тела запроса
	r.Body = http.MaxBytesReader(w, r.Body, 1024*1024) // 1MB

	// Читаем тело запроса
	body, err := io.ReadAll(r.Body)
	if err != nil {
		log.Printf("Security: Failed to read request body from %s: %v", getClientIP(r), err)
		http.Error(w, `{"error":"Failed to read request"}`, http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	// Проверяем подпись webhook (если настроена)
	if webhookSecret != "" {
		signature := r.Header.Get("X-Webhook-Signature")
		if signature == "" {
			signature = r.Header.Get("X-Hub-Signature-256") // GitHub style
		}
		
		if err := validateWebhookSignature(body, signature, webhookSecret); err != nil {
			log.Printf("Security: Invalid webhook signature from %s: %v", getClientIP(r), err)
			http.Error(w, `{"error":"Invalid signature"}`, http.StatusUnauthorized)
			return
		}
	}

	// Логируем безопасно (маскируем чувствительные данные)
	sanitizedBody := sanitizeLogData(string(body))
	log.Printf("Webhook received from %s (size: %d bytes): %s", getClientIP(r), len(body), sanitizedBody)

	// Создаем Telegram клиент
	bot, err := tgbotapi.NewBotAPI(telegramToken)
	if err != nil {
		log.Printf("Error: Failed to create Telegram client: %v", err)
		http.Error(w, `{"error":"Telegram client error"}`, http.StatusInternalServerError)
		return
	}

	// Обрабатываем сообщение
	messageText := processWebhook(body)

	// Конвертируем ID канала в int64
	channelIDInt, err := strconv.ParseInt(channelID, 10, 64)
	if err != nil {
		log.Printf("Error: Failed to parse channel ID: %v", err)
		http.Error(w, `{"error":"Invalid channel configuration"}`, http.StatusInternalServerError)
		return
	}

	// Отправляем сообщение в Telegram
	msg := tgbotapi.NewMessage(channelIDInt, messageText)
	msg.ParseMode = tgbotapi.ModeMarkdown

	if _, err := bot.Send(msg); err != nil {
		log.Printf("Error: Failed to send message to channel %d: %v", channelIDInt, err)
		http.Error(w, `{"error":"Failed to send message"}`, http.StatusInternalServerError)
		return
	}

	duration := time.Since(startTime)
	
	// Возвращаем успешный ответ
	w.WriteHeader(http.StatusOK)
	response := fmt.Sprintf(`{"status":"success","message":"Webhook processed successfully","duration_ms":%d}`, duration.Milliseconds())
	w.Write([]byte(response))
	
	log.Printf("Webhook processed successfully in %v for client %s", duration, getClientIP(r))
}

// validateWebhookSignature проверяет подпись webhook
func validateWebhookSignature(body []byte, signature string, secret string) error {
	if signature == "" {
		return fmt.Errorf("webhook signature required")
	}

	// Убираем префикс "sha256=" если он есть
	signature = strings.TrimPrefix(signature, "sha256=")

	// Вычисляем ожидаемую подпись
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expectedSignature := hex.EncodeToString(mac.Sum(nil))

	// Сравниваем подписи безопасным способом
	if !hmac.Equal([]byte(signature), []byte(expectedSignature)) {
		return fmt.Errorf("invalid webhook signature")
	}

	return nil
}

// sanitizeLogData маскирует чувствительные данные для логирования
func sanitizeLogData(data string) string {
	sensitiveKeys := []string{
		"token", "password", "secret", "key", "authorization",
		"api_key", "access_token", "refresh_token", "jwt",
	}

	sanitized := data
	
	for _, key := range sensitiveKeys {
		patterns := []string{
			fmt.Sprintf(`"%s":"[^"]*"`, key),
			fmt.Sprintf(`"%s":\s*"[^"]*"`, key),
		}
		
		for _, pattern := range patterns {
			sanitized = strings.ReplaceAll(sanitized, pattern, fmt.Sprintf(`"%s":"***MASKED***"`, key))
		}
	}

	// Ограничиваем длину для логов
	if len(sanitized) > 500 {
		sanitized = sanitized[:500] + "...[TRUNCATED]"
	}

	return sanitized
}

// processWebhook обрабатывает входящий webhook и возвращает сообщение для отправки
func processWebhook(rawData []byte) string {
	// Попробуем распарсить как JSON объект
	var jsonData map[string]interface{}
	if err := json.Unmarshal(rawData, &jsonData); err == nil {
		return formatJSONMessage(jsonData)
	}

	// В крайнем случае, отправим как есть
	return fmt.Sprintf("📝 **Webhook данные**\n\n```\n%s\n```", string(rawData))
}

// formatJSONMessage форматирует произвольный JSON
func formatJSONMessage(data map[string]interface{}) string {
	var builder strings.Builder

	builder.WriteString("📦 **Webhook данные**\n\n")

	for key, value := range data {
		switch key {
		case "event", "type", "action":
			builder.WriteString(fmt.Sprintf("**Событие:** %v\n", value))
		case "timestamp", "time", "created_at":
			builder.WriteString(fmt.Sprintf("**Время:** %v\n", value))
		case "user", "username", "author":
			builder.WriteString(fmt.Sprintf("**Пользователь:** %v\n", value))
		case "message", "description", "text":
			builder.WriteString(fmt.Sprintf("**Сообщение:** %v\n", value))
		default:
			builder.WriteString(fmt.Sprintf("**%s:** %v\n", key, value))
		}
	}

	return builder.String()
}

// getClientIP безопасно получает IP клиента
func getClientIP(r *http.Request) string {
	clientIP := r.Header.Get("X-Forwarded-For")
	if clientIP != "" {
		if idx := strings.Index(clientIP, ","); idx != -1 {
			clientIP = clientIP[:idx]
		}
		return strings.TrimSpace(clientIP)
	}

	clientIP = r.Header.Get("X-Real-IP")
	if clientIP != "" {
		return clientIP
	}

	clientIP = r.Header.Get("CF-Connecting-IP")
	if clientIP != "" {
		return clientIP
	}

	return r.RemoteAddr
} 