package handler

import (
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"chateau-bot/pkg/config"
	"chateau-bot/pkg/message"
	"chateau-bot/pkg/security"
	"chateau-bot/pkg/telegram"
)

// Handler обрабатывает webhook запросы для Vercel с улучшенной безопасностью
func Handler(w http.ResponseWriter, r *http.Request) {
	startTime := time.Now()
	
	// Устанавливаем безопасные заголовки
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Content-Type", "application/json")

	// Ограниченные CORS заголовки
	w.Header().Set("Access-Control-Allow-Methods", "POST")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, X-Webhook-Signature")
	w.Header().Set("Access-Control-Max-Age", "3600")

	// Обрабатываем OPTIONS запрос для CORS
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

	// Загружаем конфигурацию
	cfg, err := config.Load()
	if err != nil {
		log.Printf("Security: Failed to load config: %v", err)
		http.Error(w, `{"error":"Configuration error"}`, http.StatusInternalServerError)
		return
	}

	// Проверяем наличие токена
	if cfg.TelegramToken == "" {
		log.Printf("Security: Telegram token not configured")
		http.Error(w, `{"error":"Bot not configured"}`, http.StatusInternalServerError)
		return
	}

	// Создаем валидатор безопасности
	validator := security.NewValidator(security.SecurityConfig{
		WebhookSecret:  cfg.WebhookSecret,
		RequireHTTPS:   true,
		MaxPayloadSize: 1024 * 1024, // 1MB
	})

	// Валидируем запрос
	if err := validator.ValidateRequest(r); err != nil {
		log.Printf("Security: Request validation failed from %s: %v", getClientIP(r), err)
		http.Error(w, `{"error":"Request validation failed"}`, http.StatusBadRequest)
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
	signature := r.Header.Get("X-Webhook-Signature")
	if signature == "" {
		signature = r.Header.Get("X-Hub-Signature-256") // GitHub style
	}
	
	if err := validator.ValidateWebhookSignature(body, signature); err != nil {
		log.Printf("Security: Invalid webhook signature from %s: %v", getClientIP(r), err)
		http.Error(w, `{"error":"Invalid signature"}`, http.StatusUnauthorized)
		return
	}

	// Логируем безопасно (маскируем чувствительные данные)
	sanitizedBody := validator.SanitizeLogData(string(body))
	log.Printf("Webhook received from %s (size: %d bytes): %s", getClientIP(r), len(body), sanitizedBody)

	// Создаем Telegram клиент
	tgClient, err := telegram.NewClient(cfg.TelegramToken)
	if err != nil {
		log.Printf("Error: Failed to create Telegram client: %v", err)
		http.Error(w, `{"error":"Telegram client error"}`, http.StatusInternalServerError)
		return
	}

	// Обрабатываем сообщение
	processor := message.NewProcessor()
	messageText, err := processor.ProcessWebhook(body)
	if err != nil {
		log.Printf("Warning: Failed to process webhook: %v", err)
		messageText = processor.CreateErrorMessage(err)
	}

	// Получаем ID канала для отправки
	channelID, err := cfg.GetChannelIDInt64()
	if err != nil {
		log.Printf("Error: Failed to parse channel ID: %v", err)
		http.Error(w, `{"error":"Invalid channel configuration"}`, http.StatusInternalServerError)
		return
	}

	if channelID == 0 {
		log.Printf("Error: No channel configured")
		http.Error(w, `{"error":"No channel configured"}`, http.StatusInternalServerError)
		return
	}

	// Отправляем сообщение в Telegram
	if err := tgClient.SendMessage(channelID, messageText); err != nil {
		log.Printf("Error: Failed to send message to channel %d: %v", channelID, err)
		http.Error(w, `{"error":"Failed to send message"}`, http.StatusInternalServerError)
		return
	}

	duration := time.Since(startTime)
	
	// Возвращаем успешный ответ
	w.WriteHeader(http.StatusOK)
	response := `{"status":"success","message":"Webhook processed successfully","duration_ms":` + strconv.FormatInt(duration.Milliseconds(), 10) + `}`
	w.Write([]byte(response))
	
	log.Printf("Webhook processed successfully in %v for client %s", duration, getClientIP(r))
}

// getClientIP безопасно получает IP клиента
func getClientIP(r *http.Request) string {
	// Проверяем заголовки в порядке приоритета
	clientIP := r.Header.Get("X-Forwarded-For")
	if clientIP != "" {
		// X-Forwarded-For может содержать несколько IP через запятую
		// Берем первый (оригинальный клиент)
		if idx := strings.Index(clientIP, ","); idx != -1 {
			clientIP = clientIP[:idx]
		}
		return strings.TrimSpace(clientIP)
	}

	clientIP = r.Header.Get("X-Real-IP")
	if clientIP != "" {
		return clientIP
	}

	clientIP = r.Header.Get("CF-Connecting-IP") // Cloudflare
	if clientIP != "" {
		return clientIP
	}

	// Fallback к RemoteAddr
	return r.RemoteAddr
} 