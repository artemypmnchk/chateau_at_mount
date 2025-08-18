package handler

import (
	"encoding/json"
	"log"
	"net/http"

	"chateau-bot/pkg/config"
	"chateau-bot/pkg/telegram"
)

// StatusResponse структура ответа статуса
type StatusResponse struct {
	Status    string                 `json:"status"`
	BotInfo   map[string]interface{} `json:"bot_info,omitempty"`
	Config    map[string]interface{} `json:"config,omitempty"`
	Error     string                 `json:"error,omitempty"`
	Timestamp string                 `json:"timestamp"`
	WebhookURL string                `json:"webhook_url"`
}

// Status обрабатывает запросы статуса бота
func Status(w http.ResponseWriter, r *http.Request) {
	// Устанавливаем заголовки
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	response := StatusResponse{
		Timestamp:  "2024-01-01T00:00:00Z", // В реальности используйте time.Now()
		WebhookURL: r.Host + "/api/webhook",
	}

	// Загружаем конфигурацию
	cfg, err := config.Load()
	if err != nil {
		response.Status = "error"
		response.Error = "Configuration error: " + err.Error()
		writeJSONResponse(w, response, http.StatusInternalServerError)
		return
	}

	// Проверяем конфигурацию
	response.Config = map[string]interface{}{
		"has_telegram_token": cfg.TelegramToken != "",
		"has_webhook_secret": cfg.WebhookSecret != "",
		"default_channel_id": cfg.DefaultChannelID,
		"allowed_channels_count": len(cfg.AllowedChannels),
	}

	// Если токен не задан, возвращаем ошибку
	if cfg.TelegramToken == "" {
		response.Status = "error"
		response.Error = "Telegram token not configured"
		writeJSONResponse(w, response, http.StatusInternalServerError)
		return
	}

	// Создаем клиент и получаем информацию о боте
	tgClient, err := telegram.NewClient(cfg.TelegramToken)
	if err != nil {
		response.Status = "error"
		response.Error = "Failed to create Telegram client: " + err.Error()
		writeJSONResponse(w, response, http.StatusInternalServerError)
		return
	}

	// Получаем информацию о боте
	botInfo, err := tgClient.GetMe()
	if err != nil {
		response.Status = "error"
		response.Error = "Failed to get bot info: " + err.Error()
		writeJSONResponse(w, response, http.StatusInternalServerError)
		return
	}

	// Заполняем информацию о боте
	response.Status = "ok"
	response.BotInfo = map[string]interface{}{
		"id":         botInfo.ID,
		"username":   botInfo.UserName,
		"first_name": botInfo.FirstName,
		"is_bot":     botInfo.IsBot,
	}

	writeJSONResponse(w, response, http.StatusOK)
}

// writeJSONResponse записывает JSON ответ
func writeJSONResponse(w http.ResponseWriter, data interface{}, statusCode int) {
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		log.Printf("Failed to encode JSON response: %v", err)
	}
} 