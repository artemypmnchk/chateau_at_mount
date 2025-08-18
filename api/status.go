package handler

import (
	"encoding/json"
	"log"
	"net/http"
	"os"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// StatusResponse структура ответа статуса
type StatusResponse struct {
	Status     string                 `json:"status"`
	BotInfo    map[string]interface{} `json:"bot_info,omitempty"`
	Config     map[string]interface{} `json:"config,omitempty"`
	Error      string                 `json:"error,omitempty"`
	WebhookURL string                 `json:"webhook_url"`
}

// Status обрабатывает запросы статуса бота
func Status(w http.ResponseWriter, r *http.Request) {
	// Устанавливаем заголовки
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	response := StatusResponse{
		WebhookURL: "https://" + r.Host + "/api/webhook",
	}

	// Получаем переменные окружения
	telegramToken := os.Getenv("TELEGRAM_TOKEN")
	webhookSecret := os.Getenv("WEBHOOK_SECRET")
	channelID := os.Getenv("TELEGRAM_CHANNEL_ID")

	// Проверяем конфигурацию
	response.Config = map[string]interface{}{
		"has_telegram_token": telegramToken != "",
		"has_webhook_secret": webhookSecret != "",
		"default_channel_id": channelID,
	}

	// Если токен не задан, возвращаем ошибку
	if telegramToken == "" {
		response.Status = "error"
		response.Error = "Telegram token not configured"
		writeJSONResponse(w, response, http.StatusInternalServerError)
		return
	}

	// Создаем клиент и получаем информацию о боте
	bot, err := tgbotapi.NewBotAPI(telegramToken)
	if err != nil {
		response.Status = "error"
		response.Error = "Failed to create Telegram client: " + err.Error()
		writeJSONResponse(w, response, http.StatusInternalServerError)
		return
	}

	// Получаем информацию о боте
	botInfo, err := bot.GetMe()
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