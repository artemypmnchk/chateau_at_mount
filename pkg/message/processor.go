package message

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// WebhookData представляет общую структуру входящих webhook данных
type WebhookData struct {
	Event     string                 `json:"event"`
	Timestamp time.Time              `json:"timestamp"`
	Data      map[string]interface{} `json:"data"`
	Source    string                 `json:"source"`
}

// Processor обрабатывает и форматирует сообщения
type Processor struct{}

// NewProcessor создает новый процессор сообщений
func NewProcessor() *Processor {
	return &Processor{}
}

// ProcessWebhook обрабатывает входящий webhook и возвращает сообщение для отправки
func (p *Processor) ProcessWebhook(rawData []byte) (string, error) {
	// Попробуем распарсить как структурированные данные
	var webhookData WebhookData
	if err := json.Unmarshal(rawData, &webhookData); err == nil {
		return p.formatStructuredMessage(webhookData), nil
	}

	// Если не получилось, попробуем как JSON объект
	var jsonData map[string]interface{}
	if err := json.Unmarshal(rawData, &jsonData); err == nil {
		return p.formatJSONMessage(jsonData), nil
	}

	// В крайнем случае, отправим как есть
	return p.formatRawMessage(string(rawData)), nil
}

// formatStructuredMessage форматирует структурированное сообщение
func (p *Processor) formatStructuredMessage(data WebhookData) string {
	var builder strings.Builder

	builder.WriteString("🔔 **Новое уведомление**\n\n")
	
	if data.Source != "" {
		builder.WriteString(fmt.Sprintf("**Источник:** %s\n", data.Source))
	}
	
	if data.Event != "" {
		builder.WriteString(fmt.Sprintf("**Событие:** %s\n", data.Event))
	}
	
	if !data.Timestamp.IsZero() {
		builder.WriteString(fmt.Sprintf("**Время:** %s\n", data.Timestamp.Format("2006-01-02 15:04:05")))
	}

	if len(data.Data) > 0 {
		builder.WriteString("\n**Данные:**\n")
		for key, value := range data.Data {
			builder.WriteString(fmt.Sprintf("• **%s:** %v\n", key, value))
		}
	}

	return builder.String()
}

// formatJSONMessage форматирует произвольный JSON
func (p *Processor) formatJSONMessage(data map[string]interface{}) string {
	var builder strings.Builder

	builder.WriteString("📦 **Webhook данные**\n\n")

	for key, value := range data {
		// Особая обработка для некоторых общих полей
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

// formatRawMessage форматирует сырые данные
func (p *Processor) formatRawMessage(data string) string {
	return fmt.Sprintf("📝 **Сырые данные webhook**\n\n```\n%s\n```", data)
}

// CreateCustomMessage создает кастомное сообщение
func (p *Processor) CreateCustomMessage(title, content string) string {
	return fmt.Sprintf("ℹ️ **%s**\n\n%s", title, content)
}

// CreateErrorMessage создает сообщение об ошибке
func (p *Processor) CreateErrorMessage(err error) string {
	return fmt.Sprintf("❌ **Ошибка обработки webhook**\n\n```\n%s\n```", err.Error())
}

// CreateSuccessMessage создает сообщение об успехе
func (p *Processor) CreateSuccessMessage(operation string) string {
	return fmt.Sprintf("✅ **Операция выполнена успешно**\n\n%s", operation)
} 