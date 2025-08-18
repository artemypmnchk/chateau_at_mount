package config

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config содержит конфигурацию для serverless функций
type Config struct {
	TelegramToken    string
	WebhookSecret    string
	DefaultChannelID string
	AllowedChannels  []string
	AllowedOrigins   []string
	MaxPayloadSize   int64
	LogLevel         string
}

// ChannelInfo содержит информацию о канале
type ChannelInfo struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Load загружает конфигурацию из переменных окружения
func Load() (*Config, error) {
	config := &Config{
		TelegramToken:    os.Getenv("TELEGRAM_TOKEN"),
		WebhookSecret:    os.Getenv("WEBHOOK_SECRET"),
		DefaultChannelID: os.Getenv("DEFAULT_CHANNEL_ID"),
		LogLevel:         getEnvWithDefault("LOG_LEVEL", "info"),
		MaxPayloadSize:   1024 * 1024, // 1MB по умолчанию
	}

	// Загружаем максимальный размер payload
	if payloadSizeStr := os.Getenv("MAX_PAYLOAD_SIZE"); payloadSizeStr != "" {
		if size, err := strconv.ParseInt(payloadSizeStr, 10, 64); err == nil {
			config.MaxPayloadSize = size
		}
	}

	// Загружаем список разрешенных каналов из JSON
	if channelsJSON := os.Getenv("ALLOWED_CHANNELS"); channelsJSON != "" {
		var channels []ChannelInfo
		if err := json.Unmarshal([]byte(channelsJSON), &channels); err == nil {
			config.AllowedChannels = make([]string, len(channels))
			for i, ch := range channels {
				config.AllowedChannels[i] = ch.ID
			}
		}
	}

	// Загружаем разрешенные источники
	if originsStr := os.Getenv("ALLOWED_ORIGINS"); originsStr != "" {
		config.AllowedOrigins = strings.Split(originsStr, ",")
		for i, origin := range config.AllowedOrigins {
			config.AllowedOrigins[i] = strings.TrimSpace(origin)
		}
	}

	// Валидация конфигурации
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("config validation failed: %w", err)
	}

	return config, nil
}

// validate проверяет обязательные параметры конфигурации
func (c *Config) validate() error {
	if c.TelegramToken == "" {
		return fmt.Errorf("TELEGRAM_TOKEN is required")
	}

	// Проверяем формат токена Telegram
	if !strings.Contains(c.TelegramToken, ":") {
		return fmt.Errorf("TELEGRAM_TOKEN has invalid format")
	}

	// Проверяем, что есть хотя бы один канал
	if c.DefaultChannelID == "" && len(c.AllowedChannels) == 0 {
		return fmt.Errorf("DEFAULT_CHANNEL_ID or ALLOWED_CHANNELS must be configured")
	}

	// Проверяем размер payload
	if c.MaxPayloadSize <= 0 || c.MaxPayloadSize > 10*1024*1024 { // Максимум 10MB
		return fmt.Errorf("MAX_PAYLOAD_SIZE must be between 1 and 10485760 bytes")
	}

	// Если WebhookSecret не задан, выводим предупреждение (но не ошибку)
	if c.WebhookSecret == "" {
		fmt.Println("WARNING: WEBHOOK_SECRET not configured - webhook signature validation disabled")
	}

	return nil
}

// IsChannelAllowed проверяет, разрешен ли канал для отправки
func (c *Config) IsChannelAllowed(channelID string) bool {
	// Если список не задан, используем канал по умолчанию
	if len(c.AllowedChannels) == 0 {
		return channelID == c.DefaultChannelID
	}

	for _, allowedID := range c.AllowedChannels {
		if allowedID == channelID {
			return true
		}
	}
	return false
}

// GetChannelID возвращает ID канала для отправки сообщений
func (c *Config) GetChannelID() string {
	if c.DefaultChannelID != "" {
		return c.DefaultChannelID
	}
	
	if len(c.AllowedChannels) > 0 {
		return c.AllowedChannels[0]
	}
	
	return ""
}

// GetChannelIDInt64 возвращает ID канала как int64 для telegram-bot-api
func (c *Config) GetChannelIDInt64() (int64, error) {
	channelID := c.GetChannelID()
	if channelID == "" {
		return 0, fmt.Errorf("no channel configured")
	}
	
	id, err := strconv.ParseInt(channelID, 10, 64)
	if err != nil {
		return 0, fmt.Errorf("invalid channel ID format: %w", err)
	}
	
	return id, nil
}

// IsSensitiveData проверяет, содержит ли строка чувствительные данные
func (c *Config) IsSensitiveData(data string) bool {
	sensitivePatterns := []string{
		c.TelegramToken,
		c.WebhookSecret,
	}
	
	dataLower := strings.ToLower(data)
	for _, pattern := range sensitivePatterns {
		if pattern != "" && strings.Contains(dataLower, strings.ToLower(pattern)) {
			return true
		}
	}
	
	return false
}

// getEnvWithDefault возвращает значение переменной окружения или значение по умолчанию
func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
} 