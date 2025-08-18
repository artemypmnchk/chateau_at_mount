package security

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
)

const (
	MaxPayloadSize = 1024 * 1024 // 1MB максимальный размер payload
	MaxHeaderSize  = 8192        // 8KB максимальный размер заголовков
)

// SecurityConfig содержит настройки безопасности
type SecurityConfig struct {
	WebhookSecret   string
	RequireHTTPS    bool
	AllowedOrigins  []string
	MaxPayloadSize  int64
}

// Validator проверяет безопасность входящих запросов
type Validator struct {
	config SecurityConfig
}

// NewValidator создает новый валидатор безопасности
func NewValidator(config SecurityConfig) *Validator {
	if config.MaxPayloadSize == 0 {
		config.MaxPayloadSize = MaxPayloadSize
	}
	return &Validator{config: config}
}

// ValidateRequest проверяет запрос на соответствие требованиям безопасности
func (v *Validator) ValidateRequest(r *http.Request) error {
	// Проверка HTTPS (в продакшене Vercel автоматически перенаправляет)
	if v.config.RequireHTTPS && r.Header.Get("X-Forwarded-Proto") != "https" {
		return fmt.Errorf("HTTPS required")
	}

	// Проверка размера Content-Length
	if r.ContentLength > v.config.MaxPayloadSize {
		return fmt.Errorf("payload too large: %d bytes (max: %d)", r.ContentLength, v.config.MaxPayloadSize)
	}

	// Проверка Content-Type
	contentType := r.Header.Get("Content-Type")
	if contentType == "" {
		return fmt.Errorf("Content-Type header required")
	}

	// Разрешенные Content-Type
	allowedTypes := []string{
		"application/json",
		"application/x-www-form-urlencoded",
		"text/plain",
	}
	
	isValidType := false
	for _, allowedType := range allowedTypes {
		if strings.HasPrefix(contentType, allowedType) {
			isValidType = true
			break
		}
	}
	
	if !isValidType {
		return fmt.Errorf("unsupported Content-Type: %s", contentType)
	}

	return nil
}

// ValidateWebhookSignature проверяет подпись webhook
func (v *Validator) ValidateWebhookSignature(body []byte, signature string) error {
	if v.config.WebhookSecret == "" {
		// Если секрет не настроен, пропускаем проверку (но логируем предупреждение)
		return nil
	}

	if signature == "" {
		return fmt.Errorf("webhook signature required")
	}

	// Убираем префикс "sha256=" если он есть
	signature = strings.TrimPrefix(signature, "sha256=")

	// Вычисляем ожидаемую подпись
	mac := hmac.New(sha256.New, []byte(v.config.WebhookSecret))
	mac.Write(body)
	expectedSignature := hex.EncodeToString(mac.Sum(nil))

	// Сравниваем подписи безопасным способом
	if !hmac.Equal([]byte(signature), []byte(expectedSignature)) {
		return fmt.Errorf("invalid webhook signature")
	}

	return nil
}

// SanitizeLogData маскирует чувствительные данные для логирования
func (v *Validator) SanitizeLogData(data string) string {
	// Список ключей, которые нужно маскировать
	sensitiveKeys := []string{
		"token", "password", "secret", "key", "authorization",
		"api_key", "access_token", "refresh_token", "jwt",
		"private_key", "cert", "certificate",
	}

	sanitized := data
	
	// Простое маскирование JSON полей
	for _, key := range sensitiveKeys {
		// Маскируем значения в JSON
		patterns := []string{
			fmt.Sprintf(`"%s":"[^"]*"`, key),
			fmt.Sprintf(`"%s":\s*"[^"]*"`, key),
			fmt.Sprintf(`'%s':'[^']*'`, key),
			fmt.Sprintf(`'%s':\s*'[^']*'`, key),
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

// ValidateOrigin проверяет источник запроса
func (v *Validator) ValidateOrigin(origin string) error {
	if len(v.config.AllowedOrigins) == 0 {
		// Если список источников не задан, разрешаем все
		return nil
	}

	for _, allowedOrigin := range v.config.AllowedOrigins {
		if origin == allowedOrigin || allowedOrigin == "*" {
			return nil
		}
	}

	return fmt.Errorf("origin not allowed: %s", origin)
} 