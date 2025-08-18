package telegram

import (
	"fmt"
	"log"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// Client обертка для работы с Telegram Bot API
type Client struct {
	bot *tgbotapi.BotAPI
}

// NewClient создает новый Telegram клиент
func NewClient(token string) (*Client, error) {
	bot, err := tgbotapi.NewBotAPI(token)
	if err != nil {
		return nil, fmt.Errorf("failed to create telegram bot: %w", err)
	}

	return &Client{bot: bot}, nil
}

// SendMessage отправляет текстовое сообщение в указанный канал
func (c *Client) SendMessage(channelID int64, text string) error {
	msg := tgbotapi.NewMessage(channelID, text)
	msg.ParseMode = tgbotapi.ModeMarkdown

	_, err := c.bot.Send(msg)
	if err != nil {
		return fmt.Errorf("failed to send message to channel %d: %w", channelID, err)
	}

	log.Printf("Message sent successfully to channel %d", channelID)
	return nil
}

// SendFormattedMessage отправляет форматированное сообщение
func (c *Client) SendFormattedMessage(channelID int64, text string, parseMode string) error {
	msg := tgbotapi.NewMessage(channelID, text)
	
	switch parseMode {
	case "markdown":
		msg.ParseMode = tgbotapi.ModeMarkdown
	case "html":
		msg.ParseMode = tgbotapi.ModeHTML
	default:
		msg.ParseMode = ""
	}

	_, err := c.bot.Send(msg)
	if err != nil {
		return fmt.Errorf("failed to send formatted message to channel %d: %w", channelID, err)
	}

	log.Printf("Formatted message sent successfully to channel %d", channelID)
	return nil
}

// GetMe возвращает информацию о боте
func (c *Client) GetMe() (*tgbotapi.User, error) {
	user, err := c.bot.GetMe()
	if err != nil {
		return nil, fmt.Errorf("failed to get bot info: %w", err)
	}

	return &user, nil
}

// SetWebhook устанавливает webhook для бота
func (c *Client) SetWebhook(webhookURL string) error {
	webhookConfig := tgbotapi.NewWebhook(webhookURL)
	
	_, err := c.bot.Request(webhookConfig)
	if err != nil {
		return fmt.Errorf("failed to set webhook: %w", err)
	}

	log.Printf("Webhook set successfully: %s", webhookURL)
	return nil
} 