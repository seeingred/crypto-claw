package telegram

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"

	"github.com/seeingred/crypto-claw/internal/config"
	"github.com/seeingred/crypto-claw/internal/transport"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// DecisionCallback is called when the user approves or rejects a transaction.
type DecisionCallback func(txID string, approved bool)

// Bot wraps a Telegram bot for transaction notifications and approval.
type Bot struct {
	api              *tgbotapi.BotAPI
	authorizedUserID int64
	autoMode         bool
	mu               sync.RWMutex
	onDecision       DecisionCallback
	logger           *slog.Logger
	stopCh           chan struct{}
}

// New creates and starts a Telegram bot.
func New(cfg config.TelegramConfig, logger *slog.Logger) (*Bot, error) {
	api, err := tgbotapi.NewBotAPI(cfg.BotToken)
	if err != nil {
		return nil, fmt.Errorf("create telegram bot: %w", err)
	}

	b := &Bot{
		api:              api,
		authorizedUserID: cfg.AuthorizedUserID,
		logger:           logger,
		stopCh:           make(chan struct{}),
	}

	return b, nil
}

// SetDecisionCallback sets the callback invoked on user approval/rejection.
func (b *Bot) SetDecisionCallback(cb DecisionCallback) {
	b.onDecision = cb
}

// SetAutoMode toggles auto/manual mode.
func (b *Bot) SetAutoMode(auto bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.autoMode = auto
}

// AutoMode returns whether auto mode is active.
func (b *Bot) AutoMode() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.autoMode
}

// Start begins listening for updates. Blocks until Stop is called.
func (b *Bot) Start() {
	u := tgbotapi.NewUpdate(0)
	u.Timeout = 60

	updates := b.api.GetUpdatesChan(u)

	for {
		select {
		case <-b.stopCh:
			return
		case update := <-updates:
			if update.CallbackQuery != nil {
				b.handleCallback(update.CallbackQuery)
			} else if update.Message != nil {
				b.handleMessage(update.Message)
			}
		}
	}
}

// Stop stops the bot's update loop.
func (b *Bot) Stop() {
	close(b.stopCh)
	b.api.StopReceivingUpdates()
}

// NotifyTransaction sends a transaction notification with Approve/Reject buttons.
func (b *Bot) NotifyTransaction(txID string, req transport.SignRequestPayload, reason string) error {
	text := formatTxNotification(txID, req, reason)

	msg := tgbotapi.NewMessage(b.authorizedUserID, text)
	msg.ParseMode = "Markdown"
	msg.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("Approve", "approve:"+txID),
			tgbotapi.NewInlineKeyboardButtonData("Reject", "reject:"+txID),
		),
	)

	_, err := b.api.Send(msg)
	return err
}

// SendSettingsMenu sends the settings menu with auto/manual toggle.
func (b *Bot) SendSettingsMenu(chatID int64) error {
	b.mu.RLock()
	mode := "Manual"
	toggleData := "settings:auto"
	if b.autoMode {
		mode = "Auto"
		toggleData = "settings:manual"
	}
	b.mu.RUnlock()

	text := fmt.Sprintf("*Settings*\nCurrent mode: *%s*", mode)
	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = "Markdown"
	msg.ReplyMarkup = tgbotapi.NewInlineKeyboardMarkup(
		tgbotapi.NewInlineKeyboardRow(
			tgbotapi.NewInlineKeyboardButtonData("Toggle to "+toggleLabel(mode), toggleData),
		),
	)

	_, err := b.api.Send(msg)
	return err
}

// isAuthorized checks if the user is the authorized user.
func (b *Bot) isAuthorized(userID int64) bool {
	return userID == b.authorizedUserID
}

func formatTxNotification(txID string, req transport.SignRequestPayload, reason string) string {
	var sb strings.Builder
	sb.WriteString("*New Transaction for Review*\n\n")
	sb.WriteString(fmt.Sprintf("*TX ID:* `%s`\n", txID))
	sb.WriteString(fmt.Sprintf("*To:* `%s`\n", strings.Join(req.To, ", ")))
	if req.Value != "" {
		sb.WriteString(fmt.Sprintf("*Value:* %s wei\n", req.Value))
	}
	if req.Data != "" {
		display := req.Data
		if len(display) > 66 {
			display = display[:66] + "..."
		}
		sb.WriteString(fmt.Sprintf("*Data:* `%s`\n", display))
	}
	sb.WriteString(fmt.Sprintf("*Path:* %s\n", req.DerivationPath))
	if reason != "" {
		sb.WriteString(fmt.Sprintf("\n*Analyzer:* %s\n", escapeMD(reason)))
	}
	return sb.String()
}

// escapeMD escapes characters that break Telegram Markdown V1 parsing.
func escapeMD(s string) string {
	replacer := strings.NewReplacer(
		"`", "'",
		"*", "",
		"_", " ",
		"[", "(",
		"]", ")",
		"{", "(",
		"}", ")",
	)
	return replacer.Replace(s)
}

func toggleLabel(current string) string {
	if current == "Auto" {
		return "Manual"
	}
	return "Auto"
}
