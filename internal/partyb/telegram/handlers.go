package telegram

import (
	"strings"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// handleCallback processes inline keyboard button presses.
func (b *Bot) handleCallback(query *tgbotapi.CallbackQuery) {
	if !b.isAuthorized(query.From.ID) {
		b.answerCallback(query.ID, "Unauthorized")
		return
	}

	data := query.Data

	switch {
	case strings.HasPrefix(data, "approve:"):
		txID := strings.TrimPrefix(data, "approve:")
		b.handleTxDecision(query, txID, true, false)

	case strings.HasPrefix(data, "whitelist:"):
		txID := strings.TrimPrefix(data, "whitelist:")
		b.handleTxDecision(query, txID, true, true)

	case strings.HasPrefix(data, "reject:"):
		txID := strings.TrimPrefix(data, "reject:")
		b.handleTxDecision(query, txID, false, false)

	case data == "settings:auto":
		b.SetAutoMode(true)
		b.answerCallback(query.ID, "Switched to Auto mode")
		b.editSettingsMessage(query.Message)

	case data == "settings:manual":
		b.SetAutoMode(false)
		b.answerCallback(query.ID, "Switched to Manual mode")
		b.editSettingsMessage(query.Message)

	default:
		b.answerCallback(query.ID, "Unknown action")
	}
}

// handleMessage processes text commands from the authorized user.
func (b *Bot) handleMessage(msg *tgbotapi.Message) {
	if !b.isAuthorized(msg.From.ID) {
		return
	}

	switch msg.Text {
	case "/start":
		reply := tgbotapi.NewMessage(msg.Chat.ID, "Crypto Claw Party B bot active.\n\nCommands:\n/settings - Configure mode")
		b.api.Send(reply)
	case "/settings":
		b.SendSettingsMenu(msg.Chat.ID)
	default:
		reply := tgbotapi.NewMessage(msg.Chat.ID, "Unknown command. Use /settings to configure.")
		b.api.Send(reply)
	}
}

// handleTxDecision processes approve/reject/whitelist button presses.
func (b *Bot) handleTxDecision(query *tgbotapi.CallbackQuery, txID string, approved bool, whitelist bool) {
	action := "Rejected"
	if approved && whitelist {
		action = "Approved & Whitelisted"
	} else if approved {
		action = "Approved"
	}

	b.answerCallback(query.ID, action)

	// Update the message to show the decision.
	if query.Message != nil {
		edit := tgbotapi.NewEditMessageText(
			query.Message.Chat.ID,
			query.Message.MessageID,
			query.Message.Text+"\n\n*Decision: "+action+"*",
		)
		edit.ParseMode = "Markdown"
		b.api.Send(edit)
	}

	// Whitelist the address if requested.
	if whitelist && b.onWhitelist != nil {
		b.onWhitelist(txID)
	}

	// Route decision back to the service.
	if b.onDecision != nil {
		b.onDecision(txID, approved)
	}
}

// answerCallback sends an acknowledgment to a callback query.
func (b *Bot) answerCallback(callbackID, text string) {
	callback := tgbotapi.NewCallback(callbackID, text)
	if _, err := b.api.Request(callback); err != nil {
		b.logger.Error("failed to answer callback", "err", err)
	}
}

// editSettingsMessage updates an existing settings message after toggle.
func (b *Bot) editSettingsMessage(msg *tgbotapi.Message) {
	if msg == nil {
		return
	}

	b.mu.RLock()
	mode := "Manual"
	toggleData := "settings:auto"
	if b.autoMode {
		mode = "Auto"
		toggleData = "settings:manual"
	}
	b.mu.RUnlock()

	text := "*Settings*\nCurrent mode: *" + mode + "*"
	edit := tgbotapi.NewEditMessageTextAndMarkup(
		msg.Chat.ID,
		msg.MessageID,
		text,
		tgbotapi.NewInlineKeyboardMarkup(
			tgbotapi.NewInlineKeyboardRow(
				tgbotapi.NewInlineKeyboardButtonData("Toggle to "+toggleLabel(mode), toggleData),
			),
		),
	)
	edit.ParseMode = "Markdown"
	b.api.Send(edit)
}
