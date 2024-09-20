package config

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"github.com/google/uuid"
	"go.lumeweb.com/portal/config"
	"strconv"
)

var _ config.APIConfig = (*APIConfig)(nil)
var _ config.Validator = (*APIConfig)(nil)

type APIConfig struct {
	ClientID         string `mapstructure:"client_id"`
	ClientSecret     string `mapstructure:"client_secret"`
	SupportPortalURL string `mapstructure:"support_portal_url"`
	MailboxID        string `mapstructure:"mailbox_id"`
}

func (a APIConfig) Defaults() map[string]any {
	var clientId uuid.UUID
	var clientSecret string

	if a.ClientID == "" {
		clientId = uuid.New()
	}

	if a.ClientSecret == "" {
		secretBytes := make([]byte, 32)
		_, err := rand.Read(secretBytes)
		if err != nil {
			panic(err)
		}
		clientSecret = base64.URLEncoding.EncodeToString(secretBytes)
	}

	return map[string]any{
		"client_id":          clientId.String(),
		"client_secret":      clientSecret,
		"support_portal_url": "",
		"mailbox_id":         "",
	}
}

func (a APIConfig) Validate() error {
	if a.ClientID == "" {
		return errors.New("client_id is required")
	}

	if a.ClientSecret == "" {
		return errors.New("client_secret is required")
	}

	if a.SupportPortalURL == "" {
		return errors.New("support_portal_url is required")
	}

	if a.MailboxID == "" {
		return errors.New("mailbox_id is required")
	}

	if _, err := strconv.ParseUint(a.MailboxID, 10, 64); err != nil {
		return errors.New("mailbox_id must be a valid number")
	}

	return nil
}
