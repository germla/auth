package auth_identity

import (
	"time"

	"github.com/qor/auth/claims"
	"github.com/uptrace/bun"
)

// AuthIdentity auth identity session model
type AuthIdentity struct {
	bun.BaseModel
	Basic
	SignLogs
}

// Basic basic information about auth identity
type Basic struct {
	Provider          string
	UID               string `bun:"uid"`
	EncryptedPassword string
	UserID            string
	ConfirmedAt       *time.Time
}

// ToClaims convert to auth Claims
func (basic Basic) ToClaims() *claims.Claims {
	claims := claims.Claims{}
	claims.Provider = basic.Provider
	claims.Id = basic.UID
	claims.UserID = basic.UserID
	return &claims
}
