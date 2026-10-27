package models

import "github.com/trauringetag/synapse-backend/internal/domain"

const (
	RoleUser       = domain.RoleUser
	RoleAdmin      = domain.RoleAdmin
	StatusActive   = domain.StatusActive
	StatusInactive = domain.StatusInactive
)

type User = domain.User
type RefreshToken = domain.RefreshToken
