package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"github.com/trauringetag/synapse-backend/internal/infrastructure/config"
	"github.com/trauringetag/synapse-backend/internal/messages"
)

type Claims struct {
	Role  string `json:"role"`
	Email string `json:"email"`
	jwt.RegisteredClaims
}

type Pair struct {
	AccessToken  string
	RefreshToken string
	AccessExp    time.Time
	RefreshExp   time.Time
}

func IssuePair(cfg *config.Config, userID uuid.UUID, email, role string) (*Pair, error) {
	now := time.Now()
	accessExp := now.Add(cfg.AccessTTL)
	refreshExp := now.Add(cfg.RefreshTTL)

	access, err := sign(cfg, userID, email, role, "access", uuid.NewString(), now, accessExp)
	if err != nil {
		return nil, err
	}
	refresh, err := sign(cfg, userID, email, role, "refresh", uuid.NewString(), now, refreshExp)
	if err != nil {
		return nil, err
	}
	return &Pair{
		AccessToken:  access,
		RefreshToken: refresh,
		AccessExp:    accessExp,
		RefreshExp:   refreshExp,
	}, nil
}

func sign(cfg *config.Config, userID uuid.UUID, email, role, tokenType, jti string, now, exp time.Time) (string, error) {
	claims := Claims{
		Role:  role,
		Email: email,
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   userID.String(),
			ID:        jti,
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(exp),
			Issuer:    "synapse-backend",
			Audience:  []string{tokenType},
		},
	}
	t := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return t.SignedString(cfg.JWTSecret)
}

func Parse(cfg *config.Config, tokenString, expectedType string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (any, error) {
		if t.Method != jwt.SigningMethodHS256 || t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf(messages.UnexpectedSigningMethod)
		}
		return cfg.JWTSecret, nil
	},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
		jwt.WithIssuer("synapse-backend"),
		jwt.WithAudience(expectedType),
		jwt.WithExpirationRequired(),
	)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf(messages.InvalidToken)
	}
	aud, err := claims.GetAudience()
	if err != nil || len(aud) != 1 || aud[0] != expectedType {
		return nil, fmt.Errorf(messages.InvalidTokenPurpose)
	}
	return claims, nil
}

func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
