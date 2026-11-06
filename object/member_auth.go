package object

import (
	"crypto/subtle"
	"errors"
	"fmt"

	"github.com/casdoor/casdoor/conf"
	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrMemberUnauthenticated = errors.New("member access token is inactive")
	ErrMemberAppDenied       = errors.New("member application is not allowed")
	ErrMemberConflict        = errors.New("member operation conflict")
	ErrMemberInvalid         = errors.New("invalid member operation")
)

func MemberScopeAllowed(application *Application, scope string) bool {
	if application != nil {
		for _, item := range application.Scopes {
			if item != nil && item.Name == scope {
				return true
			}
		}
	}
	return false
}

func GetActiveMember(application *Application, raw string) (*User, error) {
	record, err := GetTokenByAccessToken(raw)
	if err != nil {
		return nil, fmt.Errorf("read member access token: %w", err)
	}
	if record == nil || record.ExpiresIn <= 0 || record.User == "" ||
		record.GrantType == "client_credentials" || record.Owner != application.Owner ||
		record.Application != application.Name || record.Organization != application.Organization ||
		subtle.ConstantTimeCompare([]byte(raw), []byte(record.AccessToken)) != 1 {
		return nil, ErrMemberUnauthenticated
	}
	cert, err := getCertByApplication(application)
	if err != nil {
		return nil, fmt.Errorf("read member signing certificate: %w", err)
	}
	key, err := jwt.ParseRSAPublicKeyFromPEM([]byte(cert.Certificate))
	if err != nil {
		return nil, fmt.Errorf("parse member signing certificate: %w", err)
	}
	claims := &Claims{}
	parsed, err := jwt.ParseWithClaims(raw, claims, func(*jwt.Token) (any, error) { return key, nil },
		jwt.WithValidMethods([]string{"RS256"}), jwt.WithAudience(application.ClientId),
		jwt.WithIssuer(conf.GetConfigString("origin")), jwt.WithExpirationRequired())
	if err != nil || !parsed.Valid || claims.TokenType != "access-token" || claims.Subject == "" {
		return nil, ErrMemberUnauthenticated
	}
	user, err := GetUserByUserId(application.Organization, claims.Subject)
	if err != nil {
		return nil, fmt.Errorf("read current member: %w", err)
	}
	if user == nil || user.IsForbidden || user.IsDeleted {
		return nil, ErrMemberUnauthenticated
	}
	return user, nil
}
