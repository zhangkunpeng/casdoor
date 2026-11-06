package object

import (
	"errors"
	"fmt"

	"github.com/casdoor/casdoor/util"
)

type MemberAccessProof struct {
	DPoP   string
	Method string
	URI    string
}

func checkMemberPhoneToken(application *Application, token *Token) error {
	if application == nil || token == nil || token.ExpiresIn <= 0 || token.User == "" ||
		token.AccessTokenHash == "" || token.IdTokenHash == "" ||
		token.Owner != application.Owner || token.Application != application.Name ||
		token.Organization != application.Organization {
		return ErrMemberUnauthenticated
	}
	switch token.GrantType {
	case "", "authorization_code", "urn:ietf:params:oauth:grant-type:token-exchange":
	default:
		return ErrMemberUnauthenticated
	}
	switch token.TokenType {
	case "Bearer":
		if token.DPoPJkt != "" {
			return ErrMemberUnauthenticated
		}
	case "DPoP":
		if token.DPoPJkt == "" {
			return ErrMemberUnauthenticated
		}
	default:
		return ErrMemberUnauthenticated
	}
	if expired, _ := util.IsTokenExpired(token.CreatedTime, token.ExpiresIn); expired {
		return ErrMemberUnauthenticated
	}
	return nil
}

func resolvePhoneUserAccess(application *Application, accessToken string, proof MemberAccessProof) (*Token, *User, error) {
	token, err := GetTokenByAccessToken(accessToken)
	if err != nil {
		return nil, nil, fmt.Errorf("read phone binding access token: %w", err)
	}
	if err := checkMemberPhoneToken(application, token); err != nil {
		return nil, nil, err
	}
	if token.TokenType == "DPoP" {
		jkt, err := ValidateDPoPProof(proof.DPoP, proof.Method, proof.URI, accessToken)
		if err != nil {
			return nil, nil, errors.Join(ErrMemberUnauthenticated, err)
		}
		if jkt != token.DPoPJkt {
			return nil, nil, ErrMemberUnauthenticated
		}
	}
	user, err := GetUser(util.GetId(token.Organization, token.User))
	if err != nil {
		return nil, nil, fmt.Errorf("read phone binding user: %w", err)
	}
	if user == nil || user.IsForbidden || user.IsDeleted {
		return nil, nil, ErrMemberUnauthenticated
	}
	return token, user, nil
}

func checkCurrentMemberPhoneToken(application *Application, observed, current *Token) error {
	if current.AccessTokenHash != observed.AccessTokenHash || current.IdTokenHash != observed.IdTokenHash ||
		current.User != observed.User || current.TokenType != observed.TokenType ||
		current.DPoPJkt != observed.DPoPJkt || current.GrantType != observed.GrantType ||
		current.CreatedTime != observed.CreatedTime || current.ExpiresIn != observed.ExpiresIn {
		return ErrMemberUnauthenticated
	}
	return checkMemberPhoneToken(application, current)
}
