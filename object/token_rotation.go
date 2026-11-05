package object

import (
	"fmt"

	"github.com/casdoor/casdoor/util"
	"github.com/xorm-io/core"
)

func persistRefreshedToken(original, successor *Token, rotate bool) (bool, error) {
	session := ormer.Engine.NewSession()
	defer session.Close()
	if err := session.Begin(); err != nil {
		return false, fmt.Errorf("begin token rotation: %w", err)
	}
	defer session.Rollback()

	current := Token{Owner: original.Owner, Name: original.Name}
	exists, err := session.ForUpdate().Get(&current)
	if err != nil {
		return false, fmt.Errorf("lock refresh token: %w", err)
	}
	if !exists || current.ExpiresIn <= 0 || current.RefreshUsed {
		return false, nil
	}

	if current.FamilyId == "" {
		current.FamilyId = util.GenerateAuthorizationCode()
		if _, err = session.ID(core.PK{current.Owner, current.Name}).Cols("family_id").Update(&current); err != nil {
			return false, fmt.Errorf("initialize token family: %w", err)
		}
	}
	successor.FamilyId = current.FamilyId
	if rotate {
		_, err = session.ID(core.PK{current.Owner, current.Name}).
			Cols("expires_in", "refresh_used").
			Update(&Token{ExpiresIn: 0, RefreshUsed: true})
		if err != nil {
			return false, fmt.Errorf("retire refresh token: %w", err)
		}
	}
	successor.popularHashes()
	if _, err = session.Insert(successor); err != nil {
		return false, fmt.Errorf("persist refresh successor: %w", err)
	}
	if err = session.Commit(); err != nil {
		return false, fmt.Errorf("commit token rotation: %w", err)
	}
	return true, nil
}

func RevokeOAuthToken(application *Application, value, hint string) error {
	token, err := GetTokenByTokenValue(value, hint)
	if err != nil {
		return fmt.Errorf("find token to revoke: %w", err)
	}
	if token == nil {
		token, err = GetTokenByAccessToken(value)
		if err != nil {
			return fmt.Errorf("find access token to revoke: %w", err)
		}
	}
	if token == nil {
		token, err = GetTokenByRefreshToken(value)
		if err != nil {
			return fmt.Errorf("find refresh token to revoke: %w", err)
		}
	}
	if token == nil || token.Owner != application.Owner || token.Application != application.Name ||
		token.Organization != application.Organization {
		return nil
	}
	if token.FamilyId == "" {
		_, err = ExpireToken(token)
	} else {
		// Locking the family rows also serializes revocation with a refresh holding its parent.
		_, err = ormer.Engine.Where("owner = ? AND application = ? AND family_id = ?",
			token.Owner, token.Application, token.FamilyId).
			Cols("expires_in").Update(&Token{ExpiresIn: 0})
	}
	if err != nil {
		return fmt.Errorf("revoke token family: %w", err)
	}
	return nil
}
