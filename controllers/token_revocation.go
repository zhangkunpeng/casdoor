package controllers

import (
	"net/http"

	"github.com/casdoor/casdoor/object"
)

func (c *ApiController) RevokeOAuthToken() {
	ok, application, _, _, err := c.ValidateOAuth(false)
	if err != nil || !ok {
		return
	}
	value := c.Ctx.Input.Query("token")
	if value == "" {
		c.ResponseTokenError(object.InvalidRequest, "token is required")
		return
	}
	if err = object.RevokeOAuthToken(application, value, c.Ctx.Input.Query("token_type_hint")); err != nil {
		c.ResponseTokenError(object.EndpointError, "token revocation unavailable")
		return
	}
	c.Ctx.Output.SetStatus(http.StatusOK)
}
