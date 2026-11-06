package controllers

import (
	"errors"
	"net/http"

	"github.com/casdoor/casdoor/object"
)

func (c *ApiController) memberError(status int, code string) {
	c.Ctx.Output.SetStatus(status)
	c.Ctx.Output.Header("Cache-Control", "no-store")
	c.Data["json"] = map[string]string{"error": code}
	c.ServeJSON()
}

func (c *ApiController) MemberPhone() {
	ok, application, _, _, err := c.ValidateOAuth(false)
	if err != nil || !ok {
		return
	}
	err = object.BindMemberPhone(application, c.Ctx.Input.Query("access_token"), c.Ctx.Input.Query("app_id"),
		c.Ctx.Input.Query("code"))
	if err != nil {
		c.memberOperationError(err)
		return
	}
	c.Ctx.Output.Header("Cache-Control", "no-store")
	c.Data["json"] = map[string]bool{"phoneBound": true}
	c.ServeJSON()
}

func (c *ApiController) memberOperationError(err error) {
	switch {
	case errors.Is(err, object.ErrMemberUnauthenticated):
		c.memberError(http.StatusUnauthorized, "member_access_inactive")
	case errors.Is(err, object.ErrMemberAppDenied):
		c.memberError(http.StatusForbidden, "member_app_denied")
	case errors.Is(err, object.ErrMemberInvalid):
		c.memberError(http.StatusBadRequest, "invalid_member_operation")
	default:
		c.memberError(http.StatusServiceUnavailable, "member_dependency_unavailable")
	}
}
