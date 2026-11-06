package controllers

import (
	"errors"
	"net/http"

	"github.com/casdoor/casdoor/object"
)

func (c *ApiController) MemberIdentity() {
	ok, application, _, _, err := c.ValidateOAuth(false)
	if err != nil || !ok {
		return
	}
	if !object.MemberScopeAllowed(application, "wechat:read") {
		c.memberError(http.StatusForbidden, "member_scope_denied")
		return
	}
	appID := c.Ctx.Input.Query("app_id")
	if appID == "" {
		c.memberError(http.StatusBadRequest, "invalid_app_id")
		return
	}
	subject := c.Ctx.Input.Query("subject")
	if subject == "" || len(subject) > 255 {
		c.memberError(http.StatusBadRequest, "invalid_subject")
		return
	}
	identity, err := object.GetMemberIdentity(application, subject, appID)
	if errors.Is(err, object.ErrMemberAppDenied) {
		c.memberError(http.StatusForbidden, "member_app_denied")
		return
	}
	if err != nil {
		c.memberError(http.StatusServiceUnavailable, "member_identity_unavailable")
		return
	}
	if identity == nil {
		c.memberError(http.StatusNotFound, "member_not_found")
		return
	}
	c.Ctx.Output.Header("Cache-Control", "no-store")
	c.Data["json"] = identity
	c.ServeJSON()
}

func (c *ApiController) memberError(status int, code string) {
	c.Ctx.Output.SetStatus(status)
	c.Ctx.Output.Header("Cache-Control", "no-store")
	c.Data["json"] = map[string]string{"error": code}
	c.ServeJSON()
}
