package controllers

import (
	"errors"
	"net/http"

	"github.com/casdoor/casdoor/object"
)

func (c *ApiController) memberApplication(scope string) *object.Application {
	ok, application, _, _, err := c.ValidateOAuth(false)
	if err != nil || !ok {
		return nil
	}
	if !object.MemberScopeAllowed(application, scope) {
		c.memberError(http.StatusForbidden, "member_scope_denied")
		return nil
	}
	return application
}

func (c *ApiController) memberMutationUser(application *object.Application) *object.User {
	user, err := object.GetActiveMember(application, c.Ctx.Input.Query("access_token"))
	if err != nil {
		c.memberOperationError(err)
		return nil
	}
	return user
}

func (c *ApiController) MemberPhone() {
	application := c.memberApplication("phone:write")
	if application == nil {
		return
	}
	user := c.memberMutationUser(application)
	if user == nil {
		return
	}
	err := object.BindMemberPhone(application, user, c.Ctx.Input.Query("app_id"),
		c.Ctx.Input.Query("operation_id"), c.Ctx.Input.Query("code"))
	if err != nil {
		c.memberOperationError(err)
		return
	}
	c.Ctx.Output.Header("Cache-Control", "no-store")
	c.Data["json"] = map[string]bool{"phoneBound": true}
	c.ServeJSON()
}

func (c *ApiController) MemberWechatCredential() {
	application := c.memberApplication("wechat:credential")
	if application == nil {
		return
	}
	credential, err := object.GetMemberWechatCredential(application, c.Ctx.Input.Query("app_id"))
	if err != nil {
		c.memberOperationError(err)
		return
	}
	c.Ctx.Output.Header("Cache-Control", "no-store")
	c.Data["json"] = map[string]any{"access_token": credential.AccessToken, "expires_at": credential.ExpiresAt}
	c.ServeJSON()
}

func (c *ApiController) memberOperationError(err error) {
	switch {
	case errors.Is(err, object.ErrMemberUnauthenticated):
		c.memberError(http.StatusUnauthorized, "member_access_inactive")
	case errors.Is(err, object.ErrMemberAppDenied):
		c.memberError(http.StatusForbidden, "member_app_denied")
	case errors.Is(err, object.ErrMemberConflict):
		c.memberError(http.StatusConflict, "member_operation_conflict")
	case errors.Is(err, object.ErrMemberInvalid):
		c.memberError(http.StatusBadRequest, "invalid_member_operation")
	default:
		c.memberError(http.StatusServiceUnavailable, "member_dependency_unavailable")
	}
}
