package controllers

import (
	"io"
	"net/http"
	"strconv"

	"github.com/casdoor/casdoor/object"
)

func (c *ApiController) MemberFace() {
	c.Ctx.Request.Body = http.MaxBytesReader(c.Ctx.ResponseWriter, c.Ctx.Request.Body, object.MemberFaceMaxBytes+65536)
	if err := c.Ctx.Request.ParseMultipartForm(object.MemberFaceMaxBytes + 65536); err != nil {
		c.memberOperationError(object.ErrMemberInvalid)
		return
	}
	defer c.Ctx.Request.MultipartForm.RemoveAll()
	application := c.memberApplication("face:write")
	if application == nil {
		return
	}
	user := c.memberMutationUser(application)
	if user == nil {
		return
	}
	expected, err := strconv.ParseUint(c.Ctx.Input.Query("expected_revision"), 10, 64)
	if err != nil {
		c.memberOperationError(object.ErrMemberInvalid)
		return
	}
	action := c.Ctx.Input.Query("action")
	var content []byte
	if action == "replace" {
		if c.Ctx.Input.Query("consent") != "true" {
			c.memberOperationError(object.ErrMemberInvalid)
			return
		}
		file, _, err := c.Ctx.Request.FormFile("photo")
		if err != nil {
			c.memberOperationError(object.ErrMemberInvalid)
			return
		}
		defer file.Close()
		content, err = io.ReadAll(io.LimitReader(file, object.MemberFaceMaxBytes+1))
		if err != nil || len(content) > object.MemberFaceMaxBytes {
			c.memberOperationError(object.ErrMemberInvalid)
			return
		}
	}
	profile, err := object.ChangeMemberFace(user, c.Ctx.Input.Query("operation_id"), expected, action, content)
	if err != nil {
		c.memberOperationError(err)
		return
	}
	c.Ctx.Output.Header("Cache-Control", "no-store")
	c.Data["json"] = profile
	c.ServeJSON()
}

func (c *ApiController) MemberFaceProfile() {
	application := c.memberApplication("face:read")
	if application == nil {
		return
	}
	subject := c.Ctx.Input.Query("subject")
	user, err := object.GetUserByUserId(application.Organization, subject)
	if err != nil {
		c.memberOperationError(err)
		return
	}
	if user == nil {
		c.memberOperationError(object.ErrMemberNotFound)
		return
	}
	profile, err := object.GetMemberFaceProfile(user.Owner, user.Id)
	if err != nil {
		c.memberOperationError(err)
		return
	}
	c.Ctx.Output.Header("Cache-Control", "no-store")
	c.Data["json"] = profile
	c.ServeJSON()
}

func (c *ApiController) MemberFaceAsset() {
	application := c.memberApplication("face:read")
	if application == nil {
		return
	}
	revision, err := strconv.ParseUint(c.Ctx.Input.Query("revision"), 10, 64)
	if err != nil {
		c.memberOperationError(object.ErrMemberInvalid)
		return
	}
	asset, err := object.GetMemberFaceAsset(application, c.Ctx.Input.Query("subject"),
		c.Ctx.Input.Query("asset_id"), revision)
	if err != nil {
		c.memberOperationError(err)
		return
	}
	c.Ctx.Output.Header("Cache-Control", "no-store")
	c.Ctx.Output.Header("Content-Type", asset.ContentType)
	c.Ctx.Output.Header("X-Content-Type-Options", "nosniff")
	_ = c.Ctx.Output.Body(asset.Content)
}
