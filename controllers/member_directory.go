package controllers

import (
	"encoding/json"
	"strconv"

	"github.com/casdoor/casdoor/object"
)

func (c *ApiController) MemberDirectory() {
	application := c.memberApplication("directory:read")
	if application == nil {
		return
	}
	c.Ctx.Output.Header("Cache-Control", "no-store")
	if raw := c.Ctx.Input.Query("subjects"); raw != "" {
		var subjects []string
		if err := json.Unmarshal([]byte(raw), &subjects); err != nil {
			c.memberOperationError(object.ErrMemberInvalid)
			return
		}
		items, err := object.GetMemberDirectory(application, subjects)
		if err != nil {
			c.memberOperationError(err)
			return
		}
		c.Data["json"] = map[string]any{"items": items}
	} else {
		nickname, nicknameErr := strconv.ParseBool(c.Ctx.Input.Query("match_nickname"))
		phone, phoneErr := strconv.ParseBool(c.Ctx.Input.Query("match_phone"))
		if nicknameErr != nil || phoneErr != nil {
			c.memberOperationError(object.ErrMemberInvalid)
			return
		}
		subjects, err := object.SearchMemberDirectory(application, c.Ctx.Input.Query("keyword"), nickname, phone)
		if err != nil {
			c.memberOperationError(err)
			return
		}
		c.Data["json"] = map[string]any{"subjects": subjects}
	}
	c.ServeJSON()
}
