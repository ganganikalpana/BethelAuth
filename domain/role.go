package domain

import (
	"fmt"
	"strings"
)

type RolePermissions struct {
	rolePermissions map[string][]string
}

func (p RolePermissions) IsAuthorizedFor(role string, routeName string) bool {
	perms := p.rolePermissions[role]
	fmt.Println(perms)
	for _, r := range perms {
		if r == strings.TrimSpace(routeName) {
			return true
		}
	}
	return false
}
func GetRolePermissions() RolePermissions {
	return RolePermissions{map[string][]string{
		"admin": {"GetLecturer", "GetAllLecturers", "GetAllClasses", "GetClass", "NewClass"},
	}}
}
