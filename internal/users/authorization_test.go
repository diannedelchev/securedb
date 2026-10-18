package users

import "testing"

func TestQueryCapabilities(t *testing.T) {
	for _, tc := range []struct {
		roles                     []string
		read, devWrite, prodWrite bool
	}{
		{nil, false, false, false},
		{[]string{RoleAuditor}, false, false, false},
		{[]string{RoleAnalyst}, true, false, false},
		{[]string{RoleQA}, true, true, false},
		{[]string{RoleDeveloper}, true, true, true},
		{[]string{RoleDBA}, true, true, true},
		{[]string{RoleAdmin}, true, true, true},
		{[]string{RoleAnalyst, RoleDeveloper}, true, true, true},
	} {
		u := &User{IsActive: true, Roles: tc.roles}
		if u.CanQuery() != tc.read || u.CanWrite("development") != tc.devWrite || u.CanWrite("production") != tc.prodWrite {
			t.Errorf("incorrect capabilities for %v", tc.roles)
		}
		u.IsActive = false
		if u.CanQuery() || u.CanWrite("development") {
			t.Fatal("inactive user has query capability")
		}
	}
	var u *User
	if u.CanQuery() || u.CanWrite("production") {
		t.Fatal("anonymous user has query capability")
	}
}
