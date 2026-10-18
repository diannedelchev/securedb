package connections

import (
	"testing"

	"github.com/diannedelchev/securedb/internal/users"
)

// Testing a connection dials the target from this server with the stored
// credentials, so it must be limited to the same people who may edit it.
func TestCanManage(t *testing.T) {
	owned := &Connection{OwnerID: "owner"}
	for _, tc := range []struct {
		name  string
		user  *users.User
		conn  *Connection
		allow bool
	}{
		{"anonymous", nil, owned, false},
		{"analyst, someone else's connection", &users.User{ID: "u", IsActive: true, Roles: []string{users.RoleAnalyst}}, owned, false},
		{"developer, someone else's connection", &users.User{ID: "u", IsActive: true, Roles: []string{users.RoleDeveloper}}, owned, false},
		{"auditor, someone else's connection", &users.User{ID: "u", IsActive: true, Roles: []string{users.RoleAuditor}}, owned, false},
		{"owner", &users.User{ID: "owner", IsActive: true, Roles: []string{users.RoleDeveloper}}, owned, true},
		{"dba", &users.User{ID: "u", IsActive: true, Roles: []string{users.RoleDBA}}, owned, true},
		{"admin", &users.User{ID: "u", IsActive: true, Roles: []string{users.RoleAdmin}}, owned, true},
		{"non-privileged, no connection loaded", &users.User{ID: "u", IsActive: true, Roles: []string{users.RoleDeveloper}}, nil, false},
	} {
		if got := canManage(tc.user, tc.conn); got != tc.allow {
			t.Errorf("%s: canManage = %v, want %v", tc.name, got, tc.allow)
		}
	}
}
