package seed

import (
	"context"
	"strings"
	"testing"
)

func TestInitialAdminRequiresConfiguredPassword(t *testing.T) {
	for _, password := range []string{"", "short"} {
		t.Run(password, func(t *testing.T) {
			// A nil pool ensures validation happens before creating an account.
			err := seedAdmin(context.Background(), nil, Options{AdminEmail: "admin@test.local", AdminPassword: password})
			if err == nil || !strings.Contains(err.Error(), "seed.admin.password") {
				t.Fatalf("expected password configuration error, got %v", err)
			}
		})
	}
}
