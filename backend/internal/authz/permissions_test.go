package authz

import (
	"testing"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/auth"
)

func TestRolePermissionMatrix(t *testing.T) {
	allPermissions := []Permission{
		PermissionAssetsRead,
		PermissionAssetsManage,
		PermissionFindingsRead,
		PermissionFindingsReview,
		PermissionEventsRead,
		PermissionIncidentsRead,
		PermissionIncidentsTriage,
		PermissionIncidentsRespond,
		PermissionIncidentsClose,
		PermissionRemediationRead,
		PermissionRemediationManage,
		PermissionRemediationExecute,
		PermissionEvidenceRead,
		PermissionActionsApprove,
		PermissionUsersManage,
		PermissionConnectorsManage,
		PermissionPlatformManage,
		PermissionAuditRead,
	}

	expected := map[string]map[Permission]bool{
		auth.RoleAdmin: {
			PermissionAssetsRead:         true,
			PermissionAssetsManage:       true,
			PermissionFindingsRead:       true,
			PermissionFindingsReview:     true,
			PermissionEventsRead:         true,
			PermissionIncidentsRead:      true,
			PermissionIncidentsTriage:    true,
			PermissionIncidentsRespond:   true,
			PermissionIncidentsClose:     true,
			PermissionRemediationRead:    true,
			PermissionRemediationManage:  true,
			PermissionRemediationExecute: true,
			PermissionEvidenceRead:       true,
			PermissionActionsApprove:     true,
			PermissionUsersManage:        true,
			PermissionConnectorsManage:   true,
			PermissionPlatformManage:     true,
			PermissionAuditRead:          true,
		},

		auth.RoleAnalyst: {
			PermissionAssetsRead:        true,
			PermissionFindingsRead:      true,
			PermissionFindingsReview:    true,
			PermissionEventsRead:        true,
			PermissionIncidentsRead:     true,
			PermissionIncidentsTriage:   true,
			PermissionRemediationRead:   true,
			PermissionRemediationManage: true,
			PermissionEvidenceRead:      true,
		},

		auth.RoleResponder: {
			PermissionAssetsRead:         true,
			PermissionFindingsRead:       true,
			PermissionEventsRead:         true,
			PermissionIncidentsRead:      true,
			PermissionIncidentsRespond:   true,
			PermissionIncidentsClose:     true,
			PermissionRemediationRead:    true,
			PermissionRemediationExecute: true,
			PermissionEvidenceRead:       true,
		},

		auth.RoleViewer: {
			PermissionAssetsRead:      true,
			PermissionFindingsRead:    true,
			PermissionEventsRead:      true,
			PermissionIncidentsRead:   true,
			PermissionRemediationRead: true,
		},
	}

	for role, roleExpected := range expected {
		for _, permission := range allPermissions {
			want := roleExpected[permission]
			got := HasPermission(role, permission)

			if got != want {
				t.Errorf(
					"HasPermission(%q, %q) = %v; want %v",
					role,
					permission,
					got,
					want,
				)
			}
		}
	}
}

func TestUnknownRoleIsDenied(t *testing.T) {
	if HasPermission("superadmin", PermissionUsersManage) {
		t.Fatal("unknown role must not receive permissions")
	}
}

func TestUnknownPermissionIsDenied(t *testing.T) {
	if HasPermission(auth.RoleAdmin, Permission("users:delete")) {
		t.Fatal("unknown permission must be denied")
	}
}

func TestEmptyRoleOrPermissionIsDenied(t *testing.T) {
	if HasPermission("", PermissionAssetsRead) {
		t.Fatal("empty role must be denied")
	}

	if HasPermission(auth.RoleAdmin, "") {
		t.Fatal("empty permission must be denied")
	}
}
