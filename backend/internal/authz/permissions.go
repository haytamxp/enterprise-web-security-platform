package authz

import "github.com/haytamxp/enterprise-web-security-platform/backend/internal/auth"

type Permission string

const (
	PermissionAssetsRead   Permission = "assets:read"
	PermissionAssetsManage Permission = "assets:manage"

	PermissionFindingsRead   Permission = "findings:read"
	PermissionFindingsReview Permission = "findings:review"

	PermissionEventsRead Permission = "events:read"

	PermissionIncidentsRead    Permission = "incidents:read"
	PermissionIncidentsTriage  Permission = "incidents:triage"
	PermissionIncidentsRespond Permission = "incidents:respond"
	PermissionIncidentsClose   Permission = "incidents:close"

	PermissionRemediationRead    Permission = "remediation:read"
	PermissionRemediationManage  Permission = "remediation:manage"
	PermissionRemediationExecute Permission = "remediation:execute"

	PermissionEvidenceRead Permission = "evidence:read"

	PermissionActionsApprove Permission = "actions:approve"

	PermissionUsersManage      Permission = "users:manage"
	PermissionConnectorsManage Permission = "connectors:manage"
	PermissionPlatformManage   Permission = "platform:manage"
	PermissionAuditRead        Permission = "audit:read"
)

func permissionSet(permissions ...Permission) map[Permission]struct{} {
	result := make(map[Permission]struct{}, len(permissions))

	for _, permission := range permissions {
		result[permission] = struct{}{}
	}

	return result
}

// rolePermissions defines the permissions available to each human user role.
// Service and connector identities are handled separately.
var rolePermissions = map[string]map[Permission]struct{}{
	auth.RoleAdmin: permissionSet(
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
	),

	auth.RoleAnalyst: permissionSet(
		PermissionAssetsRead,
		PermissionFindingsRead,
		PermissionFindingsReview,
		PermissionEventsRead,
		PermissionIncidentsRead,
		PermissionIncidentsTriage,
		PermissionRemediationRead,
		PermissionRemediationManage,
		PermissionEvidenceRead,
	),

	auth.RoleResponder: permissionSet(
		PermissionAssetsRead,
		PermissionFindingsRead,
		PermissionEventsRead,
		PermissionIncidentsRead,
		PermissionIncidentsRespond,
		PermissionIncidentsClose,
		PermissionRemediationRead,
		PermissionRemediationExecute,
		PermissionEvidenceRead,
	),

	auth.RoleViewer: permissionSet(
		PermissionAssetsRead,
		PermissionFindingsRead,
		PermissionEventsRead,
		PermissionIncidentsRead,
		PermissionRemediationRead,
	),
}

// HasPermission returns false for unknown roles and unknown permissions.
// Authorization is deny-by-default.
func HasPermission(role string, permission Permission) bool {
	if role == "" || permission == "" {
		return false
	}

	permissions, roleExists := rolePermissions[role]
	if !roleExists {
		return false
	}

	_, allowed := permissions[permission]
	return allowed
}
