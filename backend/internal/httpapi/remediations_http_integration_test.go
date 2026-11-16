package httpapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/auth"
	"github.com/haytamxp/enterprise-web-security-platform/backend/internal/storage"
)

func TestRemediationsHTTPAuthorizationTenantIsolationAndRetests(t *testing.T) {
	store, ctx, _ := openHTTPConnectorTestStore(t)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	prefix := "m6-http-" + suffix

	tenantA := createFindingIntegrationTenant(
		t, ctx, store.DB,
		"M6 Remediation HTTP Tenant A",
		prefix+"-tenant-a",
	)
	tenantB := createFindingIntegrationTenant(
		t, ctx, store.DB,
		"M6 Remediation HTTP Tenant B",
		prefix+"-tenant-b",
	)

	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		for _, tenantID := range []string{tenantA, tenantB} {
			if _, err := store.DB.ExecContext(cleanupCtx,
				`DELETE FROM retest_results WHERE tenant_id = $1::uuid`, tenantID); err != nil {
				t.Errorf("cleanup M6 retest results: %v", err)
			}
			if _, err := store.DB.ExecContext(cleanupCtx,
				`DELETE FROM remediation_tasks WHERE tenant_id = $1::uuid`, tenantID); err != nil {
				t.Errorf("cleanup M6 remediation tasks: %v", err)
			}
			if _, err := store.DB.ExecContext(cleanupCtx,
				`DELETE FROM findings WHERE tenant_id = $1::uuid`, tenantID); err != nil {
				t.Errorf("cleanup M6 findings: %v", err)
			}
			if _, err := store.DB.ExecContext(cleanupCtx,
				`DELETE FROM assets WHERE tenant_id = $1::uuid`, tenantID); err != nil {
				t.Errorf("cleanup M6 assets: %v", err)
			}
			if _, err := store.DB.ExecContext(cleanupCtx,
				`DELETE FROM users WHERE tenant_id = $1::uuid`, tenantID); err != nil {
				t.Errorf("cleanup M6 users: %v", err)
			}
			if _, err := store.DB.ExecContext(cleanupCtx,
				`DELETE FROM tenants WHERE tenant_id = $1::uuid`, tenantID); err != nil {
				t.Errorf("cleanup M6 tenants: %v", err)
			}
		}
	})

	createUser := func(tenantID, role, label string) *storage.User {
		t.Helper()
		user, err := store.CreateUser(
			ctx,
			tenantID,
			label+"-"+suffix+"@example.test",
			"integration-test-password-hash",
			role,
		)
		if err != nil {
			t.Fatalf("create M6 test user %s: %v", label, err)
		}
		return user
	}

	adminA := createUser(tenantA, auth.RoleAdmin, "admin-a")
	analystA := createUser(tenantA, auth.RoleAnalyst, "analyst-a")
	responderA := createUser(tenantA, auth.RoleResponder, "responder-a")
	viewerB := createUser(tenantB, auth.RoleViewer, "viewer-b")
	adminB := createUser(tenantB, auth.RoleAdmin, "admin-b")

	tokens, err := auth.NewTokenManager(
		strings.Repeat("m6-http-integration-secret-", 2),
		"m6-http-integration",
		15*time.Minute,
	)
	if err != nil {
		t.Fatalf("create M6 HTTP token manager: %v", err)
	}

	issueToken := func(user *storage.User) string {
		t.Helper()
		token, _, issueErr := tokens.Issue(user.ID, user.TenantID, user.Role)
		if issueErr != nil {
			t.Fatalf("issue M6 token for %s: %v", user.Email, issueErr)
		}
		return token
	}

	adminTokenA := issueToken(adminA)
	analystTokenA := issueToken(analystA)
	responderTokenA := issueToken(responderA)
	viewerTokenB := issueToken(viewerB)
	adminTokenB := issueToken(adminB)
	handler := NewWithAuth(store, tokens)

	assetA := prefix + "-asset-a"
	assetB := prefix + "-asset-b"
	findingA := prefix + "-finding-a"
	findingB := prefix + "-finding-b"

	assetAResponse := performAssetIntegrationRequest(
		t, handler, http.MethodPost, "/api/v1/assets",
		createAssetIntegrationPayload(tenantA, assetA), adminTokenA,
	)
	if assetAResponse.Code != http.StatusCreated {
		t.Fatalf("create Tenant A asset: expected 201, got %d: %s", assetAResponse.Code, assetAResponse.Body.String())
	}
	assetBResponse := performAssetIntegrationRequest(
		t, handler, http.MethodPost, "/api/v1/assets",
		createAssetIntegrationPayload(tenantB, assetB), adminTokenB,
	)
	if assetBResponse.Code != http.StatusCreated {
		t.Fatalf("create Tenant B asset: expected 201, got %d: %s", assetBResponse.Code, assetBResponse.Body.String())
	}

	findingAResponse := performFindingIntegrationRequest(
		t, handler, http.MethodPost, "/api/v1/findings",
		createFindingIntegrationPayload(tenantA, assetA, findingA), adminTokenA,
	)
	if findingAResponse.Code != http.StatusCreated {
		t.Fatalf("create Tenant A finding: expected 201, got %d: %s", findingAResponse.Code, findingAResponse.Body.String())
	}
	findingBResponse := performFindingIntegrationRequest(
		t, handler, http.MethodPost, "/api/v1/findings",
		createFindingIntegrationPayload(tenantB, assetB, findingB), adminTokenB,
	)
	if findingBResponse.Code != http.StatusCreated {
		t.Fatalf("create Tenant B finding: expected 201, got %d: %s", findingBResponse.Code, findingBResponse.Body.String())
	}

	remediationA := prefix + "-remediation-a"
	remediationB := prefix + "-remediation-b"
	createPayloadA := map[string]any{
		"remediation_id": remediationA,
		"finding_id":     findingA,
		"title":          "Remediate M6 HTTP test finding A",
		"description":    "Integration test remediation plan",
		"priority":       "high",
		"assigned_to":    analystA.ID,
	}
	createPayloadB := map[string]any{
		"remediation_id": remediationB,
		"finding_id":     findingB,
		"title":          "Remediate M6 HTTP test finding B",
		"priority":       "medium",
	}

	if got := performFindingIntegrationRequest(
		t, handler, http.MethodPost, "/api/v1/remediations", createPayloadA, viewerTokenB,
	).Code; got != http.StatusForbidden {
		t.Fatalf("viewer must not create remediation: expected 403, got %d", got)
	}

	createdA := performFindingIntegrationRequest(
		t, handler, http.MethodPost, "/api/v1/remediations", createPayloadA, adminTokenA,
	)
	if createdA.Code != http.StatusCreated {
		t.Fatalf("create Tenant A remediation: expected 201, got %d: %s", createdA.Code, createdA.Body.String())
	}
	createdB := performFindingIntegrationRequest(
		t, handler, http.MethodPost, "/api/v1/remediations", createPayloadB, adminTokenB,
	)
	if createdB.Code != http.StatusCreated {
		t.Fatalf("create Tenant B remediation: expected 201, got %d: %s", createdB.Code, createdB.Body.String())
	}

	crossTenantGet := performFindingIntegrationRequest(
		t, handler, http.MethodGet, "/api/v1/remediations/"+remediationA, nil, adminTokenB,
	)
	if crossTenantGet.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant remediation read: expected 404, got %d: %s", crossTenantGet.Code, crossTenantGet.Body.String())
	}

	listA := performFindingIntegrationRequest(
		t, handler, http.MethodGet, "/api/v1/remediations?limit=10", nil, adminTokenA,
	)
	if listA.Code != http.StatusOK {
		t.Fatalf("list Tenant A remediations: expected 200, got %d: %s", listA.Code, listA.Body.String())
	}
	var pageA struct {
		Items []struct {
			RemediationID string `json:"remediation_id"`
		} `json:"items"`
	}
	if err := json.Unmarshal(listA.Body.Bytes(), &pageA); err != nil {
		t.Fatalf("decode Tenant A remediation list: %v", err)
	}
	if len(pageA.Items) != 1 || pageA.Items[0].RemediationID != remediationA {
		t.Fatalf("Tenant A list leaked or omitted remediations: %+v", pageA.Items)
	}

	listB := performFindingIntegrationRequest(
		t, handler, http.MethodGet, "/api/v1/remediations?limit=10", nil, adminTokenB,
	)
	if listB.Code != http.StatusOK {
		t.Fatalf("list Tenant B remediations: expected 200, got %d: %s", listB.Code, listB.Body.String())
	}
	var pageB struct {
		Items []struct {
			RemediationID string `json:"remediation_id"`
		} `json:"items"`
	}
	if err := json.Unmarshal(listB.Body.Bytes(), &pageB); err != nil {
		t.Fatalf("decode Tenant B remediation list: %v", err)
	}
	if len(pageB.Items) != 1 || pageB.Items[0].RemediationID != remediationB {
		t.Fatalf("Tenant B list leaked or omitted remediations: %+v", pageB.Items)
	}

	crossTenantAssignment := performFindingIntegrationRequest(
		t, handler, http.MethodPatch, "/api/v1/remediations/"+remediationA,
		map[string]any{"assigned_to": adminB.ID}, adminTokenA,
	)
	if crossTenantAssignment.Code != http.StatusBadRequest {
		t.Fatalf("cross-tenant assignee must be rejected: expected 400, got %d: %s", crossTenantAssignment.Code, crossTenantAssignment.Body.String())
	}

	analystRetest := performFindingIntegrationRequest(
		t, handler, http.MethodPost, "/api/v1/remediations/"+remediationA+"/retests",
		map[string]any{
			"retest_id": prefix + "-analyst-retest",
			"status":    "still_present",
			"summary":   "Analyst must not execute a retest",
		}, analystTokenA,
	)
	if analystRetest.Code != http.StatusForbidden {
		t.Fatalf("analyst must not execute retest: expected 403, got %d: %s", analystRetest.Code, analystRetest.Body.String())
	}

	stillPresentID := prefix + "-retest-still-present"
	stillPresent := performFindingIntegrationRequest(
		t, handler, http.MethodPost, "/api/v1/remediations/"+remediationA+"/retests",
		map[string]any{
			"retest_id":     stillPresentID,
			"status":        "still_present",
			"summary":       "The vulnerability remains reproducible",
			"evidence_refs": []string{"evidence-ref://m6/still-present"},
			"tested_at":     time.Now().UTC(),
		}, responderTokenA,
	)
	if stillPresent.Code != http.StatusCreated {
		t.Fatalf("create still_present retest: expected 201, got %d: %s", stillPresent.Code, stillPresent.Body.String())
	}

	fixedID := prefix + "-retest-fixed"
	fixed := performFindingIntegrationRequest(
		t, handler, http.MethodPost, "/api/v1/remediations/"+remediationA+"/retests",
		map[string]any{
			"retest_id":     fixedID,
			"status":        "fixed",
			"summary":       "The vulnerability is no longer reproducible",
			"evidence_refs": []string{"evidence-ref://m6/fixed"},
			"tested_at":     time.Now().UTC(),
		}, responderTokenA,
	)
	if fixed.Code != http.StatusCreated {
		t.Fatalf("create fixed retest: expected 201, got %d: %s", fixed.Code, fixed.Body.String())
	}

	listRetests := performFindingIntegrationRequest(
		t, handler, http.MethodGet, "/api/v1/remediations/"+remediationA+"/retests", nil, adminTokenA,
	)
	if listRetests.Code != http.StatusOK {
		t.Fatalf("list retests: expected 200, got %d: %s", listRetests.Code, listRetests.Body.String())
	}
	var retests struct {
		Items []struct {
			RetestID string `json:"retest_id"`
			Status   string `json:"status"`
		} `json:"items"`
	}
	if err := json.Unmarshal(listRetests.Body.Bytes(), &retests); err != nil {
		t.Fatalf("decode retest list: %v", err)
	}
	if len(retests.Items) != 2 {
		t.Fatalf("expected two immutable retest records, got %d", len(retests.Items))
	}

	completedTaskRetest := performFindingIntegrationRequest(
		t, handler, http.MethodPost, "/api/v1/remediations/"+remediationA+"/retests",
		map[string]any{
			"retest_id": prefix + "-retest-after-completion",
			"status":    "still_present",
			"summary":   "A completed task must reject further retests",
		}, responderTokenA,
	)
	if completedTaskRetest.Code != http.StatusConflict {
		t.Fatalf("completed task must reject another retest: expected 409, got %d: %s", completedTaskRetest.Code, completedTaskRetest.Body.String())
	}

	completedTaskUpdate := performFindingIntegrationRequest(
		t, handler, http.MethodPatch, "/api/v1/remediations/"+remediationA,
		map[string]any{"status": "in_progress"}, adminTokenA,
	)
	if completedTaskUpdate.Code != http.StatusConflict {
		t.Fatalf("completed task must not be reopened: expected 409, got %d: %s", completedTaskUpdate.Code, completedTaskUpdate.Body.String())
	}
}
