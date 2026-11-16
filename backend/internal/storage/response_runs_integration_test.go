package storage

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

func createResponseRunTestIncident(t *testing.T, ctx context.Context, store *Store, tenantID, incidentID string) {
	t.Helper()
	_, err := store.DB.ExecContext(ctx, `
INSERT INTO incidents (
    tenant_id, incident_id, schema_version, asset_id, occurred_at,
    severity, confidence, title, correlation_id, description, status
) VALUES ($1::uuid, $2, '1.0', 'asset-m7-test', NOW(), 'high', 0.95,
          'M7 response integration incident', $3, 'Synthetic integration-test incident', 'open')`,
		tenantID, incidentID, "corr-"+incidentID,
	)
	if err != nil {
		t.Fatalf("create test incident %s: %v", incidentID, err)
	}
}

func cleanupResponseRunTestTenant(t *testing.T, store *Store, tenantID string) {
	t.Helper()
	if tenantID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	statements := []string{
		`DELETE FROM response_approvals WHERE tenant_id = $1::uuid`,
		`DELETE FROM response_action_executions WHERE tenant_id = $1::uuid`,
		`DELETE FROM response_runs WHERE tenant_id = $1::uuid`,
		`DELETE FROM response_playbook_actions WHERE tenant_id = $1::uuid`,
		`DELETE FROM response_playbooks WHERE tenant_id = $1::uuid`,
		`DELETE FROM incidents WHERE tenant_id = $1::uuid AND incident_id LIKE 'm7-run-test-%'`,
		`DELETE FROM users WHERE tenant_id = $1::uuid`,
		`DELETE FROM tenants WHERE tenant_id = $1::uuid`,
	}
	for _, statement := range statements {
		if _, err := store.DB.ExecContext(ctx, statement, tenantID); err != nil {
			t.Logf("cleanup response run test tenant %s: %v", tenantID, err)
			return
		}
	}
}

func TestResponseRunApprovalAndExecutionIntegration(t *testing.T) {
	store, ctx := openResponsePlaybookIntegrationStore(t)
	suffix := fmt.Sprintf("%d", time.Now().UnixNano())

	var tenantA, tenantB string
	t.Cleanup(func() {
		cleanupResponseRunTestTenant(t, store, tenantB)
		cleanupResponseRunTestTenant(t, store, tenantA)
	})

	tenantA = createResponsePlaybookTestTenant(t, ctx, store, suffix, "run-a")
	tenantB = createResponsePlaybookTestTenant(t, ctx, store, suffix, "run-b")
	requester := createResponsePlaybookTestUser(t, ctx, store, tenantA, suffix, "run-requester")
	approver := createResponsePlaybookTestUser(t, ctx, store, tenantA, suffix, "run-approver")
	userB := createResponsePlaybookTestUser(t, ctx, store, tenantB, suffix, "run-b")

	incidentID := "m7-run-test-incident-" + suffix
	createResponseRunTestIncident(t, ctx, store, tenantA, incidentID)

	playbook, err := store.CreateResponsePlaybook(ctx, tenantA, requester, CreateResponsePlaybookParams{
		PlaybookID: "pb-run-" + suffix,
		Name:       "M7 approval and execution test",
	})
	if err != nil {
		t.Fatalf("create response playbook: %v", err)
	}

	_, err = store.CreateResponsePlaybookAction(ctx, tenantA, CreateResponsePlaybookActionParams{
		ResponseActionID: "act-notify-" + suffix,
		PlaybookID:       playbook.PlaybookID,
		ActionKey:        "notify-on-call",
		StepOrder:        1,
		ActionType:       "notify",
		RequiresApproval: true,
		IsEnabled:        true,
	})
	if err != nil {
		t.Fatalf("create notification action: %v", err)
	}
	_, err = store.CreateResponsePlaybookAction(ctx, tenantA, CreateResponsePlaybookActionParams{
		ResponseActionID: "act-evidence-" + suffix,
		PlaybookID:       playbook.PlaybookID,
		ActionKey:        "collect-evidence",
		StepOrder:        2,
		ActionType:       "collect_evidence",
		RequiresApproval: false,
		IsEnabled:        true,
	})
	if err != nil {
		t.Fatalf("create evidence action: %v", err)
	}
	activate := true
	if _, err := store.UpdateResponsePlaybook(ctx, tenantA, playbook.PlaybookID, requester, UpdateResponsePlaybookParams{
		IsActive: &activate,
	}); err != nil {
		t.Fatalf("activate response playbook: %v", err)
	}

	requestReason := "Synthetic test of incident response approval"
	params := CreateResponseRunParams{
		ResponseRunID:  "run-main-" + suffix,
		IncidentID:     incidentID,
		PlaybookID:     playbook.PlaybookID,
		IdempotencyKey: "idem-main-" + suffix,
		RequestReason:  &requestReason,
	}
	run, err := store.CreateResponseRun(ctx, tenantA, requester, params)
	if err != nil {
		t.Fatalf("create response run: %v", err)
	}
	if run.Status != "pending_approval" || !run.RequiresApproval {
		t.Fatalf("expected run pending approval, got status=%q requires_approval=%v", run.Status, run.RequiresApproval)
	}

	// Same idempotency key and same request returns the original run, even if
	// the caller supplies a different response_run_id on retry.
	retryParams := params
	retryParams.ResponseRunID = "run-retry-" + suffix
	retried, err := store.CreateResponseRun(ctx, tenantA, requester, retryParams)
	if err != nil {
		t.Fatalf("idempotent response run retry: %v", err)
	}
	if retried.ResponseRunID != run.ResponseRunID {
		t.Fatalf("idempotent retry returned run %q, want %q", retried.ResponseRunID, run.ResponseRunID)
	}

	conflictingParams := retryParams
	otherReason := "different request"
	conflictingParams.RequestReason = &otherReason
	if _, err := store.CreateResponseRun(ctx, tenantA, requester, conflictingParams); !errors.Is(err, ErrResponseIdempotencyConflict) {
		t.Fatalf("expected idempotency conflict, got %v", err)
	}

	if _, err := store.GetResponseRunByID(ctx, tenantB, run.ResponseRunID); !errors.Is(err, ErrResponseRunNotFound) {
		t.Fatalf("expected cross-tenant run lookup to be not found, got %v", err)
	}
	listedB, hasMore, err := store.ListResponseRuns(ctx, tenantB, 0, 10)
	if err != nil {
		t.Fatalf("list tenant B response runs: %v", err)
	}
	if len(listedB) != 0 || hasMore {
		t.Fatalf("tenant B saw tenant A response runs: %+v", listedB)
	}
	if _, err := store.CreateResponseRun(ctx, tenantB, userB, CreateResponseRunParams{
		ResponseRunID: "run-cross-" + suffix, IncidentID: incidentID,
		PlaybookID: playbook.PlaybookID, IdempotencyKey: "idem-cross-" + suffix,
	}); !errors.Is(err, ErrResponseIncidentNotFound) {
		t.Fatalf("expected cross-tenant incident to be hidden, got %v", err)
	}

	approvals, hasMore, err := store.ListResponseApprovals(ctx, tenantA, "pending", 0, 10)
	if err != nil {
		t.Fatalf("list pending approvals: %v", err)
	}
	if len(approvals) != 1 || hasMore {
		t.Fatalf("expected exactly one pending approval, got %d (hasMore=%v)", len(approvals), hasMore)
	}
	approvalID := approvals[0].ApprovalID
	if _, _, err := store.DecideResponseApproval(ctx, tenantA, approvalID, requester, true, nil); !errors.Is(err, ErrResponseSelfApproval) {
		t.Fatalf("expected self-approval rejection, got %v", err)
	}
	approval, approvedRun, err := store.DecideResponseApproval(ctx, tenantA, approvalID, approver, true, nil)
	if err != nil {
		t.Fatalf("approve response run: %v", err)
	}
	if approval.Status != "approved" || approvedRun.Status != "queued" {
		t.Fatalf("unexpected approval/run status: approval=%q run=%q", approval.Status, approvedRun.Status)
	}
	if _, _, err := store.DecideResponseApproval(ctx, tenantA, approvalID, approver, true, nil); !errors.Is(err, ErrResponseApprovalAlreadyDecided) {
		t.Fatalf("expected repeated approval to be rejected, got %v", err)
	}

	startedRun, err := store.StartResponseRun(ctx, tenantA, run.ResponseRunID)
	if err != nil {
		t.Fatalf("start response run: %v", err)
	}
	if startedRun.Status != "running" || startedRun.StartedAt == nil {
		t.Fatalf("unexpected started run: %+v", startedRun)
	}

	executions, err := store.ListResponseActionExecutions(ctx, tenantA, run.ResponseRunID)
	if err != nil {
		t.Fatalf("list response action executions: %v", err)
	}
	if len(executions) != 2 {
		t.Fatalf("expected two action execution snapshots, got %d", len(executions))
	}

	first, err := store.StartResponseActionExecution(ctx, tenantA, run.ResponseRunID, executions[0].ActionExecutionID)
	if err != nil {
		t.Fatalf("start first action execution: %v", err)
	}
	if first.Status != "running" || first.AttemptCount != 1 {
		t.Fatalf("unexpected first attempt: %+v", first)
	}
	failed, err := store.FinishResponseActionExecution(ctx, tenantA, run.ResponseRunID, first.ActionExecutionID, FinishResponseActionExecutionParams{
		Status: "failed", ErrorCode: responseRunStringPointer("MOCK_CONNECTOR_FAILURE"),
	})
	if err != nil {
		t.Fatalf("finish first action as failed: %v", err)
	}
	if failed.Status != "failed" || failed.FinishedAt == nil {
		t.Fatalf("unexpected failed action execution: %+v", failed)
	}

	retry, err := store.StartResponseActionExecution(ctx, tenantA, run.ResponseRunID, first.ActionExecutionID)
	if err != nil {
		t.Fatalf("retry failed action execution: %v", err)
	}
	if retry.AttemptCount != 2 {
		t.Fatalf("retry attempt count = %d, want 2", retry.AttemptCount)
	}
	if _, err := store.FinishResponseActionExecution(ctx, tenantA, run.ResponseRunID, retry.ActionExecutionID, FinishResponseActionExecutionParams{
		Status: "succeeded", ResultSummary: responseRunStringPointer("Mock connector completed notification"),
	}); err != nil {
		t.Fatalf("finish retried action successfully: %v", err)
	}

	second, err := store.StartResponseActionExecution(ctx, tenantA, run.ResponseRunID, executions[1].ActionExecutionID)
	if err != nil {
		t.Fatalf("start second action execution: %v", err)
	}
	if _, err := store.FinishResponseActionExecution(ctx, tenantA, run.ResponseRunID, second.ActionExecutionID, FinishResponseActionExecutionParams{
		Status: "succeeded", ResultSummary: responseRunStringPointer("Mock evidence collection completed"),
	}); err != nil {
		t.Fatalf("finish second action successfully: %v", err)
	}

	finalized, err := store.FinalizeResponseRun(ctx, tenantA, run.ResponseRunID)
	if err != nil {
		t.Fatalf("finalize response run: %v", err)
	}
	if finalized.Status != "succeeded" || finalized.FinishedAt == nil {
		t.Fatalf("unexpected final response run: %+v", finalized)
	}

	// A second run proves cancellation closes a pending approval safely using
	// the authenticated tenant user who requested cancellation.
	cancelParams := params
	cancelParams.ResponseRunID = "run-cancel-" + suffix
	cancelParams.IdempotencyKey = "idem-cancel-" + suffix
	cancelRun, err := store.CreateResponseRun(ctx, tenantA, requester, cancelParams)
	if err != nil {
		t.Fatalf("create response run for cancellation: %v", err)
	}
	cancelApprovals, _, err := store.ListResponseApprovals(ctx, tenantA, "pending", 0, 10)
	if err != nil {
		t.Fatalf("list pending approvals before cancellation: %v", err)
	}
	var cancelApprovalID string
	for _, candidate := range cancelApprovals {
		if candidate.ResponseRunID == cancelRun.ResponseRunID {
			cancelApprovalID = candidate.ApprovalID
			break
		}
	}
	if cancelApprovalID == "" {
		t.Fatal("pending approval for cancellation run was not found")
	}
	cancelled, err := store.CancelResponseRun(ctx, tenantA, cancelRun.ResponseRunID, requester)
	if err != nil {
		t.Fatalf("cancel pending response run: %v", err)
	}
	if cancelled.Status != "cancelled" || cancelled.FinishedAt == nil {
		t.Fatalf("unexpected cancelled response run: %+v", cancelled)
	}
	cancelApproval, err := store.GetResponseApprovalByID(ctx, tenantA, cancelApprovalID)
	if err != nil {
		t.Fatalf("get cancelled approval: %v", err)
	}
	if cancelApproval.Status != "rejected" || cancelApproval.DecidedBy == nil || *cancelApproval.DecidedBy != requester {
		t.Fatalf("unexpected cancellation approval record: %+v", cancelApproval)
	}
}

func responseRunStringPointer(value string) *string { return &value }
