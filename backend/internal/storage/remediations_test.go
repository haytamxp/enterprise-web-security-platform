package storage

import "testing"

func TestM6RemediationPriorityValidation(t *testing.T) {
	for _, value := range []string{"critical", "high", "medium", "low"} {
		if !validateRemediationPriority(value) {
			t.Errorf("expected valid priority %q", value)
		}
	}
	for _, value := range []string{"", "info", "urgent", "P1"} {
		if validateRemediationPriority(value) {
			t.Errorf("expected invalid priority %q", value)
		}
	}
}

func TestM6RetestStatusValidation(t *testing.T) {
	for _, value := range []string{"fixed", "still_present", "inconclusive"} {
		if !validateRetestStatus(value) {
			t.Errorf("expected valid retest status %q", value)
		}
	}
	if validateRetestStatus("completed") {
		t.Fatal("completed is not a retest result")
	}
}

func TestM6RemediationTransitions(t *testing.T) {
	allowed := [][2]string{{"open", "in_progress"}, {"open", "blocked"}, {"open", "cancelled"}, {"in_progress", "blocked"}, {"blocked", "in_progress"}}
	for _, pair := range allowed {
		if !validRemediationTransition(pair[0], pair[1]) {
			t.Errorf("expected transition %s -> %s", pair[0], pair[1])
		}
	}
	rejected := [][2]string{{"open", "completed"}, {"completed", "in_progress"}, {"cancelled", "open"}, {"blocked", "completed"}}
	for _, pair := range rejected {
		if validRemediationTransition(pair[0], pair[1]) {
			t.Errorf("unexpected transition %s -> %s", pair[0], pair[1])
		}
	}
}
