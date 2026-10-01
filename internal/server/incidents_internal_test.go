package server

import (
	"testing"
	"time"

	"github.com/wsjrosiris/serverbrain/internal/actions"
)

// A plan step must be awaited at least as long as the action may run.
func TestStepWaitLimitCoversActionTimeout(t *testing.T) {
	for _, d := range actions.All() {
		if limit := stepWaitLimit(d.Name); limit < time.Duration(d.TimeoutSeconds)*time.Second+time.Minute {
			t.Errorf("%s: waits %s, action may run %ds", d.Name, limit, d.TimeoutSeconds)
		}
	}
}
