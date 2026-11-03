//go:build !windows

package executor

import "testing"

func TestWindowsProcessOperationsUnavailable(t *testing.T) {
	if pids, err := ListProcessIDsByExecutable(t.Context(), "nginx.exe"); err == nil || pids != nil {
		t.Fatalf("got %v %v", pids, err)
	}
	if err := TerminateProcessByPID(t.Context(), 1); err == nil {
		t.Fatal("termination unexpectedly allowed")
	}
}
