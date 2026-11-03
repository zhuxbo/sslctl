package config

import (
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestRemoveSitePreservesUnrelatedAndClearsOnlyEmptyState(t *testing.T) {
	for _, keepState := range []bool{false, true} {
		t.Run(map[bool]string{false: "clear", true: "preserve"}[keepState], func(t *testing.T) {
			cm, err := NewConfigManagerWithDir(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			stamp := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
			unrelated := CertConfig{CertName: "unrelated", Bindings: []SiteBinding{{ServerName: "other"}}, Metadata: CertMetadata{FailedBindingsAt: stamp, StaleSince: stamp, RetryAttemptCount: 4}}
			states := []string{"remove"}
			if keepState {
				states = append(states, "keep")
			}
			cfg := &Config{Certificates: []CertConfig{
				unrelated,
				{CertName: "orphan", Bindings: []SiteBinding{{ServerName: "remove"}}},
				{CertName: "shared", Bindings: []SiteBinding{{ServerName: "remove"}, {ServerName: "keep"}}, Metadata: CertMetadata{FailedBindings: states, StaleBindings: states, FailedBindingsAt: stamp, StaleSince: stamp, RetryAttemptCount: 4}},
			}}
			if err := cm.Save(cfg); err != nil {
				t.Fatal(err)
			}
			result, err := cm.RemoveSite("remove")
			if err != nil {
				t.Fatal(err)
			}
			if result.RemovedBindings != 2 || len(result.RemovedCertificates) != 1 {
				t.Fatalf("result %+v", result)
			}
			after, err := cm.Reload()
			if err != nil {
				t.Fatal(err)
			}
			if len(after.Certificates) != 2 || !reflect.DeepEqual(after.Certificates[0], unrelated) || after.Certificates[1].CertName != "shared" {
				t.Fatalf("remaining %+v", after.Certificates)
			}
			state := after.Certificates[1].Metadata
			if keepState {
				if !state.FailedBindingsAt.Equal(stamp) || !state.StaleSince.Equal(stamp) || state.RetryAttemptCount != 4 || !reflect.DeepEqual(state.FailedBindings, []string{"keep"}) || !reflect.DeepEqual(state.StaleBindings, []string{"keep"}) {
					t.Fatalf("state cleared prematurely %+v", state)
				}
			} else {
				if !state.FailedBindingsAt.IsZero() || !state.StaleSince.IsZero() || state.RetryAttemptCount != 0 || len(state.FailedBindings) != 0 || len(state.StaleBindings) != 0 {
					t.Fatalf("state not cleared %+v", state)
				}
			}
		})
	}
}

func TestRemoveCertificateMissingWrapsSentinel(t *testing.T) {
	cm, err := NewConfigManagerWithDir(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	removed, err := cm.RemoveCertificate("missing")
	if !errors.Is(err, ErrCertNotFound) || removed != nil {
		t.Fatalf("got %v, %v", removed, err)
	}
}
