package upgrade

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestExecute_AlreadyLatest(t *testing.T) {
	info := &ReleaseInfo{
		LatestStable: "v1.0.0",
		LatestDev:    "v1.1.0-beta",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(info)
	}))
	defer server.Close()

	// 临时替换 ReleaseURL，使用 httptest 服务器
	result, err := executeWithClient(Options{
		CurrentVersion: "v1.0.0",
		Channel:        "stable",
	}, nil, server.URL+"/releases.json", server.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.NeedUpgrade {
		t.Error("expected NeedUpgrade=false for same version")
	}
}

func TestExecute_CheckOnly(t *testing.T) {
	info := &ReleaseInfo{
		LatestStable: "v2.0.0",
		LatestDev:    "v2.1.0-beta",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(info)
	}))
	defer server.Close()

	result, err := executeWithClient(Options{
		CurrentVersion: "v1.0.0",
		Channel:        "stable",
		CheckOnly:      true,
	}, nil, server.URL+"/releases.json", server.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.NeedUpgrade {
		t.Error("expected NeedUpgrade=true")
	}
	if result.ToVersion != "v2.0.0" {
		t.Errorf("ToVersion = %q, want v2.0.0", result.ToVersion)
	}
}

func TestExecute_Force(t *testing.T) {
	info := &ReleaseInfo{
		LatestStable: "v1.0.0",
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(info)
	}))
	defer server.Close()

	result, err := executeWithClient(Options{
		CurrentVersion: "v1.0.0",
		Channel:        "stable",
		CheckOnly:      true,
		Force:          true,
	}, nil, server.URL+"/releases.json", server.Client())
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !result.NeedUpgrade {
		t.Error("expected NeedUpgrade=true with Force=true")
	}
}

func TestExecute_FetchError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	_, err := executeWithClient(Options{
		CurrentVersion: "v1.0.0",
	}, nil, server.URL+"/releases.json", server.Client())
	if err == nil {
		t.Error("expected error for server error")
	}
}
