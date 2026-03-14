package main

import (
	"crypto/x509"
	"math/big"
	"testing"
	"time"

	"github.com/zhuxbo/sslctl/pkg/backup"
	"github.com/zhuxbo/sslctl/pkg/config"
)

func TestApplyRollbackMetadata_UsesParsedCert(t *testing.T) {
	now := time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)
	expireAt := now.Add(30 * 24 * time.Hour)
	cert := &x509.Certificate{
		NotAfter:     expireAt,
		SerialNumber: big.NewInt(123456),
	}

	cfg := &config.Config{
		Certificates: []config.CertConfig{
			{
				CertName: "order-1",
				Bindings: []config.SiteBinding{
					{SiteName: "example.com"},
				},
				Metadata: config.CertMetadata{
					CSRSubmittedAt:  now.Add(-24 * time.Hour),
					LastCSRHash:     "old",
					LastIssueState:  "pending",
					IssueRetryCount: 2,
				},
			},
		},
	}

	updated := applyRollbackMetadata(cfg, "example.com", cert, nil, now)
	if len(updated) != 1 {
		t.Fatalf("expected 1 updated cert, got %d", len(updated))
	}

	meta := cfg.Certificates[0].Metadata
	if !meta.LastDeployAt.Equal(now) {
		t.Errorf("LastDeployAt = %v, want %v", meta.LastDeployAt, now)
	}
	if !meta.CertExpiresAt.Equal(expireAt) {
		t.Errorf("CertExpiresAt = %v, want %v", meta.CertExpiresAt, expireAt)
	}
	if meta.CertSerial != "1E240" { // 123456 in hex
		t.Errorf("CertSerial = %q, want %q", meta.CertSerial, "1E240")
	}
	if !meta.CSRSubmittedAt.IsZero() || meta.LastCSRHash != "" || meta.LastIssueState != "" || meta.IssueRetryCount != 0 {
		t.Errorf("renew metadata not reset: %+v", meta)
	}
}

func TestApplyRollbackMetadata_FallbackToBackupMeta(t *testing.T) {
	now := time.Date(2024, 2, 3, 4, 5, 6, 0, time.UTC)
	expireAt := now.Add(10 * 24 * time.Hour)
	meta := &backup.Metadata{
		CertInfo: backup.CertInfo{
			NotAfter: expireAt,
			Serial:   "ABCDEF",
		},
	}

	cfg := &config.Config{
		Certificates: []config.CertConfig{
			{
				CertName: "order-2",
				Bindings: []config.SiteBinding{
					{SiteName: "example.org"},
				},
			},
		},
	}

	updated := applyRollbackMetadata(cfg, "example.org", nil, meta, now)
	if len(updated) != 1 {
		t.Fatalf("expected 1 updated cert, got %d", len(updated))
	}

	got := cfg.Certificates[0].Metadata
	if got.CertSerial != "ABCDEF" {
		t.Errorf("CertSerial = %q, want %q", got.CertSerial, "ABCDEF")
	}
	if !got.CertExpiresAt.Equal(expireAt) {
		t.Errorf("CertExpiresAt = %v, want %v", got.CertExpiresAt, expireAt)
	}
}

func TestApplyRollbackMetadata_NoMatch(t *testing.T) {
	cfg := &config.Config{
		Certificates: []config.CertConfig{
			{
				CertName: "order-3",
				Bindings: []config.SiteBinding{
					{SiteName: "site-a"},
				},
			},
		},
	}

	updated := applyRollbackMetadata(cfg, "site-b", nil, nil, time.Now())
	if len(updated) != 0 {
		t.Fatalf("expected 0 updated certs, got %d", len(updated))
	}
}
