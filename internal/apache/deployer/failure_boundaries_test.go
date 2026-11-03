package deployer

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	base "github.com/zhuxbo/sslctl/internal/deployer"
	deployerrors "github.com/zhuxbo/sslctl/pkg/errors"
)

func TestWriteFailureStopsDeployment(t *testing.T) {
	original := writeCertificate
	t.Cleanup(func() { writeCertificate = original })
	injected := errors.New("injected write failure")
	phases := []deployerrors.DeployPhase{deployerrors.PhaseWriteKey, deployerrors.PhaseWriteCert, deployerrors.PhaseWriteChain}
	for failed, phase := range phases {
		t.Run(string(phase), func(t *testing.T) {
			dir := t.TempDir()
			d := NewApacheDeployer(base.Config{CertPath: filepath.Join(dir, "cert"), KeyPath: filepath.Join(dir, "key"), ChainPath: filepath.Join(dir, "chain")})
			paths := []string{d.keyPath, d.certPath, d.chainPath}
			calls := []string{}
			writeCertificate = func(b *base.Base, path string, data []byte, mode os.FileMode) error {
				calls = append(calls, path)
				if path == paths[failed] {
					return injected
				}
				return original(b, path, data, mode)
			}
			err := d.Deploy(t.Context(), "cert", "chain", "key")
			var structured *deployerrors.StructuredDeployError
			if !errors.As(err, &structured) || structured.Type != deployerrors.DeployErrorPermission || structured.Phase != phase || !errors.Is(err, injected) {
				t.Fatalf("wrong error: %#v", err)
			}
			if !reflect.DeepEqual(calls, paths[:failed+1]) {
				t.Fatalf("continued after failure: %v", calls)
			}
			for _, path := range paths[failed:] {
				if _, err := os.Stat(path); !os.IsNotExist(err) {
					t.Fatalf("unexpected later write: %s (%v)", path, err)
				}
			}
		})
	}
}

func TestSELinuxWarningAndFileModes(t *testing.T) {
	original := restoreCertificateContext
	t.Cleanup(func() { restoreCertificateContext = original })
	for _, failure := range []bool{false, true} {
		t.Run(fmt.Sprint(failure), func(t *testing.T) {
			dir := t.TempDir()
			d := NewApacheDeployer(base.Config{CertPath: filepath.Join(dir, "cert"), KeyPath: filepath.Join(dir, "key"), ChainPath: filepath.Join(dir, "chain")})
			paths := []string{d.certPath, d.keyPath, d.chainPath}
			calls := []string{}
			restoreCertificateContext = func(_ *base.Base, path string) error {
				calls = append(calls, path)
				if failure {
					return errors.New("context denied")
				}
				return nil
			}
			capture, err := os.CreateTemp(t.TempDir(), "stderr")
			if err != nil {
				t.Fatal(err)
			}
			defer capture.Close()
			previous := os.Stderr
			os.Stderr = capture
			defer func() { os.Stderr = previous }()
			err = d.Deploy(t.Context(), "cert", "chain", "key")
			os.Stderr = previous
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(calls, paths) {
				t.Fatalf("context targets: %v", calls)
			}
			output, err := os.ReadFile(capture.Name())
			if err != nil {
				t.Fatal(err)
			}
			if failure {
				for _, path := range paths {
					want := "[WARN] SELinux context restore failed for " + path + ": context denied\n"
					if !strings.Contains(string(output), want) {
						t.Fatalf("missing warning %q in %q", want, output)
					}
				}
			} else if len(output) != 0 {
				t.Fatalf("unexpected warning: %s", output)
			}
			if runtime.GOOS != "windows" {
				for _, path := range paths {
					want := os.FileMode(0644)
					if path == d.keyPath {
						want = 0600
					}
					info, err := os.Stat(path)
					if err != nil || info.Mode().Perm() != want {
						t.Fatalf("mode %s: %v %v", path, info, err)
					}
				}
			}
		})
	}
}

func TestPrepareFailureIsReturnedUnchanged(t *testing.T) {
	for _, rollback := range []bool{false, true} {
		t.Run(fmt.Sprint(rollback), func(t *testing.T) {
			dir := t.TempDir()
			cert := filepath.Join(dir, "cert")
			if err := os.Symlink("missing", cert); err != nil {
				t.Skip(err)
			}
			d := NewApacheDeployer(base.Config{CertPath: cert, KeyPath: filepath.Join(dir, "key")})
			want := d.Prepare()
			if want == nil {
				t.Fatal("expected dangling link failure")
			}
			var got error
			if rollback {
				got = d.Rollback(t.Context(), "missing-cert", "missing-key", "missing-chain")
			} else {
				got = d.Deploy(t.Context(), "cert", "chain", "key")
			}
			var structured *deployerrors.StructuredDeployError
			if got == nil || got.Error() != want.Error() || errors.As(got, &structured) {
				t.Fatalf("prepare error lost: got %v want %v", got, want)
			}
			if _, err := os.Stat(d.keyPath); !os.IsNotExist(err) {
				t.Fatalf("key created after prepare failure: %v", err)
			}
		})
	}
}

func TestRollbackFailureStopsFollowingFiles(t *testing.T) {
	for failed := 0; failed < 3; failed++ {
		t.Run(fmt.Sprint(failed), func(t *testing.T) {
			dir := t.TempDir()
			d := NewApacheDeployer(base.Config{CertPath: filepath.Join(dir, "cert"), KeyPath: filepath.Join(dir, "key"), ChainPath: filepath.Join(dir, "chain")})
			paths := []string{d.certPath, d.keyPath, d.chainPath}
			sources := make([]string, len(paths))
			for i, path := range paths {
				if err := os.WriteFile(path, []byte("current"), 0600); err != nil {
					t.Fatal(err)
				}
				sources[i] = path + ".backup"
				if i != failed {
					if err := os.WriteFile(sources[i], []byte("backup"), 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			err := d.Rollback(t.Context(), sources[0], sources[1], sources[2])
			var structured *deployerrors.StructuredDeployError
			if !errors.As(err, &structured) || structured.Type != deployerrors.DeployErrorPermission || structured.Phase != deployerrors.PhaseRollback || !errors.Is(structured.Cause, os.ErrNotExist) {
				t.Fatalf("wrong restore error: %#v", err)
			}
			for i, path := range paths {
				got, err := os.ReadFile(path)
				want := "current"
				if i < failed {
					want = "backup"
				}
				if err != nil || string(got) != want {
					t.Fatalf("rollback order %s: %q %v", path, got, err)
				}
			}
		})
	}
}
