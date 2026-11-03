package testutil

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// DockerCLI 用本地文件模拟 Docker CLI 的边界，文件操作与容器脚本仍实际执行。
// 真正的挂载、属主和 TLS 行为由 DinD E2E 验证。
type DockerCLI struct {
	Dir      string
	CertPath string
	KeyPath  string
	Trace    string
}

func NewDockerCLI(t *testing.T) *DockerCLI {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("Docker CLI fixture 使用 POSIX shell")
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	bin := filepath.Join(dir, "bin")
	if err := os.Mkdir(bin, 0700); err != nil {
		t.Fatal(err)
	}
	f := &DockerCLI{Dir: dir, CertPath: filepath.Join(dir, "cert.pem"), KeyPath: filepath.Join(dir, "key.pem"), Trace: filepath.Join(dir, "trace")}
	scripts := map[string]string{
		"docker": `#!/bin/sh
printf '%s\n' "$*" >> "$TEST_DOCKER_TRACE"
case "$1" in
inspect)
  [ "$TEST_DOCKER_INSPECT_FAIL" = 1 ] && exit 1
  printf '%s\n' "$TEST_DOCKER_INFO"
  ;;
cp)
  n=0
  [ -f "$TEST_DOCKER_DIR/cp-count" ] && n=$(/bin/cat "$TEST_DOCKER_DIR/cp-count")
  n=$((n + 1)); printf '%s' "$n" > "$TEST_DOCKER_DIR/cp-count"
  [ "$TEST_DOCKER_FAIL_CP" = "$n" ] && exit 21
  if [ "$TEST_DOCKER_WAIT_CP" = "$n" ]; then
    : > "$TEST_DOCKER_DIR/cp-blocked"
    exec sleep 60
  fi
  src="$2"; dst="$3"
  case "$src" in fixture-id:*) src=${src#fixture-id:} ;; *:*) exit 22 ;; esac
  case "$dst" in fixture-id:*) dst=${dst#fixture-id:} ;; *:*) exit 23 ;; esac
  exec /bin/cp "$src" "$dst"
  ;;
exec)
  shift
  if [ "$1" = --user ]; then shift 2; fi
  [ "$1" = fixture-id ] || exit 24
  shift
  exec "$@"
  ;;
*) exit 25 ;;
esac
`,
		"nginx": `#!/bin/sh
case "$*" in
  '-t')
    if [ "$TEST_DOCKER_FAIL_TEST" = 1 ] && [ ! -e "$TEST_DOCKER_DIR/test-failed" ]; then
      : > "$TEST_DOCKER_DIR/test-failed"; exit 31
    fi
    ;;
  '-s reload')
    if [ "$TEST_DOCKER_FAIL_RELOAD" = 1 ] && [ ! -e "$TEST_DOCKER_DIR/reload-failed" ]; then
      : > "$TEST_DOCKER_DIR/reload-failed"; exit 32
    fi
    /bin/cp "$TEST_DOCKER_CERT" "$TEST_DOCKER_DIR/loaded-cert"
    /bin/cp "$TEST_DOCKER_KEY" "$TEST_DOCKER_DIR/loaded-key"
    ;;
  *) exit 33 ;;
esac
`,
		"stat": `#!/bin/sh
if [ "$1" = -c ]; then
  format="$2"; shift 2
  case "$format" in '%u:%g') exec /usr/bin/stat -f '%u:%g' "$@" ;; '%a') exec /usr/bin/stat -f '%Lp' "$@" ;; esac
fi
exec /usr/bin/stat "$@"
`,
	}
	// macOS 的 stat 参数不同，生产容器使用 Linux stat。
	if runtime.GOOS != "darwin" {
		delete(scripts, "stat")
	}
	for name, script := range scripts {
		if err := os.WriteFile(filepath.Join(bin, name), []byte(script), 0700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	t.Setenv("TEST_DOCKER_DIR", dir)
	t.Setenv("TEST_DOCKER_TRACE", f.Trace)
	t.Setenv("TEST_DOCKER_CERT", f.CertPath)
	t.Setenv("TEST_DOCKER_KEY", f.KeyPath)
	t.Setenv("TEST_DOCKER_INFO", `[{"Id":"fixture-id","Name":"/web","State":{"Running":true},"Mounts":[]}]`)
	for _, name := range []string{"TEST_DOCKER_INSPECT_FAIL", "TEST_DOCKER_FAIL_CP", "TEST_DOCKER_WAIT_CP", "TEST_DOCKER_FAIL_TEST", "TEST_DOCKER_FAIL_RELOAD"} {
		t.Setenv(name, "")
	}
	return f
}

func (f *DockerCLI) WritePair(t *testing.T, cert, key string) {
	t.Helper()
	for name, content := range map[string]string{f.CertPath: cert, f.KeyPath: key} {
		if err := os.WriteFile(name, []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
}

func (f *DockerCLI) AssertPair(t *testing.T, cert, key string) {
	t.Helper()
	for name, want := range map[string]string{f.CertPath: cert, f.KeyPath: key} {
		got, err := os.ReadFile(name)
		if err != nil || string(got) != want {
			t.Fatalf("%s 的内容不符合预期 (read error: %v)", filepath.Base(name), err)
		}
	}
}

func (f *DockerCLI) ReadOnlyMountJSON() string {
	return fmt.Sprintf(`[{"Id":"fixture-id","Name":"/web","State":{"Running":true},"Mounts":[{"Type":"bind","Destination":%q,"RW":false}]}]`, f.Dir)
}
