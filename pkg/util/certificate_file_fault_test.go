package util

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type faultCertificateRoot struct {
	certificateRoot
	stat   func(string) (os.FileInfo, error)
	lstat  func(string) (os.FileInfo, error)
	open   func(string) (certificateHandle, error)
	create func(string, int, os.FileMode) (certificateHandle, error)
	rename func(string, string) error
}

func (r *faultCertificateRoot) Stat(p string) (os.FileInfo, error) {
	if r.stat != nil {
		return r.stat(p)
	}
	return r.certificateRoot.Stat(p)
}
func (r *faultCertificateRoot) Lstat(p string) (os.FileInfo, error) {
	if r.lstat != nil {
		return r.lstat(p)
	}
	return r.certificateRoot.Lstat(p)
}
func (r *faultCertificateRoot) Open(p string) (certificateHandle, error) {
	if r.open != nil {
		return r.open(p)
	}
	return r.certificateRoot.Open(p)
}
func (r *faultCertificateRoot) OpenFile(p string, f int, m os.FileMode) (certificateHandle, error) {
	if r.create != nil {
		return r.create(p, f, m)
	}
	return r.certificateRoot.OpenFile(p, f, m)
}
func (r *faultCertificateRoot) Rename(a, b string) error {
	if r.rename != nil {
		return r.rename(a, b)
	}
	return r.certificateRoot.Rename(a, b)
}

type faultCertificateHandle struct {
	certificateHandle
	stat  func() (os.FileInfo, error)
	read  func([]byte) (int, error)
	write func([]byte) (int, error)
	close func() error
}

func (f *faultCertificateHandle) Stat() (os.FileInfo, error) {
	if f.stat != nil {
		return f.stat()
	}
	return f.certificateHandle.Stat()
}
func (f *faultCertificateHandle) Read(p []byte) (int, error) {
	if f.read != nil {
		return f.read(p)
	}
	return f.certificateHandle.Read(p)
}
func (f *faultCertificateHandle) Write(p []byte) (int, error) {
	if f.write != nil {
		return f.write(p)
	}
	return f.certificateHandle.Write(p)
}
func (f *faultCertificateHandle) Close() error {
	if f.close != nil {
		return f.close()
	}
	return f.certificateHandle.Close()
}
func certificateFixture(t *testing.T) (*CertificateFile, *faultCertificateRoot) {
	t.Helper()
	p := filepath.Join(t.TempDir(), "cert.pem")
	if err := os.WriteFile(p, []byte("original"), 0600); err != nil {
		t.Fatal(err)
	}
	f, err := ResolveCertificateFile(p)
	if err != nil {
		t.Fatal(err)
	}
	r := &faultCertificateRoot{}
	open := f.io.openRoot
	f.io.openRoot = func(p string) (certificateRoot, error) { base, err := open(p); r.certificateRoot = base; return r, err }
	return f, r
}
func TestCertificateResolveErrors(t *testing.T) {
	sentinel := errors.New("resolve failure")
	for _, stage := range []string{"abs", "eval", "parent", "lstat", "stat"} {
		t.Run(stage, func(t *testing.T) {
			f, _ := certificateFixture(t)
			deps := systemCertificateIO()
			switch stage {
			case "abs":
				deps.abs = func(string) (string, error) { return "", sentinel }
			case "eval":
				deps.eval = func(path string) (string, error) {
					if path != f.Path {
						t.Fatalf("continued resolving parent after link resolution failure: %s", path)
					}
					return "", sentinel
				}
			case "parent":
				f.Path = filepath.Join(filepath.Dir(f.Path), "missing", "cert")
				deps.eval = func(string) (string, error) { return "", sentinel }
			case "lstat":
				deps.lstat = func(string) (os.FileInfo, error) { return nil, sentinel }
			case "stat":
				deps.stat = func(string) (os.FileInfo, error) { return nil, sentinel }
			}
			got, err := resolveCertificateFile(f.Path, deps)
			if got != nil || !errors.Is(err, sentinel) {
				t.Fatalf("got %v, %v; want wrapped sentinel", got, err)
			}
			if stage == "eval" && !strings.Contains(err.Error(), "解析证书链接 "+f.Path+":") {
				t.Fatalf("missing resolution context: %v", err)
			}
		})
	}
	if _, err := ResolveCertificateFile(""); err == nil || !strings.Contains(err.Error(), "路径为空") {
		t.Fatalf("empty path: %v", err)
	}
	if _, err := ReadCertificateFile("", 100); err == nil {
		t.Fatal("wrapper suppressed resolution error")
	}
	f, _ := certificateFixture(t)
	if got, err := ReadCertificateFile(f.Path, 8); err != nil || string(got) != "original" {
		t.Fatalf("wrapper: %q %v", got, err)
	}
}
func TestCertificateReadBounds(t *testing.T) {
	for _, limit := range []int64{-1, 0, 1, 7, 8, 9} {
		t.Run(string(rune(limit+65)), func(t *testing.T) {
			f, r := certificateFixture(t)
			consumed := 0
			r.open = func(p string) (certificateHandle, error) {
				h, e := r.certificateRoot.Open(p)
				return &faultCertificateHandle{certificateHandle: h, read: func(b []byte) (int, error) { n, e := h.Read(b); consumed += n; return n, e }}, e
			}
			got, err := f.Read(limit)
			if limit > 0 && limit < 8 {
				if err == nil || got != nil {
					t.Fatalf("limit %d accepted %q", limit, got)
				}
				if consumed != int(limit+1) {
					t.Fatalf("read %d bytes, want %d", consumed, limit+1)
				}
			} else if err != nil || string(got) != "original" {
				t.Fatalf("limit %d: %q %v", limit, got, err)
			}
		})
	}
}
func TestCertificateReadFailures(t *testing.T) {
	sentinel := errors.New("read failure")
	for _, stage := range []string{"check", "root", "root-stat", "root-stat-with-info", "root-changed", "missing", "special", "open", "stat", "inode", "read", "final-check"} {
		t.Run(stage, func(t *testing.T) {
			f, r := certificateFixture(t)
			want := sentinel
			wantText := ""
			switch stage {
			case "check":
				f.io.eval = func(string) (string, error) { return "", sentinel }
			case "root":
				f.io.openRoot = func(string) (certificateRoot, error) { return nil, sentinel }
			case "root-stat":
				r.stat = func(string) (os.FileInfo, error) { return nil, sentinel }
				wantText = "目标目录发生变化"
			case "root-stat-with-info":
				// 接口报告错误时，附带的元数据也不能作为目录身份可信凭据。
				r.stat = func(string) (os.FileInfo, error) { return f.parent, sentinel }
				wantText = "目标目录发生变化"
			case "root-changed":
				other, e := os.Stat(t.TempDir())
				if e != nil {
					t.Fatal(e)
				}
				r.stat = func(string) (os.FileInfo, error) { return other, nil }
				wantText = "目标目录发生变化"
			case "missing":
				r.lstat = func(string) (os.FileInfo, error) { return nil, sentinel }
			case "special":
				info, e := os.Stat(filepath.Dir(f.Target))
				if e != nil {
					t.Fatal(e)
				}
				r.lstat = func(string) (os.FileInfo, error) { return info, nil }
				wantText = "不是普通文件"
			case "open":
				r.open = func(string) (certificateHandle, error) { return nil, sentinel }
			default:
				r.open = func(p string) (certificateHandle, error) {
					h, e := r.certificateRoot.Open(p)
					w := &faultCertificateHandle{certificateHandle: h}
					switch stage {
					case "stat":
						w.stat = func() (os.FileInfo, error) { return nil, sentinel }
					case "inode":
						other := filepath.Join(t.TempDir(), "other")
						if e := os.WriteFile(other, []byte("other"), 0600); e != nil {
							t.Fatal(e)
						}
						info, e := os.Stat(other)
						if e != nil {
							t.Fatal(e)
						}
						w.stat = func() (os.FileInfo, error) { return info, nil }
						wantText = "读取前发生变化"
					case "read":
						w.read = func([]byte) (int, error) { return 0, sentinel }
					case "final-check":
						w.read = func(b []byte) (int, error) {
							f.io.eval = func(string) (string, error) { return "", sentinel }
							return h.Read(b)
						}
					}
					return w, e
				}
			}
			got, err := f.Read(100)
			if got != nil || err == nil {
				t.Fatalf("got %q %v", got, err)
			}
			if wantText != "" {
				if !strings.Contains(err.Error(), wantText) {
					t.Fatal(err)
				}
			} else if !errors.Is(err, want) {
				t.Fatalf("lost error: %v", err)
			}
		})
	}
}
func TestCertificateWriteFailures(t *testing.T) {
	sentinel := errors.New("write failure")
	for _, stage := range []string{"create", "write", "close", "check", "lstat", "special", "rename", "final-check"} {
		t.Run(stage, func(t *testing.T) {
			f, r := certificateFixture(t)
			wantText := ""
			switch stage {
			case "create":
				r.create = func(string, int, os.FileMode) (certificateHandle, error) { return nil, sentinel }
			case "write", "close", "check":
				r.create = func(p string, flags int, m os.FileMode) (certificateHandle, error) {
					h, e := r.certificateRoot.OpenFile(p, flags, m)
					w := &faultCertificateHandle{certificateHandle: h}
					switch stage {
					case "write":
						w.write = func([]byte) (int, error) { return 0, sentinel }
					case "close":
						w.close = func() error { _ = h.Close(); return sentinel }
					case "check":
						w.close = func() error {
							e := h.Close()
							f.io.eval = func(string) (string, error) { return "", sentinel }
							return e
						}
					}
					return w, e
				}
			case "lstat":
				r.lstat = func(string) (os.FileInfo, error) { return nil, sentinel }
			case "special":
				info, e := os.Stat(filepath.Dir(f.Target))
				if e != nil {
					t.Fatal(e)
				}
				r.lstat = func(string) (os.FileInfo, error) { return info, nil }
				wantText = "不是普通文件"
			case "rename":
				r.rename = func(string, string) error { return sentinel }
			case "final-check":
				r.rename = func(a, b string) error {
					e := r.certificateRoot.Rename(a, b)
					f.io.eval = func(string) (string, error) { return "", sentinel }
					return e
				}
			}
			err := f.Write([]byte("replacement"), 0600)
			if err == nil {
				t.Fatal("failure ignored")
			}
			if wantText != "" {
				if !strings.Contains(err.Error(), wantText) {
					t.Fatal(err)
				}
			} else if !errors.Is(err, sentinel) {
				t.Fatalf("lost error: %v", err)
			}
			got, e := os.ReadFile(f.Target)
			if e != nil {
				t.Fatal(e)
			}
			want := "original"
			if stage == "final-check" {
				want = "replacement"
			}
			if string(got) != want {
				t.Fatalf("target: %q", got)
			}
			entries, e := os.ReadDir(filepath.Dir(f.Target))
			if e != nil {
				t.Fatal(e)
			}
			if len(entries) != 1 {
				t.Fatalf("temporary file leaked: %v", entries)
			}
		})
	}
}
func TestCertificateParentReplacement(t *testing.T) {
	f, _ := certificateFixture(t)
	parent := filepath.Dir(f.Target)
	if e := os.Rename(parent, parent+"-old"); e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { _ = os.RemoveAll(parent + "-old") })
	if e := os.Mkdir(parent, 0700); e != nil {
		t.Fatal(e)
	}
	if e := f.Check(); e == nil || !strings.Contains(e.Error(), "发生变化") {
		t.Fatalf("replaced parent: %v", e)
	}
}

var _ io.Reader = (*faultCertificateHandle)(nil)

func TestCertificateOpenRootStopsOnCheckFailure(t *testing.T) {
	f, _ := certificateFixture(t)
	sentinel := errors.New("path changed")
	f.io.eval = func(string) (string, error) { return "", sentinel }
	root, err := f.openRoot()
	if root != nil {
		_ = root.Close()
		t.Fatal("opened root after failed path validation")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("lost validation error: %v", err)
	}
}
