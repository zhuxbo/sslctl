package util

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCertificateFileLinks(t *testing.T) {
	for _, absolute := range []bool{false, true} {
		t.Run(map[bool]string{false: "relative", true: "absolute"}[absolute], func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, "archive.pem")
			if err := os.WriteFile(target, []byte("old"), 0600); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(dir, "live.pem")
			dest := "archive.pem"
			if absolute {
				dest = target
			}
			if err := os.Symlink(dest, link); err != nil {
				t.Skip(err)
			}
			file, err := ResolveCertificateFile(link)
			if err != nil {
				t.Fatal(err)
			}
			if err := file.Write([]byte("new"), 0600); err != nil {
				t.Fatal(err)
			}
			if got, err := os.Readlink(link); err != nil || got != dest {
				t.Fatalf("link changed: %q %v", got, err)
			}
			if got, err := file.Read(100); err != nil || string(got) != "new" {
				t.Fatalf("read: %q %v", got, err)
			}
			if _, err := file.Read(2); err == nil {
				t.Fatal("size limit ignored")
			}
			other := filepath.Join(dir, "renewed.pem")
			_ = os.WriteFile(other, []byte("renewed"), 0600)
			_ = os.Remove(link)
			_ = os.Symlink(other, link)
			if err := file.Write([]byte("stale"), 0600); err == nil {
				t.Fatal("redirect accepted")
			}
			got, _ := os.ReadFile(other)
			if string(got) != "renewed" {
				t.Fatal("renewed target changed")
			}
		})
	}
}

func TestCertificateFileRejectsInvalidTargets(t *testing.T) {
	dir := t.TempDir()
	for _, test := range []struct{ name, target string }{{"dangling", "missing"}, {"loop", "loop"}, {"directory", "."}} {
		t.Run(test.name, func(t *testing.T) {
			path := filepath.Join(dir, test.name)
			if err := os.Symlink(test.target, path); err != nil {
				t.Skip(err)
			}
			if _, err := ResolveCertificateFile(path); err == nil {
				t.Fatal("invalid link accepted")
			}
		})
	}
}

func TestCertificateFileParentLink(t *testing.T) {
	dir := t.TempDir()
	a := filepath.Join(dir, "a")
	b := filepath.Join(dir, "b")
	_ = os.Mkdir(a, 0700)
	_ = os.Mkdir(b, 0700)
	link := filepath.Join(dir, "current")
	if err := os.Symlink(a, link); err != nil {
		t.Skip(err)
	}
	file, err := ResolveCertificateFile(filepath.Join(link, "cert.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Write([]byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	_ = os.Remove(link)
	_ = os.Symlink(b, link)
	if err := file.Write([]byte("bad"), 0600); err == nil {
		t.Fatal("parent redirect accepted")
	}
	if _, err := os.Stat(filepath.Join(b, "cert.pem")); !os.IsNotExist(err) {
		t.Fatal("new target written")
	}
}
