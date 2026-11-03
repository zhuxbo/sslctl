package deployer

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/zhuxbo/sslctl/pkg/util"
)

func TestCertificateTargetChangedDuringReload(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("测试替身使用 POSIX shell")
	}
	for _, rollback := range []bool{false, true} {
		t.Run(map[bool]string{false: "deploy", true: "rollback"}[rollback], func(t *testing.T) {
			dir := t.TempDir()
			link := filepath.Join(dir, "live.pem")
			for _, name := range []string{"old.pem", "renewed.pem"} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(name), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink("old.pem", link); err != nil {
				t.Skip(err)
			}
			script := "#!/bin/sh\nrm " + util.ShellQuote(link) + "\nln -s renewed.pem " + util.ShellQuote(link) + "\n"
			if err := os.WriteFile(filepath.Join(dir, "nginx"), []byte(script), 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
			b := &Base{ReloadCommand: "nginx -s reload"}
			if err := b.PrepareFiles(link); err != nil {
				t.Fatal(err)
			}
			var err error
			if rollback {
				err = b.TestAndReloadForRollback(t.Context())
			} else {
				err = b.TestAndReload(t.Context())
			}
			if err == nil {
				t.Fatal("重载期间目标改向不能报告成功")
			}
			got, _ := os.ReadFile(link)
			if string(got) != "renewed.pem" {
				t.Fatal("续签目标被修改")
			}
		})
	}
}
