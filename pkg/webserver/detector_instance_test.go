package webserver

import (
	"strings"
	"testing"
)

func TestNginxInstanceCommandSelection(t *testing.T) {
	for _, tc := range []struct {
		name, exe, os, svc string
		exact, discover    bool
	}{
		{"target windows", "target-nginx", "windows", "target-service", true, false},
		{"target no service", "target-nginx", "windows", "", true, false},
		{"discover windows", "", "windows", "discovered-service", false, true},
		{"discover no service", "", "windows", "", false, true},
		{"target unix", "target-nginx", "linux", "", false, false},
		{"discover unix", "", "linux", "", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			found, exact, broad := false, false, false
			cmds := detectNginxCommandsFor(tc.exe, tc.os, func() string { found = true; return "discovered-nginx" }, func(kind, path string) string {
				exact = true
				if kind != "nginx" || path != tc.exe {
					t.Fatalf("exact %q %q", kind, path)
				}
				return tc.svc
			}, func(kind, image string) string {
				broad = true
				if kind != "nginx" || image != "nginx.exe" {
					t.Fatalf("broad %q %q", kind, image)
				}
				return tc.svc
			})
			bin := tc.exe
			if bin == "" {
				bin = "discovered-nginx"
			}
			reload := bin + " -s reload"
			if tc.svc != "" {
				reload = WinSvcReloadPrefix + tc.svc + WinSvcFallbackSep + reload
			}
			if cmds.TestCmd != bin+" -t" || cmds.ReloadCmd != reload || found != tc.discover || exact != tc.exact || broad != (tc.os == "windows" && tc.exe == "") {
				t.Fatalf("cmds=%+v found=%v exact=%v broad=%v", cmds, found, exact, broad)
			}
		})
	}
}

func TestServiceExecutableEmptyPathRejected(t *testing.T) {
	for _, pair := range [][2]string{{"", ""}, {"", "c:/nginx.exe"}, {"c:/nginx.exe", ""}} {
		if serviceExecutableMatchesTarget(pair[0], pair[1]) {
			t.Fatalf("matched empty path %q", pair)
		}
	}
	if !serviceExecutableMatchesTarget(`C:\Nginx.EXE`, strings.ReplaceAll(`C:\Nginx.EXE`, `\`, `/`)) {
		t.Fatal("normalized target not matched")
	}
}
