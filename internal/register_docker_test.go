package internal

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	nginxScanner "github.com/zhuxbo/sslctl/internal/nginx/scanner"
)

// 模拟只有 docker、没有 docker-compose，且 Compose 原配置已不可用的宿主机。
func setupScanDocker(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("使用 POSIX shell 模拟 Docker CLI")
	}
	dir := t.TempDir()
	trace := filepath.Join(dir, "trace")
	script := `#!/bin/sh
printf '%s\n' "$*" >> "$SCAN_TRACE"
case "$1" in
  version) exit 0 ;;
  ps)
    [ "$SCAN_FAILURE" = discovery ] && exit 1
    printf '%s\n' '{"ID":"abc123","Names":"mlmw-nginx","Image":"ticket-nginx:latest"}'
    ;;
  inspect)
    if [ "$2" = --format ]; then
      printf '%s\n' '/missing/docker-compose.yml|mlmw-nginx'
    else
      [ "$SCAN_FAILURE" = inspect ] && exit 1
      printf '%s\n' '[{"Id":"abc123","Name":"/mlmw-nginx","State":{"Running":true},"Mounts":[{"Type":"bind","Source":"/host/ssl","Destination":"/etc/nginx/ssl","RW":true}]}]'
    fi
    ;;
  exec)
    [ "$2" = abc123 ] && [ "$3" = sh ] && [ "$4" = -c ] || exit 2
    case "$5" in
      'nginx -t 2>&1') printf '%s\n' 'nginx: the configuration file /etc/nginx/nginx.conf syntax is ok' ;;
      "cat '/etc/nginx/nginx.conf'")
        printf '%s\n' 'server {' 'listen 443 ssl;' 'server_name ticket.mlmw.online localhost;' 'ssl_certificate /etc/nginx/ssl/cert.pem;' 'ssl_certificate_key /etc/nginx/ssl/key.pem;' '}'
        ;;
      *) exit 3 ;;
    esac
    ;;
  *) exit 4 ;;
esac
`
	if err := os.WriteFile(filepath.Join(dir, "docker"), []byte(script), 0755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir)
	t.Setenv("SCAN_TRACE", trace)
	t.Setenv("SCAN_FAILURE", "")
	return trace
}

func TestNginxScanComposeContainerWithoutComposeCLI(t *testing.T) {
	trace := setupScanDocker(t)
	a := &nginxScannerAdapter{scanner: nginxScanner.NewWithConfig(filepath.Join(t.TempDir(), "missing.conf"))}
	sites, err := a.Scan()
	if err != nil || len(sites) != 1 {
		t.Fatalf("Scan() = %v, %v，期望宿主没有站点时仍发现容器站点", sites, err)
	}
	site := sites[0]
	if site.ServerName != "ticket.mlmw.online" || site.ContainerID != "abc123" || site.ContainerName != "mlmw-nginx" {
		t.Fatalf("容器站点信息错误: %+v", site)
	}
	if !site.VolumeMode || site.HostCertPath != "/host/ssl/cert.pem" || site.HostKeyPath != "/host/ssl/key.pem" {
		t.Fatalf("证书挂载映射错误: %+v", site)
	}
	commands, err := os.ReadFile(trace)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(commands), "exec abc123 sh -c nginx -t") {
		t.Fatalf("未按已发现的容器 ID 执行: %s", commands)
	}
}

func TestNginxScanReportsDockerFailure(t *testing.T) {
	for _, tc := range []struct{ failure, want string }{
		{"discovery", "发现 Docker Nginx 容器失败"},
		{"inspect", "扫描 Docker Nginx 容器 mlmw-nginx 失败"},
	} {
		t.Run(tc.failure, func(t *testing.T) {
			setupScanDocker(t)
			t.Setenv("SCAN_FAILURE", tc.failure)
			a := &nginxScannerAdapter{scanner: nginxScanner.NewWithConfig(filepath.Join(t.TempDir(), "missing.conf"))}
			sites, err := a.Scan()
			if len(sites) != 0 || err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Scan() = %v, %v，期望保留 Docker 错误 %q", sites, err, tc.want)
			}
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
				t.Fatalf("未保留 Docker 命令退出错误: %v", err)
			}
		})
	}
}

func TestNginxScanKeepsLocalSitesWhenDockerFails(t *testing.T) {
	setupScanDocker(t)
	t.Setenv("SCAN_FAILURE", "inspect")
	configPath := filepath.Join(t.TempDir(), "nginx.conf")
	if err := os.WriteFile(configPath, []byte("server {\nlisten 80;\nserver_name local.example.com;\n}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	a := &nginxScannerAdapter{scanner: nginxScanner.NewWithConfig(configPath)}
	sites, err := a.Scan()
	if err != nil || len(sites) != 1 || sites[0].ServerName != "local.example.com" {
		t.Fatalf("Docker 失败不应丢弃本地站点: %v, %v", sites, err)
	}
}
