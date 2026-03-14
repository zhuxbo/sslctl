package docker

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDeployToHost_Success(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	d := &Deployer{
		hostCertPath: certPath,
		hostKeyPath:  keyPath,
	}

	cert := "-----BEGIN CERTIFICATE-----\ntest cert\n-----END CERTIFICATE-----"
	key := "-----BEGIN PRIVATE KEY-----\ntest key\n-----END PRIVATE KEY-----"

	if err := d.deployToHost(cert, key); err != nil {
		t.Fatalf("deployToHost: %v", err)
	}

	// 验证证书内容
	certData, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	if string(certData) != cert {
		t.Errorf("cert content mismatch")
	}

	// 验证私钥内容
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("read key: %v", err)
	}
	if string(keyData) != key {
		t.Errorf("key content mismatch")
	}

	// 验证私钥权限（0600）
	keyInfo, err := os.Stat(keyPath)
	if err != nil {
		t.Fatalf("stat key: %v", err)
	}
	if keyInfo.Mode().Perm() != 0600 {
		t.Errorf("key permission = %o, want 0600", keyInfo.Mode().Perm())
	}
}

func TestDeployToHost_Fullchain(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "fullchain.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	d := &Deployer{
		hostCertPath: certPath,
		hostKeyPath:  keyPath,
	}

	cert := "server cert"
	intermediate := "intermediate cert"
	fullchain := cert + "\n" + intermediate
	key := "private key"

	if err := d.deployToHost(fullchain, key); err != nil {
		t.Fatalf("deployToHost: %v", err)
	}

	data, err := os.ReadFile(certPath)
	if err != nil {
		t.Fatalf("read cert: %v", err)
	}
	if string(data) != fullchain {
		t.Errorf("fullchain content mismatch: got %q", string(data))
	}
}

func TestDeployToHost_DifferentDirectories(t *testing.T) {
	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "certs", "cert.pem")
	keyPath := filepath.Join(tmpDir, "keys", "key.pem")

	d := &Deployer{
		hostCertPath: certPath,
		hostKeyPath:  keyPath,
	}

	if err := d.deployToHost("cert", "key"); err != nil {
		t.Fatalf("deployToHost: %v", err)
	}

	// 验证两个目录都创建了
	if _, err := os.Stat(filepath.Dir(certPath)); err != nil {
		t.Errorf("cert dir not created: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(keyPath)); err != nil {
		t.Errorf("key dir not created: %v", err)
	}
}

func TestNewDeployer_DefaultCommands(t *testing.T) {
	client := NewClient("abc123")
	d := NewDeployer(client, DeployerOptions{
		CertPath: "/ssl/cert.pem",
		KeyPath:  "/ssl/key.pem",
	})

	if d.testCommand != "nginx -t" {
		t.Errorf("testCommand = %q, want 'nginx -t'", d.testCommand)
	}
	if d.reloadCommand != "nginx -s reload" {
		t.Errorf("reloadCommand = %q, want 'nginx -s reload'", d.reloadCommand)
	}
}

func TestNewDeployer_CustomCommands(t *testing.T) {
	client := NewClient("abc123")
	d := NewDeployer(client, DeployerOptions{
		CertPath:      "/ssl/cert.pem",
		KeyPath:       "/ssl/key.pem",
		TestCommand:   "/usr/sbin/nginx -t",
		ReloadCommand: "kill -HUP 1",
	})

	if d.testCommand != "/usr/sbin/nginx -t" {
		t.Errorf("testCommand = %q", d.testCommand)
	}
	if d.reloadCommand != "kill -HUP 1" {
		t.Errorf("reloadCommand = %q", d.reloadCommand)
	}
}

func TestGetDeployMode(t *testing.T) {
	client := NewClient("abc123")

	tests := []struct {
		name       string
		opts       DeployerOptions
		volumeMode bool
		want       string
	}{
		{
			name:       "auto 默认",
			opts:       DeployerOptions{CertPath: "/ssl/cert.pem", KeyPath: "/ssl/key.pem"},
			volumeMode: false,
			want:       "auto",
		},
		{
			name:       "volume 模式",
			opts:       DeployerOptions{CertPath: "/ssl/cert.pem", KeyPath: "/ssl/key.pem"},
			volumeMode: true,
			want:       "volume",
		},
		{
			name: "copy 模式",
			opts: DeployerOptions{
				CertPath:   "/ssl/cert.pem",
				KeyPath:    "/ssl/key.pem",
				DeployMode: "copy",
			},
			want: "copy",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			d := NewDeployer(client, tt.opts)
			d.volumeMode = tt.volumeMode
			if got := d.GetDeployMode(); got != tt.want {
				t.Errorf("GetDeployMode() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsVolumeMode(t *testing.T) {
	client := NewClient("abc123")
	d := NewDeployer(client, DeployerOptions{
		CertPath: "/ssl/cert.pem",
		KeyPath:  "/ssl/key.pem",
	})

	if d.IsVolumeMode() {
		t.Error("expected IsVolumeMode() = false initially")
	}

	d.SetHostPaths("/host/cert.pem", "/host/key.pem")
	if !d.IsVolumeMode() {
		t.Error("expected IsVolumeMode() = true after SetHostPaths")
	}
}

func TestGetHostPaths(t *testing.T) {
	client := NewClient("abc123")
	d := NewDeployer(client, DeployerOptions{
		CertPath:     "/ssl/cert.pem",
		KeyPath:      "/ssl/key.pem",
		HostCertPath: "/host/cert.pem",
		HostKeyPath:  "/host/key.pem",
	})

	certPath, keyPath := d.GetHostPaths()
	if certPath != "/host/cert.pem" {
		t.Errorf("certPath = %q", certPath)
	}
	if keyPath != "/host/key.pem" {
		t.Errorf("keyPath = %q", keyPath)
	}
}

func TestSetHostPaths(t *testing.T) {
	client := NewClient("abc123")
	d := NewDeployer(client, DeployerOptions{
		CertPath: "/ssl/cert.pem",
		KeyPath:  "/ssl/key.pem",
	})

	d.SetHostPaths("/host/cert.pem", "/host/key.pem")
	certPath, keyPath := d.GetHostPaths()
	if certPath != "/host/cert.pem" {
		t.Errorf("certPath = %q", certPath)
	}
	if keyPath != "/host/key.pem" {
		t.Errorf("keyPath = %q", keyPath)
	}
	if !d.IsVolumeMode() {
		t.Error("expected VolumeMode = true")
	}
}

func TestSetHostPaths_Empty(t *testing.T) {
	client := NewClient("abc123")
	d := NewDeployer(client, DeployerOptions{
		CertPath: "/ssl/cert.pem",
		KeyPath:  "/ssl/key.pem",
	})

	d.SetHostPaths("", "")
	if d.IsVolumeMode() {
		t.Error("expected VolumeMode = false for empty paths")
	}
}

func TestCreateFromSite_VolumeMode(t *testing.T) {
	client := NewClient("abc123")
	site := &SSLSite{
		CertificatePath: "/ssl/cert.pem",
		PrivateKeyPath:  "/ssl/key.pem",
		HostCertPath:    "/host/cert.pem",
		HostKeyPath:     "/host/key.pem",
		VolumeMode:      true,
	}

	d := CreateFromSite(client, site, "nginx -t", "nginx -s reload")
	if d.deployMode != "volume" {
		t.Errorf("deployMode = %q, want volume", d.deployMode)
	}
	if d.hostCertPath != "/host/cert.pem" {
		t.Errorf("hostCertPath = %q", d.hostCertPath)
	}
}

func TestCreateFromSite_CopyMode(t *testing.T) {
	client := NewClient("abc123")
	site := &SSLSite{
		CertificatePath: "/ssl/cert.pem",
		PrivateKeyPath:  "/ssl/key.pem",
		VolumeMode:      false,
	}

	d := CreateFromSite(client, site, "", "")
	if d.deployMode != "copy" {
		t.Errorf("deployMode = %q, want copy", d.deployMode)
	}
	if d.testCommand != "nginx -t" {
		t.Errorf("testCommand = %q, want default 'nginx -t'", d.testCommand)
	}
}

func TestValidateCommand(t *testing.T) {
	tests := []struct {
		cmd  string
		want bool
	}{
		{"nginx -t", true},
		{"nginx -s reload", true},
		{"nginx -s reopen", true},
		{"/usr/sbin/nginx -t", true},
		{"/usr/sbin/nginx -s reload", true},
		{"kill -HUP 1", true},
		{"rm -rf /", false},
		{"curl http://evil.com", false},
		{"", false},
		{" nginx -t ", true}, // 带空格
	}

	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			if got := ValidateCommand(tt.cmd); got != tt.want {
				t.Errorf("ValidateCommand(%q) = %v, want %v", tt.cmd, got, tt.want)
			}
		})
	}
}

func TestGetDir(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{"/etc/nginx/ssl/cert.pem", "/etc/nginx/ssl"},
		{"/cert.pem", ""},
		{"file.pem", ""},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			if got := getDir(tt.path); got != tt.want {
				t.Errorf("getDir(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}
