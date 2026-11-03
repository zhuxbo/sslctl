// Package config 写路径外部修改感知与读-改-写回归测试
package config

import (
	"errors"
	"testing"
	"time"
)

func TestRemoveSite_RemovesBindingStateAndOrphanCertificate(t *testing.T) {
	dir := t.TempDir()
	cm, err := NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatalf("NewConfigManagerWithDir() error = %v", err)
	}

	cfg := &Config{Certificates: []CertConfig{
		{
			CertName: "shared-cert",
			Enabled:  true,
			Bindings: []SiteBinding{
				{ServerName: "remove.example.com", Enabled: true},
				{ServerName: "keep.example.com", Enabled: true},
			},
			Metadata: CertMetadata{
				FailedBindings: []string{"remove.example.com", "keep.example.com"},
				StaleBindings:  []string{"remove.example.com", "keep.example.com"},
			},
		},
		{
			CertName: "orphan-cert",
			Enabled:  true,
			Bindings: []SiteBinding{{ServerName: "remove.example.com", Enabled: true}},
		},
	}}
	if err := cm.Save(cfg); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	result, err := cm.RemoveSite("remove.example.com")
	if err != nil {
		t.Fatalf("RemoveSite() error = %v", err)
	}
	if result.RemovedBindings != 2 {
		t.Fatalf("RemovedBindings = %d, want 2", result.RemovedBindings)
	}
	if len(result.RemovedCertificates) != 1 || result.RemovedCertificates[0].CertName != "orphan-cert" {
		t.Fatalf("RemovedCertificates = %+v, want orphan-cert", result.RemovedCertificates)
	}

	after, err := cm.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(after.Certificates) != 1 || after.Certificates[0].CertName != "shared-cert" {
		t.Fatalf("Certificates = %+v, want shared-cert only", after.Certificates)
	}
	cert := after.Certificates[0]
	if len(cert.Bindings) != 1 || cert.Bindings[0].ServerName != "keep.example.com" {
		t.Fatalf("Bindings = %+v, want keep.example.com only", cert.Bindings)
	}
	if len(cert.Metadata.FailedBindings) != 1 || cert.Metadata.FailedBindings[0] != "keep.example.com" {
		t.Fatalf("FailedBindings = %v, want keep.example.com only", cert.Metadata.FailedBindings)
	}
	if len(cert.Metadata.StaleBindings) != 1 || cert.Metadata.StaleBindings[0] != "keep.example.com" {
		t.Fatalf("StaleBindings = %v, want keep.example.com only", cert.Metadata.StaleBindings)
	}
}

func TestRemoveSite_MissingTargetDoesNotWrite(t *testing.T) {
	dir := t.TempDir()
	cm, err := NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatalf("NewConfigManagerWithDir() error = %v", err)
	}
	if err := cm.AddCert(&CertConfig{
		CertName: "keep-cert",
		Bindings: []SiteBinding{{ServerName: "keep.example.com", Enabled: true}},
	}); err != nil {
		t.Fatalf("AddCert() error = %v", err)
	}
	before, err := cm.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	_, err = cm.RemoveSite("missing.example.com")
	if !errors.Is(err, ErrSiteNotFound) {
		t.Fatalf("RemoveSite() error = %v, want ErrSiteNotFound", err)
	}
	after, err := cm.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if !after.Metadata.UpdatedAt.Equal(before.Metadata.UpdatedAt) {
		t.Fatal("missing site must not rewrite config")
	}
	if len(after.Certificates) != 1 || after.Certificates[0].CertName != "keep-cert" {
		t.Fatalf("missing site changed config: %+v", after.Certificates)
	}
}

func TestRemoveCertificate_RemovesEveryMatchingRecord(t *testing.T) {
	dir := t.TempDir()
	cm, err := NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatalf("NewConfigManagerWithDir() error = %v", err)
	}
	if err := cm.Save(&Config{Certificates: []CertConfig{
		{CertName: "duplicate-cert", Bindings: []SiteBinding{{ServerName: "a.example.com"}}},
		{CertName: "keep-cert", Bindings: []SiteBinding{{ServerName: "keep.example.com"}}},
		{CertName: "duplicate-cert", Bindings: []SiteBinding{{ServerName: "b.example.com"}}},
	}}); err != nil {
		t.Fatalf("Save() error = %v", err)
	}

	removed, err := cm.RemoveCertificate("duplicate-cert")
	if err != nil {
		t.Fatalf("RemoveCertificate() error = %v", err)
	}
	if len(removed) != 2 || removed[0].Bindings[0].ServerName != "a.example.com" || removed[1].Bindings[0].ServerName != "b.example.com" {
		t.Fatalf("removed = %+v, want both duplicate-cert records", removed)
	}
	after, err := cm.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(after.Certificates) != 1 || after.Certificates[0].CertName != "keep-cert" {
		t.Fatalf("Certificates = %+v, want keep-cert only", after.Certificates)
	}
}

// TestUpdate_SeesExternalModification 验证写路径感知外部修改：
// 两个 ConfigManager 指向同一文件（模拟 CLI 与 daemon 两进程），
// cm1 建缓存后 cm2 写入变更，cm1 再执行 Update* 不得基于陈旧缓存覆盖 cm2 的更新
// （原实现 loadLocked 命中缓存直接返回，不查 mtime，读-改-写丢更新）。
func TestUpdate_SeesExternalModification(t *testing.T) {
	dir := t.TempDir()

	cm1, err := NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatalf("创建 cm1 失败: %v", err)
	}
	cm2, err := NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatalf("创建 cm2 失败: %v", err)
	}

	// 初始配置：一个证书
	cert := &CertConfig{
		CertName: "shared.example.com-1",
		OrderID:  1,
		Enabled:  true,
		API:      APIConfig{URL: "https://api1.com", Token: "t1"},
	}
	if err := cm1.AddCert(cert); err != nil {
		t.Fatalf("AddCert 失败: %v", err)
	}

	// cm1 建立内存缓存
	if _, err := cm1.Load(); err != nil {
		t.Fatalf("cm1.Load 失败: %v", err)
	}

	// 确保 mtime 前进（文件系统时间精度余量）
	time.Sleep(10 * time.Millisecond)

	// "另一进程"（cm2）添加第二个证书
	cert2 := &CertConfig{
		CertName: "other.example.com-2",
		OrderID:  2,
		Enabled:  true,
		API:      APIConfig{URL: "https://api2.com", Token: "t2"},
	}
	if err := cm2.AddCert(cert2); err != nil {
		t.Fatalf("cm2.AddCert 失败: %v", err)
	}

	time.Sleep(10 * time.Millisecond)

	// cm1 走写路径更新 Schedule：修复前基于陈旧缓存（只有 1 个证书）整文件覆盖，
	// cm2 添加的证书被丢掉
	if err := cm1.UpdateSchedule(func(sc *ScheduleConfig) {
		sc.RenewBeforeDays = 30
	}); err != nil {
		t.Fatalf("cm1.UpdateSchedule 失败: %v", err)
	}

	// 用第三个全新实例读取盘上最终状态
	cm3, err := NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatalf("创建 cm3 失败: %v", err)
	}
	final, err := cm3.Load()
	if err != nil {
		t.Fatalf("cm3.Load 失败: %v", err)
	}

	if len(final.Certificates) != 2 {
		t.Errorf("cm2 添加的证书被 cm1 的写操作覆盖丢失：证书数 = %d, want 2", len(final.Certificates))
	}
	if final.Schedule.RenewBeforeDays != 30 {
		t.Errorf("cm1 的 Schedule 更新丢失: RenewBeforeDays = %d, want 30", final.Schedule.RenewBeforeDays)
	}
}

// TestUpdateCert_FailedMutationDoesNotDirtyCacheOrDisk 验证 fn 失败（证书不存在）时
// 不写盘、内存缓存保持与盘上一致（原实现 fn 直接修改缓存对象，失败时缓存被污染）。
func TestUpdateCert_FailedMutationDoesNotDirtyCacheOrDisk(t *testing.T) {
	dir := t.TempDir()
	cm, err := NewConfigManagerWithDir(dir)
	if err != nil {
		t.Fatalf("创建配置管理器失败: %v", err)
	}

	cert := &CertConfig{CertName: "keep.example.com-1", OrderID: 1, Enabled: true}
	if err := cm.AddCert(cert); err != nil {
		t.Fatalf("AddCert 失败: %v", err)
	}
	before, _ := cm.Load()
	beforeUpdatedAt := before.Metadata.UpdatedAt

	// 更新不存在的证书应报错
	missing := &CertConfig{CertName: "missing.example.com-9", OrderID: 9}
	if err := cm.UpdateCert(missing); err == nil {
		t.Fatal("更新不存在的证书应报错")
	}

	// 盘上与缓存均不应有变化
	after, _ := cm.Load()
	if len(after.Certificates) != 1 || after.Certificates[0].CertName != "keep.example.com-1" {
		t.Errorf("失败的更新不应改变配置: %+v", after.Certificates)
	}
	if !after.Metadata.UpdatedAt.Equal(beforeUpdatedAt) {
		t.Error("失败的更新不应写盘（UpdatedAt 不应变化）")
	}
}

// TestConcurrentUpdates_NoLostUpdate 并发回归：多 goroutine 通过两个实例交替更新，
// 最终所有更新都不丢失。
func TestConcurrentUpdates_NoLostUpdate(t *testing.T) {
	dir := t.TempDir()
	cm1, _ := NewConfigManagerWithDir(dir)
	cm2, _ := NewConfigManagerWithDir(dir)

	// 预置 4 个证书
	for _, name := range []string{"a-1", "b-2", "c-3", "d-4"} {
		if err := cm1.AddCert(&CertConfig{CertName: name, OrderID: 1, Enabled: true}); err != nil {
			t.Fatalf("AddCert %s 失败: %v", name, err)
		}
	}

	done := make(chan error, 2)
	// 两个"进程"并发更新不同证书的元数据
	go func() {
		for i := 0; i < 20; i++ {
			c, err := cm1.GetCert("a-1")
			if err != nil {
				done <- err
				return
			}
			c.Metadata.IssueRetryCount = i
			if err := cm1.UpdateCert(c); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	go func() {
		for i := 0; i < 20; i++ {
			c, err := cm2.GetCert("b-2")
			if err != nil {
				done <- err
				return
			}
			c.Metadata.IssueRetryCount = i
			if err := cm2.UpdateCert(c); err != nil {
				done <- err
				return
			}
		}
		done <- nil
	}()
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatalf("并发更新失败: %v", err)
		}
	}

	// 4 个证书都应健在
	cm3, _ := NewConfigManagerWithDir(dir)
	final, err := cm3.Load()
	if err != nil {
		t.Fatalf("加载失败: %v", err)
	}
	if len(final.Certificates) != 4 {
		t.Errorf("并发更新后证书数 = %d, want 4（存在丢更新）", len(final.Certificates))
	}
}
