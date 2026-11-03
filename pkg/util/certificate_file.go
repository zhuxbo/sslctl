package util

import (
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// 私有依赖按实例传递，便于确定性验证 I/O 失败与路径检查之间的竞争窗口。
type certificateHandle interface {
	io.Reader
	io.Writer
	Stat() (os.FileInfo, error)
	Close() error
}

type certificateRoot interface {
	Stat(string) (os.FileInfo, error)
	Lstat(string) (os.FileInfo, error)
	Open(string) (certificateHandle, error)
	OpenFile(string, int, os.FileMode) (certificateHandle, error)
	Remove(string) error
	Rename(string, string) error
	Close() error
}

type certificateOSRoot struct{ *os.Root }

func (r certificateOSRoot) Open(name string) (certificateHandle, error) { return r.Root.Open(name) }
func (r certificateOSRoot) OpenFile(name string, flags int, mode os.FileMode) (certificateHandle, error) {
	return r.Root.OpenFile(name, flags, mode)
}

type certificateIO struct {
	abs      func(string) (string, error)
	eval     func(string) (string, error)
	lstat    func(string) (os.FileInfo, error)
	stat     func(string) (os.FileInfo, error)
	openRoot func(string) (certificateRoot, error)
}

func systemCertificateIO() certificateIO {
	return certificateIO{filepath.Abs, filepath.EvalSymlinks, os.Lstat, os.Stat, func(path string) (certificateRoot, error) {
		root, err := os.OpenRoot(path)
		return certificateOSRoot{root}, err
	}}
}

// CertificateFile 只用于用户配置的证书文件；固定解析后的目标，保留原有链接。
// 通用配置、备份资产和可执行文件仍使用拒绝符号链接的文件 API。
type CertificateFile struct {
	Path   string
	Target string
	parent os.FileInfo
	io     certificateIO
}

// ResolveCertificateFile 允许普通文件首次创建，但不允许悬空链接、循环和特殊文件。
func ResolveCertificateFile(path string) (*CertificateFile, error) {
	return resolveCertificateFile(path, systemCertificateIO())
}

func resolveCertificateFile(path string, deps certificateIO) (*CertificateFile, error) {
	if path == "" {
		return nil, fmt.Errorf("证书文件路径为空")
	}
	absolute, err := deps.abs(path)
	if err != nil {
		return nil, err
	}
	target, err := deps.eval(absolute)
	if err != nil {
		if _, statErr := deps.lstat(absolute); !os.IsNotExist(statErr) {
			return nil, fmt.Errorf("解析证书链接 %s: %w", path, err)
		}
		parent, parentErr := deps.eval(filepath.Dir(absolute))
		if parentErr != nil {
			return nil, parentErr
		}
		target = filepath.Join(parent, filepath.Base(absolute))
	}
	info, err := deps.lstat(target)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if err == nil && !info.Mode().IsRegular() {
		return nil, fmt.Errorf("证书目标不是普通文件: %s", target)
	}
	parent, err := deps.stat(filepath.Dir(target))
	if err != nil {
		return nil, err
	}
	return &CertificateFile{Path: absolute, Target: target, parent: parent, io: deps}, nil
}

// Check 拒绝操作期间链接改向或父目录被替换；允许本次原子写入替换文件 inode。
func (f *CertificateFile) Check() error {
	current, err := resolveCertificateFile(f.Path, f.io)
	if err != nil {
		return err
	}
	if current.Target != f.Target || !os.SameFile(f.parent, current.parent) {
		return fmt.Errorf("证书路径在操作期间发生变化: %s", f.Path)
	}
	return nil
}

func (f *CertificateFile) openRoot() (certificateRoot, error) {
	if err := f.Check(); err != nil {
		return nil, err
	}
	root, err := f.io.openRoot(filepath.Dir(f.Target))
	if err != nil {
		return nil, err
	}
	info, err := root.Stat(".")
	if err != nil || !os.SameFile(f.parent, info) {
		_ = root.Close()
		return nil, fmt.Errorf("证书目标目录发生变化: %s", f.Target)
	}
	return root, nil
}

func (f *CertificateFile) Read(maxSize int64) ([]byte, error) {
	root, err := f.openRoot()
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	name := filepath.Base(f.Target)
	before, err := root.Lstat(name)
	if err != nil {
		return nil, &os.PathError{Op: "read", Path: f.Path, Err: err}
	}
	if !before.Mode().IsRegular() {
		return nil, fmt.Errorf("证书目标不是普通文件: %s", f.Target)
	}
	file, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	after, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(before, after) {
		return nil, fmt.Errorf("证书文件在读取前发生变化: %s", f.Path)
	}
	var reader io.Reader = file
	if maxSize > 0 {
		reader = io.LimitReader(file, maxSize+1)
	}
	data, err := io.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	if maxSize > 0 && int64(len(data)) > maxSize {
		return nil, fmt.Errorf("file too large (max %d bytes)", maxSize)
	}
	if err := f.Check(); err != nil {
		return nil, err
	}
	return data, nil
}

// Write 在真实目标目录内原子替换文件，不替换链接，也不跟随临时文件链接。
func (f *CertificateFile) Write(data []byte, mode os.FileMode) error {
	root, err := f.openRoot()
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()
	tmp := ".sslctl-" + rand.Text()
	file, err := root.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer func() { _ = root.Remove(tmp) }()
	_, writeErr := file.Write(data)
	closeErr := file.Close()
	if writeErr != nil {
		return writeErr
	}
	if closeErr != nil {
		return closeErr
	}
	if err := f.Check(); err != nil {
		return err
	}
	info, err := root.Lstat(filepath.Base(f.Target))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if err == nil && !info.Mode().IsRegular() {
		return fmt.Errorf("证书目标不是普通文件: %s", f.Target)
	}
	if err := root.Rename(tmp, filepath.Base(f.Target)); err != nil {
		return err
	}
	return f.Check()
}

// ReadCertificateFile 读取证书或私钥，支持现有软链接并保留大小限制。
func ReadCertificateFile(path string, maxSize int64) ([]byte, error) {
	file, err := ResolveCertificateFile(path)
	if err != nil {
		return nil, err
	}
	return file.Read(maxSize)
}
