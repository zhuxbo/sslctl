package deployer

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/zhuxbo/sslctl/pkg/util"
)

// PrepareFiles 在备份前固定证书路径，部署与失败回滚复用同一组目标。
func (b *Base) PrepareFiles(paths ...string) error {
	if b.certificateFiles != nil {
		return b.CheckFiles()
	}
	files := make(map[string]*util.CertificateFile)
	targets := make(map[string]string)
	for _, path := range paths {
		if path == "" {
			continue
		}
		if err := util.EnsureDir(filepath.Dir(path), 0700); err != nil {
			return err
		}
		file, err := util.ResolveCertificateFile(path)
		if err != nil {
			return err
		}
		if previous, ok := targets[file.Target]; ok {
			return fmt.Errorf("证书文件路径指向同一目标: %s, %s", previous, path)
		}
		targets[file.Target] = path
		files[path] = file
	}
	b.certificateFiles = files
	return nil
}

func (b *Base) CheckFiles() error {
	for _, file := range b.certificateFiles {
		if err := file.Check(); err != nil {
			return err
		}
	}
	return nil
}

func (b *Base) WriteCertificate(path string, data []byte, mode os.FileMode) error {
	if err := b.CheckFiles(); err != nil {
		return err
	}
	file := b.certificateFiles[path]
	if file == nil {
		return fmt.Errorf("证书路径未初始化: %s", path)
	}
	return file.Write(data, mode)
}

func (b *Base) RestoreCertificate(source, target string) error {
	data, err := util.SafeReadFile(source, 16<<20)
	if err != nil {
		return err
	}
	info, err := os.Stat(source)
	if err != nil {
		return err
	}
	return b.WriteCertificate(target, data, info.Mode().Perm())
}

func (b *Base) RestoreCertificateContext(path string) error {
	if err := b.CheckFiles(); err != nil {
		return err
	}
	return util.RestoreFileContext(b.certificateFiles[path].Target)
}
