package internal

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/zhuxbo/sslctl/pkg/webserver"
)

func TestRegisteredDeployersPropagatePrepareFailure(t *testing.T) {
	for _, kind := range []webserver.ServerType{webserver.TypeNginx, webserver.TypeApache} {
		t.Run(string(kind), func(t *testing.T) {
			dir := t.TempDir()
			cert := filepath.Join(dir, "cert")
			if err := os.Symlink("missing", cert); err != nil {
				t.Skip(err)
			}
			d, err := webserver.NewDeployer(kind, cert, filepath.Join(dir, "key"), "", "", "")
			if err != nil {
				t.Fatal(err)
			}
			preparer, ok := d.(interface{ Prepare() error })
			if !ok {
				t.Fatal("deployer does not expose prepare")
			}
			if err := preparer.Prepare(); err == nil {
				t.Fatal("adapter swallowed invalid target error")
			}
		})
	}
}
