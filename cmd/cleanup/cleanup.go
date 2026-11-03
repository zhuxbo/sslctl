// Package cleanup 提供按站点或证书解除 sslctl 管理的命令。
package cleanup

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	cleanupservice "github.com/zhuxbo/sslctl/pkg/cleanup"
	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/util"
)

var (
	checkRootPrivilege = util.CheckRootPrivilege
	newConfigManager   = config.NewConfigManager
	exitProcess        = os.Exit
)

// Run 运行 cleanup 命令。
func Run(args []string) {
	if err := checkRootPrivilege(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		exitProcess(1)
	}
	cfgManager, err := newConfigManager()
	if err != nil {
		fmt.Fprintf(os.Stderr, "初始化配置失败: %v\n", err)
		exitProcess(1)
	}
	if err := run(args, os.Stdin, os.Stdout, os.Stderr, cfgManager); err != nil {
		fmt.Fprintf(os.Stderr, "清理失败: %v\n", err)
		exitProcess(1)
	}
}

func run(args []string, input io.Reader, output, errOutput io.Writer, cfgManager *config.ConfigManager) error {
	fs := flag.NewFlagSet("cleanup", flag.ContinueOnError)
	fs.SetOutput(errOutput)
	siteName := fs.String("site", "", "解除指定站点的 sslctl 管理")
	certName := fs.String("cert", "", "解除指定证书的 sslctl 管理")
	listOnly := fs.Bool("list", false, "列出全部受管证书和站点绑定")
	yes := fs.Bool("yes", false, "跳过确认提示")
	fs.Usage = func() {
		_, _ = fmt.Fprintln(errOutput, "用法: sslctl cleanup --list")
		_, _ = fmt.Fprintln(errOutput, "      sslctl cleanup --site <server_name> [--yes]")
		_, _ = fmt.Fprintln(errOutput, "      sslctl cleanup --cert <cert_name> [--yes]")
	}
	if err := fs.Parse(args); errors.Is(err, flag.ErrHelp) {
		return nil
	} else if err != nil {
		return err
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("不接受位置参数: %s", strings.Join(fs.Args(), " "))
	}

	*siteName = strings.TrimSpace(*siteName)
	*certName = strings.TrimSpace(*certName)
	if *listOnly {
		if *siteName != "" || *certName != "" || *yes {
			return fmt.Errorf("--list 必须单独使用")
		}
		return listManaged(output, cfgManager)
	}
	if (*siteName == "") == (*certName == "") {
		return fmt.Errorf("必须且只能指定 --site 或 --cert")
	}

	targetType, targetName := "站点", *siteName
	if *certName != "" {
		targetType, targetName = "证书", *certName
	}
	if !*yes {
		if _, err := fmt.Fprintf(output, "将解除%s %s 的 sslctl 管理并清除内部状态；在线证书文件和 Web 配置会保留。\n", targetType, targetName); err != nil {
			return fmt.Errorf("写入输出失败: %w", err)
		}
		if _, err := fmt.Fprint(output, "确认继续？[y/N] "); err != nil {
			return fmt.Errorf("写入输出失败: %w", err)
		}
		answer, err := bufio.NewReader(input).ReadString('\n')
		if err != nil && err != io.EOF {
			return fmt.Errorf("读取确认输入失败: %w", err)
		}
		answer = strings.ToLower(strings.TrimSpace(answer))
		if answer != "y" && answer != "yes" {
			if _, err := fmt.Fprintln(output, "已取消清理。"); err != nil {
				return fmt.Errorf("写入输出失败: %w", err)
			}
			return nil
		}
	}

	release, acquired, err := config.AcquireRenewalLock(cfgManager.GetWorkDir())
	if err != nil {
		return err
	}
	if !acquired {
		return fmt.Errorf("另一个 setup、deploy、cleanup 或续签任务正在执行，请稍后重试")
	}
	defer release()

	service := cleanupservice.New(cfgManager)
	var result *cleanupservice.Result
	if *siteName != "" {
		result, err = service.RemoveSite(*siteName)
	} else {
		result, err = service.RemoveCertificate(*certName)
	}
	if result != nil {
		if _, outputErr := fmt.Fprintf(output, "已解除%s %s 的 sslctl 管理：移除 %d 个站点绑定、%d 张证书记录。\n",
			targetType, targetName, result.RemovedBindings, result.RemovedCertificates); outputErr != nil {
			err = errors.Join(err, fmt.Errorf("写入输出失败: %w", outputErr))
		}
		if _, outputErr := fmt.Fprintln(output, "在线证书文件和 Web 配置已保留。"); outputErr != nil {
			err = errors.Join(err, fmt.Errorf("写入输出失败: %w", outputErr))
		}
	}
	return err
}

func listManaged(output io.Writer, cfgManager *config.ConfigManager) error {
	certs, err := cfgManager.ListCerts()
	if err != nil {
		return fmt.Errorf("读取管理配置失败: %w", err)
	}

	bindingCount := 0
	for i := range certs {
		bindingCount += len(certs[i].Bindings)
	}
	if _, err := fmt.Fprintf(output, "受管证书：%d 条记录\n", len(certs)); err != nil {
		return fmt.Errorf("写入输出失败: %w", err)
	}
	for i := range certs {
		state := "禁用"
		if certs[i].Enabled {
			state = "启用"
		}
		if _, err := fmt.Fprintf(output, "  - %s [%s]\n", certs[i].CertName, state); err != nil {
			return fmt.Errorf("写入输出失败: %w", err)
		}
	}

	if _, err := fmt.Fprintf(output, "受管站点绑定：%d 条\n", bindingCount); err != nil {
		return fmt.Errorf("写入输出失败: %w", err)
	}
	for i := range certs {
		for j := range certs[i].Bindings {
			state := "禁用"
			if certs[i].Bindings[j].Enabled {
				state = "启用"
			}
			if _, err := fmt.Fprintf(output, "  - %s -> %s [%s]\n",
				certs[i].Bindings[j].ServerName, certs[i].CertName, state); err != nil {
				return fmt.Errorf("写入输出失败: %w", err)
			}
		}
	}
	return nil
}
