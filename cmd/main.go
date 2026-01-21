// cert-deploy - SSL 证书自动部署工具
// 支持 Nginx、Apache
package main

import (
	"fmt"
	"os"

	"github.com/cnssl/cert-deploy/cmd/nginx"
	"github.com/cnssl/cert-deploy/cmd/apache"
	"github.com/cnssl/cert-deploy/pkg/logger"
)

var (
	version   = "dev"
	buildTime = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// 解析全局参数
	args := os.Args[1:]
	debug := false

	// 检查 --debug 参数
	for i, arg := range args {
		if arg == "--debug" {
			debug = true
			args = append(args[:i], args[i+1:]...)
			break
		}
	}

	if len(args) == 0 {
		printUsage()
		os.Exit(1)
	}

	// 设置 debug 模式
	if debug {
		os.Setenv("LOG_LEVEL", "debug")
		os.Setenv("CERT_DEPLOY_DEBUG", "1")
	}

	cmd := args[0]
	subArgs := args[1:]

	switch cmd {
	case "nginx":
		nginx.Run(subArgs, version, buildTime, debug)
	case "apache":
		apache.Run(subArgs, version, buildTime, debug)
	case "version", "-v", "--version":
		fmt.Printf("cert-deploy %s (built at %s)\n", version, buildTime)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "未知命令: %s\n\n", cmd)
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Printf(`cert-deploy %s - SSL 证书自动部署工具

使用方法:
  cert-deploy [--debug] <command> [options]

命令:
  nginx     Nginx 证书管理
  apache    Apache 证书管理
  version   显示版本信息
  help      显示帮助信息

全局参数:
  --debug   启用调试模式（详细日志）

Nginx 命令:
  cert-deploy nginx scan                     扫描 SSL 站点
  cert-deploy nginx deploy --site <name>     部署指定站点
  cert-deploy nginx issue --site <name>      签发证书
  cert-deploy nginx install-https            安装 HTTPS 配置
  cert-deploy nginx init --url <url> --refer_id <id>   生成站点配置
  cert-deploy nginx daemon                   守护进程模式

Apache 命令:
  cert-deploy apache scan                    扫描 SSL 站点
  cert-deploy apache deploy --site <name>    部署指定站点
  cert-deploy apache issue --site <name>     签发证书
  cert-deploy apache install-https           安装 HTTPS 配置
  cert-deploy apache init --url <url> --refer_id <id>  生成站点配置
  cert-deploy apache daemon                  守护进程模式

示例:
  cert-deploy nginx scan
  cert-deploy --debug nginx deploy --site example.com
  cert-deploy apache daemon

更多信息请访问: https://github.com/cnssl/cert-deploy
`, version)
}

// SetDebugLogger 设置调试日志记录器
func SetDebugLogger(log *logger.Logger) {
	log.SetLevel(logger.LevelDebug)
}
