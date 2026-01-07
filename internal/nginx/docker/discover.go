// Package docker 提供 Docker 容器操作支持
package docker

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// DiscoveredContainer 发现的容器
type DiscoveredContainer struct {
	ID          string
	Name        string
	Image       string
	Status      string
	IsCompose   bool
	ComposeFile string
	ServiceName string
}

// Discoverer 容器发现器
type Discoverer struct {
	imageFilter string
	labelFilter string
}

// NewDiscoverer 创建发现器
func NewDiscoverer(imageFilter, labelFilter string) *Discoverer {
	return &Discoverer{
		imageFilter: imageFilter,
		labelFilter: labelFilter,
	}
}

// Discover 发现 Nginx 容器
func (d *Discoverer) Discover(ctx context.Context) ([]*DiscoveredContainer, error) {
	// 构建 docker ps 命令
	args := []string{"ps", "--format", "{{json .}}"}

	// 添加过滤器
	if d.imageFilter != "" {
		args = append(args, "--filter", fmt.Sprintf("ancestor=%s", d.imageFilter))
	}
	if d.labelFilter != "" {
		args = append(args, "--filter", fmt.Sprintf("label=%s", d.labelFilter))
	}

	cmd := exec.CommandContext(ctx, "docker", args...)
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker ps failed: %w", err)
	}

	var containers []*DiscoveredContainer

	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var info struct {
			ID     string `json:"ID"`
			Names  string `json:"Names"`
			Image  string `json:"Image"`
			Status string `json:"Status"`
		}

		if err := json.Unmarshal([]byte(line), &info); err != nil {
			continue
		}

		// 检查是否是 Nginx 容器
		if !d.isNginxContainer(ctx, info.ID, info.Image) {
			continue
		}

		container := &DiscoveredContainer{
			ID:     info.ID,
			Name:   info.Names,
			Image:  info.Image,
			Status: info.Status,
		}

		// 检测是否是 compose 服务
		composeFile, serviceName := d.detectComposeInfo(ctx, info.ID)
		if composeFile != "" {
			container.IsCompose = true
			container.ComposeFile = composeFile
			container.ServiceName = serviceName
		}

		containers = append(containers, container)
	}

	return containers, nil
}

// DiscoverAll 发现所有 Nginx 容器（不使用过滤器）
func (d *Discoverer) DiscoverAll(ctx context.Context) ([]*DiscoveredContainer, error) {
	cmd := exec.CommandContext(ctx, "docker", "ps", "--format", "{{json .}}")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("docker ps failed: %w", err)
	}

	var containers []*DiscoveredContainer

	for _, line := range strings.Split(string(output), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		var info struct {
			ID     string `json:"ID"`
			Names  string `json:"Names"`
			Image  string `json:"Image"`
			Status string `json:"Status"`
		}

		if err := json.Unmarshal([]byte(line), &info); err != nil {
			continue
		}

		// 检查是否是 Nginx 容器
		if !d.isNginxContainer(ctx, info.ID, info.Image) {
			continue
		}

		container := &DiscoveredContainer{
			ID:     info.ID,
			Name:   info.Names,
			Image:  info.Image,
			Status: info.Status,
		}

		// 检测是否是 compose 服务
		composeFile, serviceName := d.detectComposeInfo(ctx, info.ID)
		if composeFile != "" {
			container.IsCompose = true
			container.ComposeFile = composeFile
			container.ServiceName = serviceName
		}

		containers = append(containers, container)
	}

	return containers, nil
}

// isNginxContainer 检查是否是 Nginx 容器
func (d *Discoverer) isNginxContainer(ctx context.Context, containerID, image string) bool {
	// 方法1: 镜像名包含 nginx
	imageLower := strings.ToLower(image)
	if strings.Contains(imageLower, "nginx") {
		return true
	}

	// 方法2: 检查进程（使用短超时）
	checkCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	cmd := exec.CommandContext(checkCtx, "docker", "exec", containerID, "pgrep", "-x", "nginx")
	if err := cmd.Run(); err == nil {
		return true
	}

	// 方法3: 检查 nginx 命令
	cmd = exec.CommandContext(checkCtx, "docker", "exec", containerID, "which", "nginx")
	if err := cmd.Run(); err == nil {
		return true
	}

	return false
}

// detectComposeInfo 检测 compose 配置信息
func (d *Discoverer) detectComposeInfo(ctx context.Context, containerID string) (composeFile, serviceName string) {
	cmd := exec.CommandContext(ctx, "docker", "inspect",
		"--format", "{{index .Config.Labels \"com.docker.compose.project.config_files\"}}|{{index .Config.Labels \"com.docker.compose.service\"}}",
		containerID)

	output, err := cmd.Output()
	if err != nil {
		return "", ""
	}

	result := strings.TrimSpace(string(output))
	parts := strings.Split(result, "|")
	if len(parts) != 2 {
		return "", ""
	}

	composeFile = strings.TrimSpace(parts[0])
	serviceName = strings.TrimSpace(parts[1])

	if composeFile == "" || serviceName == "" {
		return "", ""
	}

	return composeFile, serviceName
}

// DiscoverNginxContainers 便捷方法：发现所有 Nginx 容器
func DiscoverNginxContainers(ctx context.Context) ([]*DiscoveredContainer, error) {
	discoverer := NewDiscoverer("", "")
	return discoverer.DiscoverAll(ctx)
}

// HasNginxContainers 检查是否有 Nginx 容器在运行
func HasNginxContainers(ctx context.Context) bool {
	containers, err := DiscoverNginxContainers(ctx)
	return err == nil && len(containers) > 0
}
