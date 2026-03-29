package config

import (
	"encoding/json"
	"strings"
)

// migrateAction 迁移操作类型
type migrateAction int

const (
	actionRename migrateAction = iota + 1 // 重命名字段（path 下 field→target）
	actionDelete                           // 删除字段（path 下的 field）
	actionMove                             // 扁平字段移入子对象（path 下 field→target 子对象的同名键，不覆盖已有值）
	actionSpread                           // 顶层字段分发到数组元素（合并语义，不覆盖已有值）
)

// migrateRule 声明式迁移规则
// 路径格式: "." 表示根，"certificates[]" 表示遍历数组元素，可嵌套如 "certificates[].bindings[]"
type migrateRule struct {
	action migrateAction
	path   string // 操作目标路径
	field  string // 源字段名
	target string // rename→新字段名; move→目标子对象名; spread→目标路径（如 "certificates[].api"）
}

// migrateRules 所有迁移规则（按添加顺序执行）
// 新增规则追加到末尾；每条规则必须幂等
var migrateRules = []migrateRule{
	{actionSpread, ".", "api", "certificates[].api"},
	{actionRename, "certificates[].bindings[]", "site_name", "server_name"},
	{actionDelete, "certificates[].api", "callback_url", ""},
}

// migrateConfig 检查并迁移配置
// 遍历所有规则，返回迁移后的数据和是否发生变更
func migrateConfig(data []byte) ([]byte, bool, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return data, false, err
	}

	changed := false
	for _, rule := range migrateRules {
		if applyRule(raw, rule) {
			changed = true
		}
	}

	// 递归补齐默认值
	if fillDefaults(raw) {
		changed = true
	}

	if !changed {
		return data, false, nil
	}

	newData, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return data, false, err
	}
	return newData, true, nil
}

// applyRule 分发执行迁移规则
func applyRule(root map[string]interface{}, rule migrateRule) bool {
	switch rule.action {
	case actionRename:
		return applyRename(root, rule.path, rule.field, rule.target)
	case actionDelete:
		return applyDelete(root, rule.path, rule.field)
	case actionMove:
		return applyMove(root, rule.path, rule.field, rule.target)
	case actionSpread:
		return applySpread(root, rule.field, rule.target)
	}
	return false
}

// applyRename 在 path 匹配的所有节点上，将 oldKey 重命名为 newKey
func applyRename(root map[string]interface{}, path, oldKey, newKey string) bool {
	nodes := resolvePath(root, path)
	changed := false
	for _, node := range nodes {
		val, has := node[oldKey]
		if !has {
			continue
		}
		if _, hasNew := node[newKey]; !hasNew {
			node[newKey] = val
		}
		delete(node, oldKey)
		changed = true
	}
	return changed
}

// applyDelete 在 path 匹配的所有节点上，删除 key
func applyDelete(root map[string]interface{}, path, key string) bool {
	nodes := resolvePath(root, path)
	changed := false
	for _, node := range nodes {
		if _, has := node[key]; has {
			delete(node, key)
			changed = true
		}
	}
	return changed
}

// applyMove 将 path 匹配节点的扁平字段移入子对象
// 例如：path=".", field="api_url", target="api" → root["api_url"] 移入 root["api"]["api_url"]
// 目标子对象不存在时自动创建，已有同名键时不覆盖
func applyMove(root map[string]interface{}, path, field, target string) bool {
	nodes := resolvePath(root, path)
	changed := false
	for _, node := range nodes {
		val, has := node[field]
		if !has {
			continue
		}
		// 确保目标子对象存在
		sub, ok := node[target].(map[string]interface{})
		if !ok {
			sub = make(map[string]interface{})
			node[target] = sub
		}
		// 仅在子对象中不存在同名键时写入
		if _, has := sub[field]; !has {
			sub[field] = val
		}
		delete(node, field)
		changed = true
	}
	return changed
}

// applySpread 将根节点的 sourceKey 字段分发到 targetPath 指向的每个数组元素
// 合并语义：仅补全目标节点中缺失的字段，不覆盖已有值
// 分发完成后删除源字段
func applySpread(root map[string]interface{}, sourceKey, targetPath string) bool {
	source, ok := root[sourceKey]
	if !ok {
		return false
	}
	sourceMap, ok := source.(map[string]interface{})
	if !ok {
		delete(root, sourceKey)
		return true
	}
	// 空 map 直接删除
	if len(sourceMap) == 0 {
		delete(root, sourceKey)
		return true
	}

	// 解析目标路径：parentPath 定位数组元素，field 是写入的字段名
	parentPath, field := splitTargetPath(targetPath)
	nodes := resolvePath(root, parentPath)

	for _, node := range nodes {
		existing, hasExisting := node[field]
		if !hasExisting {
			node[field] = copyMap(sourceMap)
			continue
		}
		existingMap, ok := existing.(map[string]interface{})
		if !ok {
			continue
		}
		// 合并：仅补全缺失字段
		for k, v := range sourceMap {
			if _, has := existingMap[k]; !has {
				existingMap[k] = v
			}
		}
	}

	delete(root, sourceKey)
	return true
}

// --- 默认值填充 ---

// configDefaults 当前版本的默认结构（仅包含需要补齐的顶层和 schedule 字段）
// 不包含 certificates 等数组内容——数组元素由 setup 流程创建
var configDefaults = map[string]interface{}{
	"schedule": map[string]interface{}{
		"renew_before_days": float64(DefaultRenewBeforeDays),
		"renew_mode":        RenewModePull,
	},
}

// fillDefaults 递归对比当前数据与默认结构，补齐缺失字段
// 仅添加不存在的键，不覆盖已有值
func fillDefaults(raw map[string]interface{}) bool {
	return mergeDefaults(raw, configDefaults)
}

// mergeDefaults 递归合并默认值到目标 map，返回是否有变更
func mergeDefaults(dst, defaults map[string]interface{}) bool {
	changed := false
	for k, defVal := range defaults {
		existing, has := dst[k]
		if !has {
			dst[k] = defVal
			changed = true
			continue
		}
		// 如果默认值和已有值都是 map，递归合并
		defMap, defIsMap := defVal.(map[string]interface{})
		existMap, existIsMap := existing.(map[string]interface{})
		if defIsMap && existIsMap {
			if mergeDefaults(existMap, defMap) {
				changed = true
			}
		}
	}
	return changed
}

// --- 路径解析 ---

// resolvePath 解析路径，返回所有匹配的 map 节点
// 路径格式: "." = 根节点，"key[]" = 遍历数组，"key" = 进入子 map，用 "." 分隔
func resolvePath(root map[string]interface{}, path string) []map[string]interface{} {
	if path == "." {
		return []map[string]interface{}{root}
	}

	current := []map[string]interface{}{root}
	for _, part := range strings.Split(path, ".") {
		if part == "" {
			continue
		}
		var next []map[string]interface{}
		if strings.HasSuffix(part, "[]") {
			key := strings.TrimSuffix(part, "[]")
			for _, node := range current {
				for _, elem := range getSlice(node, key) {
					if m, ok := elem.(map[string]interface{}); ok {
						next = append(next, m)
					}
				}
			}
		} else {
			for _, node := range current {
				if m, ok := getMap(node, part); ok {
					next = append(next, m)
				}
			}
		}
		current = next
	}
	return current
}

// splitTargetPath 拆分目标路径为父路径和字段名
// "certificates[].api" → ("certificates[]", "api")
// "api" → (".", "api")
func splitTargetPath(target string) (parentPath, field string) {
	idx := strings.LastIndex(target, ".")
	if idx < 0 {
		return ".", target
	}
	return target[:idx], target[idx+1:]
}

// --- 辅助函数 ---

func getSlice(m map[string]interface{}, key string) []interface{} {
	v, ok := m[key]
	if !ok {
		return nil
	}
	s, ok := v.([]interface{})
	if !ok {
		return nil
	}
	return s
}

func getMap(m map[string]interface{}, key string) (map[string]interface{}, bool) {
	v, ok := m[key]
	if !ok {
		return nil, false
	}
	result, ok := v.(map[string]interface{})
	return result, ok
}

// copyMap 浅拷贝 map（当前迁移场景值均为 string 等非引用类型，无需深拷贝）
func copyMap(src map[string]interface{}) map[string]interface{} {
	dst := make(map[string]interface{}, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
