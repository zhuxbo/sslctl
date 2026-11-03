// Package certops 证书续签逻辑
package certops

import (
	"context"
	"crypto/x509"
	stderrors "errors"
	"fmt"
	"math/rand/v2"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/zhuxbo/sslctl/pkg/config"
	"github.com/zhuxbo/sslctl/pkg/csr"
	"github.com/zhuxbo/sslctl/pkg/errors"
	"github.com/zhuxbo/sslctl/pkg/fetcher"
	"github.com/zhuxbo/sslctl/pkg/logger"
	"github.com/zhuxbo/sslctl/pkg/util"
	"github.com/zhuxbo/sslctl/pkg/validator"
)

// pendingKeyDir 待确认私钥目录
const pendingKeyDir = "pending-keys"

// MaxIssueRetryCount 签发尝试上限（CSR 提交），>= 10 触顶
const MaxIssueRetryCount = config.AttemptCap

// MaxDeployAttemptCount 部署尝试上限，>= 10 触顶；与签发计数分离
const MaxDeployAttemptCount = config.AttemptCap

// MaxRetryAttemptCount 失败绑定重试上限，>= 10 停车（迁入 stale_bindings 并停止重试）。
// 使用独立计数（config.CertMetadata.RetryAttemptCount）而非证书级 DeployAttemptCount：
// 绑定级重试是 deploy-spec 未建模的平台扩展，共用公共计数会让单个坏站点、API 宕机或
// 服务端签发中把整张证书打进 CAPPED，健康站点跟着过期。
const MaxRetryAttemptCount = config.AttemptCap

// ErrNoEnabledBinding 证书没有任何启用的站点绑定（配置异常，无部署目标）。
// 部署函数据此返回明确错误而非 (0, nil, nil)，防止调用方把"一个站点都没部署"读成成功。
var ErrNoEnabledBinding = stderrors.New("证书没有启用的站点绑定")

// AutoActionSafetyMargin 自动动作安全余量（deploy-spec §3.2/§11）：
// 证书剩余有效期小于该值时不再启动新的签发/部署动作，避免临门失败与噪声。
const AutoActionSafetyMargin = 24 * time.Hour

// MaxRenewBatch 单次续签批量上限（借鉴 sslbt）
const MaxRenewBatch = 100

// 多证书分散延迟常量（借鉴 sslbt _calc_spread_delay 策略）
const (
	SpreadTotalMax = 600 // 总分散延迟上限（秒）
	SpreadMin      = 5   // 最小延迟（秒）
	SpreadMax      = 120 // 最大延迟（秒）
)

// MaxRenewBeforeDays renew_before_days 的合理上限（deploy-spec 2.9）。
// 无论续费还是重签，续签动作都应发生在到期前 30 天以内；
// 异常大值会把全部证书拉入"需要续签"状态、触发每日全量续签风暴，视为服务端异常值拒绝。
const MaxRenewBeforeDays = config.MaxRenewBeforeDays

// tryUpdateRenewBeforeDays 如果 API 返回了有效的 renew_before_days，更新本地配置
// 非关键路径，失败仅记录日志；超出合理上限时拒绝并保留旧值
func (s *Service) tryUpdateRenewBeforeDays(renewBeforeDays int) {
	if renewBeforeDays > MaxRenewBeforeDays {
		s.log.Warn("服务端返回的 renew_before_days=%d 超过上限 %d（续签应在到期前 30 天内），保留本地配置", renewBeforeDays, MaxRenewBeforeDays)
		return
	}
	applied, err := s.cfgManager.UpdateRenewBeforeDays(renewBeforeDays)
	if err != nil {
		s.log.Warn("更新 renew_before_days 失败: %v", err)
	} else if applied {
		s.log.Debug("renew_before_days 已更新为 %d（来自服务端）", renewBeforeDays)
	}
}

// calcSpreadDelay 根据待处理证书数量动态计算延迟范围
// 少量证书使用较长间隔，大量证书自动缩短以控制总时长
func calcSpreadDelay(count int) (int, int) {
	if count <= 1 {
		return SpreadMin, SpreadMax
	}
	sMax := SpreadTotalMax / count
	if sMax > SpreadMax {
		sMax = SpreadMax
	}
	if sMax < SpreadMin {
		sMax = SpreadMin
	}
	sMin := sMax / 4
	if sMin < SpreadMin {
		sMin = SpreadMin
	}
	return sMin, sMax
}

// CheckAndRenewAll 检查并续签所有证书
func (s *Service) CheckAndRenewAll(ctx context.Context) ([]*RenewResult, error) {
	cfg, err := s.cfgManager.Load()
	if err != nil {
		return nil, fmt.Errorf("加载配置失败: %w", err)
	}

	// 同名条目告警：只能由历史上未做重名检测的改名产生，其中必有零绑定孤儿，
	// 而 UpdateCert 按名匹配首条会写错条目。不自动合并/删除，交人工处理。
	if dups, dupErr := s.cfgManager.FindDuplicateCertNames(); dupErr == nil && len(dups) > 0 {
		s.log.Error("配置中存在重名证书条目 %v，元数据可能写到错误条目上，请人工清理", dups)
	}

	// 轮内 token 黑名单每轮清空：§2.2 的语义是「本轮停止」，不重置等于升级成永久停止，
	// token 换发后再也不会被重试
	s.authGate.reset()

	var results []*RenewResult
	var needsDelay bool // 上一轮是否发起了 API 请求，需要延迟

	// 收集会发起 API 请求的证书（续签 + 失败重试 + 零值回填），计算动态延迟。
	// 触顶 / 过期 / policy 阻断静默跳过、不发起请求，不计入延迟（规范 3.2）。
	pendingCount := 0
	for i := range cfg.Certificates {
		cert := cfg.Certificates[i]
		if s.willMakeAPICall(&cert, &cfg.Schedule) {
			pendingCount++
		}
	}
	if pendingCount > MaxRenewBatch {
		s.log.Warn("待处理证书数 %d 超过批量上限 %d，本次仅处理前 %d 个", pendingCount, MaxRenewBatch, MaxRenewBatch)
		pendingCount = MaxRenewBatch
	}
	spreadMin, spreadMax := calcSpreadDelay(pendingCount)

	processedCount := 0
	for i := range cfg.Certificates {
		// 上一轮处理了证书（发起过 API 请求），随机延迟后再继续
		if needsDelay {
			delay := time.Duration(spreadMin+rand.IntN(spreadMax-spreadMin+1)) * time.Second
			s.log.Debug("等待 %d 秒后处理下一个证书...", int(delay.Seconds()))
			timer := time.NewTimer(delay)
			select {
			case <-ctx.Done():
				timer.Stop()
				return results, ctx.Err()
			case <-timer.C:
			}
		}

		// 使用值拷贝而非指针，确保深拷贝保护有效
		result, madeAPICall := s.processCertRenewal(ctx, cfg, cfg.Certificates[i], &processedCount)
		needsDelay = madeAPICall
		if result != nil {
			results = append(results, result)
		}
	}

	s.reportAuthBlocks()

	// 更新检查时间（使用原子更新避免覆盖其他并发修改）
	_ = s.cfgManager.UpdateMetadata(func(m *config.ConfigMetadata) {
		m.LastCheckAt = time.Now()
	})

	return results, nil
}

// reportAuthBlocks 汇总本轮 token 级阻断。
// 逐张只记 Debug，这里统一出一条 Error——否则 100 张证书会刷 100 行同因告警，
// 而"本轮几乎什么都没做"的真正原因反而被埋掉。
func (s *Service) reportAuthBlocks() {
	tokens, codes, skipped := s.authGate.summary()
	if tokens == 0 {
		return
	}
	s.log.Error("本轮有 %d 个 API Token 被服务端拒绝（%s），已跳过使用它们的 %d 张证书（下轮调度照常重试）；"+
		"凭据类需人工换发 token 或放行 IP，限流类等窗口过去即自愈",
		tokens, strings.Join(codes, ", "), skipped)
}

// willMakeAPICall 判断证书本轮是否会发起 API 请求（用于分散延迟预估）。
// 触顶 / 过期 / policy 阻断静默跳过、不发请求，返回 false。
func (s *Service) willMakeAPICall(cert *config.CertConfig, schedule *config.ScheduleConfig) bool {
	if !cert.Enabled {
		return false
	}
	if isTerminalIssueState(cert.Metadata.LastIssueState) || cert.IsIllegalIPConfig(schedule) {
		return false
	}
	// 零启用绑定：闸门在回填之前拦截，全程零 API 请求（必须先于下面的零到期分支判断，
	// 否则零绑定 + 到期时间未知会被预估成"要发请求"，与编排层实际行为反向漂移）
	if !cert.HasEnabledBinding() {
		return false
	}
	// 到期时间未知：会发起一次 API 查询回填
	if cert.Metadata.CertExpiresAt.IsZero() {
		return true
	}
	// 已过期静默；安全余量只阻止建立新尝试，已在途查询与 active 部署仍需收尾。
	if cert.IsExpired() {
		return false
	}
	entryState := normalizeIssueState(cert.Metadata.LastIssueState)
	hasInFlightIssue := hasLocalCSRIntent(cert) ||
		entryState == config.IssueStateProcessing ||
		entryState == config.IssueStateActive
	if time.Until(cert.Metadata.CertExpiresAt) < AutoActionSafetyMargin && !hasInFlightIssue {
		return false
	}
	// 计数触顶：静默
	if cappedPhaseFor(cert, schedule) != "" {
		return false
	}
	return hasInFlightIssue || cert.NeedsRenewal(schedule) || len(cert.Metadata.FailedBindings) > 0
}

// cappedPhaseFor 返回证书当前应进入 CAPPED 的阶段，未触顶返回 ""。
//
// 签发触顶仅拦截"即将提交新 CSR"的情形；已在途（processing）或已秒签待部署（active）的证书
// 不受签发触顶影响——其继续推进由部署触顶（DeployAttemptCount）约束，避免已签发证书被误判
// 停机而白白过期。
//
// 编排层（processCertRenewal）与延迟预估（willMakeAPICall）共用本判定：两处各写一份时，
// 预估会把仍需查询的在途证书算作"不发请求"，且未来改一处漏一处就会变成真实的停机误判。
func cappedPhaseFor(cert *config.CertConfig, schedule *config.ScheduleConfig) string {
	entryState := normalizeIssueState(cert.Metadata.LastIssueState)
	if cert.GetRenewMode(schedule) == config.RenewModeLocal &&
		cert.Metadata.IssueRetryCount >= MaxIssueRetryCount &&
		entryState != config.IssueStateProcessing && entryState != config.IssueStateActive {
		return config.CappedPhaseIssue
	}
	if cert.Metadata.DeployAttemptCount >= MaxDeployAttemptCount &&
		cert.Metadata.DeployStartedAt.IsZero() {
		return config.CappedPhaseDeploy
	}
	return ""
}

// isTerminalIssueState 判断是否为终止态（静默跳过，等待人工处理）
func isTerminalIssueState(state string) bool {
	switch state {
	case config.IssueStateCapped, config.IssueStateExpired, config.IssueStatePolicyBlocked:
		return true
	}
	return false
}

// normalizeIssueState 将服务端 pending / approving 状态归一为 processing（spec 2.4/2.6/3.5）：
// pending 表示已提交仍在处理，approving 是 processing 与 active 之间的短暂中间态，
// 统一走查询路径——只 GET、不重复 POST、不增计数、不重新生成 CSR。
func normalizeIssueState(state string) string {
	switch state {
	case "pending", "approving":
		return config.IssueStateProcessing
	}
	return state
}

// processCertRenewal 处理单个证书的续签检查。
// 含 panic 隔离：单证书处理 panic 记为该证书失败并计入统计，不拖垮整轮续签（panic 无干净部署结果，不发回调）。
// 返回 result（nil 表示本证书无需处理）与是否发起过 API 请求（用于证书间分散延迟）。
func (s *Service) processCertRenewal(ctx context.Context, cfg *config.Config, cert config.CertConfig, processedCount *int) (result *RenewResult, madeAPICall bool) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("证书 %s 续签处理 panic（已隔离，继续处理其余证书）: %v", cert.CertName, r)
			// panic 无干净部署结果：仅记 Error 日志与失败结果供统计，不上报回调（spec 1.2/2.8）
			result = &RenewResult{
				CertName: cert.CertName,
				Mode:     cert.GetRenewMode(&cfg.Schedule),
				Status:   "failure",
				Error:    fmt.Errorf("续签处理 panic: %v", r),
			}
		}
	}()

	// 已持久化终止态的清理收尾是纯本地动作，必须先于 enabled/API 门禁；
	// 即使证书随后被禁用或凭据被移除，也要继续幂等清理 pending 与验证文件。
	switch cert.Metadata.LastIssueState {
	case config.IssueStatePolicyBlocked:
		s.persistTerminalState(&cert, config.IssueStatePolicyBlocked, "")
		return nil, false
	case config.IssueStateCapped:
		s.persistTerminalState(&cert, config.IssueStateCapped, cert.Metadata.CappedPhase)
		return nil, false
	case config.IssueStateExpired:
		s.persistTerminalState(&cert, config.IssueStateExpired, "")
		return nil, false
	}

	if !cert.Enabled {
		return nil, false
	}

	// policy 阻断是纯本地判定，必须先于 API 配置检查；缺凭据的非法 IP 配置
	// 同样要进入终止态并清理可能已有的在途产物。
	if cert.IsIllegalIPConfig(&cfg.Schedule) {
		s.persistTerminalState(&cert, config.IssueStatePolicyBlocked, "")
		s.log.Warn("证书 %s 为非法 IP 配置（IP 证书须 local+file），已阻断自动续签，请重新 setup", cert.CertName)
		return nil, false
	}

	// 逐证书检查 API 配置
	api := cert.GetAPI(s.log)
	if api.URL == "" || api.Token == "" {
		s.log.Warn("证书 %s 的 API 配置不完整，跳过续签", cert.CertName)
		return nil, false
	}

	// 零启用绑定闸门：证书 enabled 却没有任何启用绑定（站点被 setup/deploy 改绑到其它证书、
	// 人工禁用、改名产生的孤儿条目等）——没有部署目标，退出自动流程：不发起任何 API 请求、
	// 不部署、不计数、不回调，落阻断标记等待人工处理。
	//
	// 位置必须在"到期时间回填"之前：回填内部会走 syncOrderID → FixCertName → RenameCert，
	// 等于让一个已被阻断的证书去改写配置；且零绑定 + 到期未知的证书若卡在回填失败上，
	// 会每天发一次注定无用的请求却永远拿不到标记。
	// 闸门内部先跑两个纯本地判定（零 API 请求），保住 deploy-spec §3.2 的 EXPIRED / CAPPED 状态转移。
	if !cert.HasEnabledBinding() {
		if !cert.Metadata.CertExpiresAt.IsZero() {
			if cert.IsExpired() {
				s.markExpired(&cert)
				return nil, false
			}
			if phase := cappedPhaseFor(&cert, &cfg.Schedule); phase != "" {
				s.markCapped(&cert, phase)
				return nil, false
			}
		}
		s.markNoBindingBlocked(&cert)
		return nil, false
	}
	if !cert.Metadata.NoBindingBlockedAt.IsZero() {
		s.clearNoBindingBlocked(&cert)
	}

	// 无进展停更闸门（deploy-spec §3.2）。位置有硬性要求：
	//   - 必须在到期时间回填**之前**——「到期时间未知 + 查询持续失败」正是本闸门要管的
	//     主场景，若排在回填之后，那条路径每轮都在 refreshExpiryFromAPI 里 return，
	//     永远走不到这里；
	//   - 必须在过期判定**之后**——两者同时成立时以 EXPIRED 为准（更准确，spec §3.2）。
	//     IsExpired 对零值到期时间返回 false，故到期未知的证书仍能落到本闸门。
	// 纯本地判定，零 API 请求。
	if cert.IsExpired() {
		s.markExpired(&cert)
		return nil, madeAPICall
	}
	if s.stalledTooLong(&cert) {
		s.markStalled(&cert)
		return nil, madeAPICall
	}

	// 轮内 token 黑名单（deploy-spec §2.2「整批共通」组）：本轮已确认该 (url, token) 被
	// 服务端拒绝，后续调用必然同样失败。位置在本地闸门之后、首个 API 请求之前——过期与
	// 停更这类零请求的状态转移照常判定，只省掉注定失败的网络往返。
	// madeAPICall 保持 false：本轮没发请求，不该计入无进展结算，也不占证书间延迟。
	if blk, blocked := s.authGate.blockedBy(api); blocked {
		s.authGate.markSkipped()
		s.log.Debug("证书 %s 跳过本轮：该 Token 已被服务端拒绝（%s）", cert.CertName, blk.desc())
		return nil, madeAPICall
	}

	// 本轮进展基线：出口据前后快照结算无进展计时（settleNoProgress）
	progressBefore := snapshotProgress(&cert)
	defer func() { s.settleNoProgress(&cert, progressBefore, madeAPICall) }()

	// 到期时间未知（部署成功但元数据保存失败、带外换证等）：
	// 语义为"未知需处理"，先查询 API 回填元数据再按正常逻辑判定，避免"永不续签 + 告警盲区"双盲
	if cert.Metadata.CertExpiresAt.IsZero() {
		madeAPICall = true
		if !s.refreshExpiryFromAPI(ctx, &cert, api) {
			return nil, madeAPICall
		}
	}

	// 已过期：静默终止并转 EXPIRED，仅留本地日志与人工入口（不发回调）
	if cert.IsExpired() {
		s.markExpired(&cert)
		return nil, madeAPICall
	}

	// 安全余量只阻止建立新尝试；已有 processing/active 或 CSR metadata 的流程
	// 必须继续 query-first 查询、验证文件放置和部署收尾。
	entryState := normalizeIssueState(cert.Metadata.LastIssueState)
	hasInFlightIssue := hasLocalCSRIntent(&cert) ||
		entryState == config.IssueStateProcessing ||
		entryState == config.IssueStateActive
	if time.Until(cert.Metadata.CertExpiresAt) < AutoActionSafetyMargin && !hasInFlightIssue {
		s.log.Warn("证书 %s 剩余有效期不足安全余量（%s），本轮不启动新动作", cert.CertName, AutoActionSafetyMargin)
		return nil, madeAPICall
	}

	// 计数触顶：签发与部署分别判断，静默进入 CAPPED（不发回调）
	mode := cert.GetRenewMode(&cfg.Schedule)
	if phase := cappedPhaseFor(&cert, &cfg.Schedule); phase != "" {
		s.markCapped(&cert, phase)
		return nil, madeAPICall
	}

	// 重试失败的绑定（证书有效但部分绑定上次部署失败）
	if !cert.NeedsRenewal(&cfg.Schedule) && len(cert.Metadata.FailedBindings) > 0 && !hasInFlightIssue {
		if *processedCount >= MaxRenewBatch {
			return nil, madeAPICall
		}
		*processedCount++
		madeAPICall = true
		s.log.Info("证书 %s 重试 %d 个失败绑定...", cert.CertName, len(cert.Metadata.FailedBindings))
		result = s.retryFailedBindings(ctx, &cert, api)
		// nil 表示本轮无可上报的结果（幽灵条目已清理、或触顶静默停车）
		if result == nil {
			return nil, madeAPICall
		}
		// 部署结果回调（pending 不发）
		if result.Status == "success" || result.Status == "failure" {
			s.sendRenewCallback(ctx, &cert, result)
		}
		return result, madeAPICall
	}

	// 检查是否需要续期
	if !cert.NeedsRenewal(&cfg.Schedule) && !hasInFlightIssue {
		s.log.Debug("证书 %s 有效期充足，跳过", cert.CertName)
		return nil, madeAPICall
	}

	if *processedCount >= MaxRenewBatch {
		return nil, madeAPICall
	}
	*processedCount++

	// 将发起 API 请求：提前置位，panic 恢复路径也保留证书间延迟语义
	madeAPICall = true

	s.log.Info("证书 %s 需要续期，开始处理...", cert.CertName)

	result = &RenewResult{CertName: cert.CertName, Mode: mode}

	var (
		certData   *fetcher.CertData
		privateKey string
		err        error
	)

	if mode == config.RenewModeLocal {
		certData, privateKey, err = s.prepareLocalRenew(ctx, &cert, api)
	} else {
		certData, privateKey, err = s.preparePullRenew(ctx, &cert, api)
	}

	if err != nil {
		// 签发阶段失败：只记本地日志与本地计数，不上报回调（spec 1.2/2.8：客户端只上报部署结果）
		result.Status = "failure"
		result.Error = err
		s.log.Warn("证书 %s 续签失败（签发阶段，不上报）: %v", cert.CertName, err)
		return result, madeAPICall
	}

	if certData == nil {
		result.Status = "pending"
		return result, madeAPICall
	}

	// 部署阶段：崩溃安全地递增部署计数、部署、落盘结果后统一回调
	s.runDeployAttempt(ctx, &cert, certData, privateKey, result)
	return result, madeAPICall
}

// runDeployAttempt 执行一次部署尝试（deploy-spec §5.1）。
// 计数纪律：新部署意图在部署前原子落盘（DeployStartedAt 置位 + DeployAttemptCount 递增）；
// 崩溃重启复验时据 DeployStartedAt 复位重放同一意图、不再递增（不盲增）。
// 回调纪律：底层部署函数不发回调，仅由本编排层在结果原子落盘后统一上报（成功/明确失败各尽力一次）。
func (s *Service) runDeployAttempt(ctx context.Context, cert *config.CertConfig, certData *fetcher.CertData, privateKey string, result *RenewResult) {
	// 环境闸门先行：必须在递增部署计数之前。坏配置下 reload 必然失败，此时写入证书
	// 既不生效又要触发回滚；且阻断不该占用部署尝试配额（修好即自动恢复，无需人工解除
	// CAPPED）。闸门内部已按「原因变化 + 次数封顶」上报过 failure，此处只需按失败收敛。
	if blockReason := s.checkDeployEnvironment(ctx, cert, cert.GetAPI(s.log)); blockReason != "" {
		result.Status = "failure"
		result.Error = stderrors.New(blockReason)
		return
	}

	incremented := false
	if cert.Metadata.DeployStartedAt.IsZero() {
		// 新部署意图：部署前原子落盘"已开始"标记与计数递增（崩溃可复位重放）
		previousCount := cert.Metadata.DeployAttemptCount
		cert.Metadata.DeployAttemptCount++
		cert.Metadata.DeployStartedAt = time.Now()
		incremented = true
		if err := s.cfgManager.UpdateCert(cert); err != nil {
			cert.Metadata.DeployAttemptCount = previousCount
			cert.Metadata.DeployStartedAt = time.Time{}
			result.Status = "failure"
			result.Error = fmt.Errorf("持久化部署意图失败，已停止部署: %w", err)
			s.log.Error("证书 %s %v", cert.CertName, result.Error)
			return
		}
	} else {
		// 复验后重放同一尝试，不再递增计数
		s.log.Info("证书 %s 检测到未落盘结果的部署意图，复验后重放同一尝试（不增计数）", cert.CertName)
	}

	persistedIntentMetadata := cloneCertMetadata(cert.Metadata)
	persistedIntentDomains := append([]string(nil), cert.Domains...)

	// 部署前记下旧序列号：deployCertToBindings 成功时会覆盖它，
	// 事后无从判断服务端是否真的换了证书
	prevSerial := cert.Metadata.CertSerial

	deployCount, failedBindings, deployErr := s.deployCertToBindings(ctx, cert, certData, privateKey)
	result.DeployCount = deployCount

	// 零启用绑定（纵深防御命中）：本轮没有发生任何部署尝试 —— 回滚计数、不上报回调。
	// 回滚必须是条件式的：崩溃重放分支本轮未递增，无条件 -- 会把计数减到上一轮之下，削弱触顶保护。
	if stderrors.Is(deployErr, ErrNoEnabledBinding) {
		if incremented {
			cert.Metadata.DeployAttemptCount--
		}
		cert.Metadata.DeployStartedAt = time.Time{}
		if err := s.cfgManager.UpdateCert(cert); err != nil {
			s.log.Warn("回滚证书 %s 部署意图失败: %v", cert.CertName, err)
		}
		result.Status = "failure"
		result.Error = deployErr
		s.log.Error("证书 %s 没有启用的站点绑定，跳过部署（不计数、不上报回调）", cert.CertName)
		return
	}

	// 结果落盘：清除"已开始"标记（本次尝试已产生明确结果）；
	// deployCertToBindings 成功时已清零全部计数与状态，失败时保留计数递增值。
	cert.Metadata.DeployStartedAt = time.Time{}
	if deployErr != nil {
		result.Status = "failure"
		if cert.Metadata.DeployAttemptCount >= MaxDeployAttemptCount {
			// 第 10 次（最后一次）部署失败：message 前置标注已达重试上限（自由文本，零协议变化）
			result.Error = fmt.Errorf("已达重试上限（已停止自动重试，需人工介入）: %w", deployErr)
		} else {
			result.Error = deployErr
		}
	} else {
		result.Status = "success"
		// 全部站点成功时才校验证书是否真的更替：有站点失败的轮次压根没写 cert_serial，
		// 本轮相同属预期的补部署（次日重试用的必然是同一张证书）
		if len(failedBindings) == 0 {
			if unchanged := s.trackCertUnchanged(cert, prevSerial); unchanged != "" {
				// 改判为失败并上报：服务端看到的一直是 success，不改判就永远不知道
				// 证书其实没更新，直到真的过期
				result.Status = "failure"
				result.Error = stderrors.New(unchanged)
				s.log.Error("证书 %s %s，已改判为失败并上报，需人工核对服务端签发状态", cert.CertName, unchanged)
			}
		}
	}
	if err := s.cfgManager.UpdateCert(cert); err != nil {
		// 配置盘上仍是 DeployStartedAt 已置位的意图；恢复内存到同一状态，
		// 并在 local pending 已被成功部署路径转正时重建 pending，保证下轮可核验并重放。
		cert.Metadata = persistedIntentMetadata
		cert.Domains = persistedIntentDomains
		var restoreErr error
		if hasLocalCSRIntent(cert) {
			restoreErr = savePendingKey(s.cfgManager.GetWorkDir(), cert.CertName, privateKey)
		}
		result.Status = "failure"
		result.Error = fmt.Errorf("部署结果落盘失败，未发送回调: %w", stderrors.Join(err, restoreErr))
		s.log.Error("证书 %s %v", cert.CertName, result.Error)
		return
	}

	// 编排层统一发送部署结果回调（成功/明确失败各尽力一次）
	s.sendRenewCallback(ctx, cert, result)
}

// trackCertUnchanged 全部站点部署成功后比对序列号，判断服务端是否真的换了证书。
// 返回非空字符串表示已连续多轮未更替，调用方据此把本轮结果改判为失败。
//
// 为什么需要这道检查：部署"成功"会清零全部计数并更新到期时间为同一个值，于是
// 三重边界同时失效——计数每轮清零永不触顶、"部署发生"算进展使无进展计时也清零、
// 到期闸门要等真过期。每轮还会真实改写证书文件并 reload Web 服务，服务端收到的
// 却是一切正常的 success，直到证书真的过期。
//
// 只在编排层（自动续签）判定，手动部署不参与：用户点两次部署、粘贴私钥后重新
// 部署、加绑站点后部署，都会用同一张证书，那是正常操作而非服务端故障。
//
// 判据要求两端序列号都非空——解析失败时序列号为空串，空串相等会让每次部署都误报。
// 到期时间未前移只作序列号缺失时的降级判据、不与序列号并列：CA 重签常保留原订单
// 剩余有效期，"新序列号 + 相同 notAfter"是完全正常的结果，而 local 模式走的恰恰
// 是重签路径。
func (s *Service) trackCertUnchanged(cert *config.CertConfig, prevSerial string) string {
	newSerial := cert.Metadata.CertSerial
	if prevSerial == "" || newSerial == "" || prevSerial != newSerial {
		if cert.Metadata.UnchangedCertRounds != 0 {
			cert.Metadata.UnchangedCertRounds = 0
		}
		return ""
	}

	cert.Metadata.UnchangedCertRounds++
	rounds := cert.Metadata.UnchangedCertRounds
	s.log.Warn("证书 %s 服务端返回的证书未更替（第 %d 轮，序列号 %s）", cert.CertName, rounds, newSerial)
	if rounds < config.CertUnchangedRounds {
		return ""
	}
	return fmt.Sprintf("服务端连续 %d 轮返回同一张证书（序列号 %s 未变），证书未实际更新", rounds, newSerial)
}

// persistTerminalState 先落盘终止门禁，再幂等清理在途产物。
// 清理或最终 metadata 落盘失败时，下一轮终止态入口会再次调用本函数继续收敛。
func (s *Service) persistTerminalState(cert *config.CertConfig, state, phase string) {
	pendingPath := getPendingKeyPath(s.cfgManager.GetWorkDir(), cert.CertName)
	if cert.Metadata.LastIssueState == state &&
		cert.Metadata.CappedPhase == phase &&
		cert.Metadata.DeployStartedAt.IsZero() &&
		cert.Metadata.CSRSubmittedAt.IsZero() &&
		cert.Metadata.LastCSRHash == "" &&
		cert.Metadata.NoProgressSince.IsZero() &&
		len(cert.Metadata.ValidationFiles) == 0 {
		if _, err := os.Lstat(pendingPath); stderrors.Is(err, os.ErrNotExist) {
			return
		}
	}

	before := cloneCertMetadata(cert.Metadata)
	cert.Metadata.LastIssueState = state
	cert.Metadata.CappedPhase = phase
	cert.Metadata.DeployStartedAt = time.Time{}
	// 兜底迁移：进入终止态后不会再有人重试 FailedBindings，不迁走就等于把这批站点
	// 静默丢弃——它们仍持有旧证书，会一路走到真实过期。只靠 markCapped 覆盖不到，
	// 先过期与先判签发阶段两条路径都绕过它。
	if len(cert.Metadata.FailedBindings) > 0 {
		migrateToStale(cert, cert.Metadata.FailedBindings, cert.Metadata.FailedBindingsAt)
		cert.Metadata.FailedBindings = nil
		cert.Metadata.FailedBindingsAt = time.Time{}
	}
	if err := s.cfgManager.UpdateCert(cert); err != nil {
		cert.Metadata = before
		s.log.Warn("持久化证书 %s 状态 %s 失败: %v", cert.CertName, state, err)
		return
	}

	if err := cleanupPendingKey(s.cfgManager.GetWorkDir(), cert.CertName); err != nil {
		s.log.Error("证书 %s 已进入 %s，但清理 pending 私钥失败，将在下轮重试: %v", cert.CertName, state, err)
		return
	}
	s.cleanupCertValidationFiles(cert)
	if len(cert.Metadata.ValidationFiles) > 0 {
		s.log.Error("证书 %s 已进入 %s，但仍有验证文件未清理，将在下轮重试", cert.CertName, state)
		return
	}

	cert.Metadata.CSRSubmittedAt = time.Time{}
	cert.Metadata.LastCSRHash = ""
	cert.Metadata.NoProgressSince = time.Time{}
	if err := s.cfgManager.UpdateCert(cert); err != nil {
		s.log.Warn("证书 %s 在途产物已清理，但终止态 metadata 收尾失败，将在下轮重试: %v", cert.CertName, err)
	}
}

// markNoBindingBlocked 落零绑定阻断标记。
// 落盘走 UpdateCertIf 原子复检：GetCert 复读是 mtime 门控的缓存读，而写入在文件锁内强制重读盘上状态，
// 两者可能是不同快照——人工在窗口内补齐绑定时，会被整条覆盖回零绑定。
// 仅在标记从无到有时打 Error（含在途签发提示），之后每轮 Debug。
func (s *Service) markNoBindingBlocked(cert *config.CertConfig) {
	if !cert.Metadata.NoBindingBlockedAt.IsZero() {
		s.log.Debug("证书 %s 无启用绑定，保持阻断", cert.CertName)
		return
	}
	s.log.Error("证书 %s 已启用但没有任何启用的站点绑定，已阻断自动续签与部署（不发起请求、不上报回调），请重新 setup 或恢复绑定", cert.CertName)
	if state := normalizeIssueState(cert.Metadata.LastIssueState); state == config.IssueStateProcessing || state == config.IssueStateActive {
		s.log.Error("证书 %s 存在在途订单（状态 %s）与可能未转正的 pending 私钥，阻断期间不会自行终止，需人工处理", cert.CertName, cert.Metadata.LastIssueState)
	}

	now := time.Now()
	err := s.cfgManager.UpdateCertIf(cert.CertName,
		func(c *config.CertConfig) bool { return !c.HasEnabledBinding() },
		func(c *config.CertConfig) { c.Metadata.NoBindingBlockedAt = now })
	switch {
	case err == nil:
		cert.Metadata.NoBindingBlockedAt = now
	case stderrors.Is(err, config.ErrCertCondNotMet):
		s.log.Warn("证书 %s 落阻断标记时复检发现绑定已恢复，跳过写入", cert.CertName)
	default:
		s.log.Warn("持久化证书 %s 阻断标记失败: %v", cert.CertName, err)
	}
}

// clearNoBindingBlocked 绑定恢复后解除阻断（计数不复位，避免旁路停机保护）
func (s *Service) clearNoBindingBlocked(cert *config.CertConfig) {
	err := s.cfgManager.UpdateCertIf(cert.CertName,
		func(c *config.CertConfig) bool { return c.HasEnabledBinding() },
		func(c *config.CertConfig) { c.Metadata.NoBindingBlockedAt = time.Time{} })
	if err != nil && !stderrors.Is(err, config.ErrCertCondNotMet) {
		s.log.Warn("清除证书 %s 阻断标记失败: %v", cert.CertName, err)
		return
	}
	cert.Metadata.NoBindingBlockedAt = time.Time{}
	s.log.Info("证书 %s 已恢复启用绑定，解除阻断（计数不复位）", cert.CertName)
}

// retainableStaleNames 过滤可迁入 StaleBindings 的名字：只保留仍在 cert.Bindings 中的绑定。
// 已被改绑到其它证书的名字不能迁入——本证书永远不会再部署该站点，
// ClearStaleBinding 的调用点都以"本次部署成功的 ServerName"为入参，永远不会包含它，
// 告警会变成永远关不掉的每日 Error。
func retainableStaleNames(cert *config.CertConfig, names []string) []string {
	if len(names) == 0 {
		return nil
	}
	exists := make(map[string]bool, len(cert.Bindings))
	for i := range cert.Bindings {
		exists[cert.Bindings[i].ServerName] = true
	}
	var kept []string
	for _, name := range names {
		if exists[name] {
			kept = append(kept, name)
		}
	}
	return kept
}

// migrateToStale 把绑定迁入 StaleBindings（去重）；StaleSince 仅在从空变非空时设置
func migrateToStale(cert *config.CertConfig, names []string, since time.Time) {
	kept := retainableStaleNames(cert, names)
	if len(kept) == 0 {
		return
	}
	seen := make(map[string]bool, len(cert.Metadata.StaleBindings))
	for _, name := range cert.Metadata.StaleBindings {
		seen[name] = true
	}
	wasEmpty := len(cert.Metadata.StaleBindings) == 0
	for _, name := range kept {
		if seen[name] {
			continue
		}
		seen[name] = true
		cert.Metadata.StaleBindings = append(cert.Metadata.StaleBindings, name)
	}
	if wasEmpty && len(cert.Metadata.StaleBindings) > 0 {
		if since.IsZero() {
			since = time.Now()
		}
		cert.Metadata.StaleSince = since
	}
}

// ClearStaleBinding 部署成功后清除该绑定的 stale 标记；列表清空时一并清除 StaleSince。
// 供续签、失败绑定重试、CLI 部署与 setup 共用。
func ClearStaleBinding(cert *config.CertConfig, serverName string) {
	if len(cert.Metadata.StaleBindings) == 0 {
		return
	}
	kept := cert.Metadata.StaleBindings[:0]
	for _, name := range cert.Metadata.StaleBindings {
		if name != serverName {
			kept = append(kept, name)
		}
	}
	if len(kept) == 0 {
		cert.Metadata.StaleBindings = nil
		cert.Metadata.StaleSince = time.Time{}
		return
	}
	cert.Metadata.StaleBindings = kept
}

// markCapped 触顶进入 CAPPED 静默并记录触顶阶段
func (s *Service) markCapped(cert *config.CertConfig, phase string) {
	if cert.Metadata.LastIssueState != config.IssueStateCapped || cert.Metadata.CappedPhase != phase {
		s.log.Error("证书 %s 已达%s尝试上限 (%d)，进入 CAPPED 静默，等待人工处理", cert.CertName, cappedPhaseLabel(phase), config.AttemptCap)
	}
	s.persistTerminalState(cert, config.IssueStateCapped, phase)
}

// markExpired 过期静默进入 EXPIRED
func (s *Service) markExpired(cert *config.CertConfig) {
	if cert.Metadata.LastIssueState != config.IssueStateExpired {
		s.log.Error("证书 %s 已过期，静默终止自动续签，仅保留本地日志与人工入口", cert.CertName)
	}
	s.persistTerminalState(cert, config.IssueStateExpired, "")
}

// cappedPhaseLabel 触顶阶段的中文标签
func cappedPhaseLabel(phase string) string {
	switch phase {
	case config.CappedPhaseIssue:
		return "签发"
	case config.CappedPhaseDeploy:
		return "部署"
	case config.CappedPhaseLegacy:
		return "旧计数"
	default:
		return phase
	}
}

// resetIssueStateForResubmit 本轮 local 签发流程失效（pending 私钥丢失等）时重置签发状态，
// 使下一轮续签检查走重新提交 CSR 路径（提交时递增 issue_retry_count，受 10 次上限约束，
// 触顶后停止并上报，符合规范 3.5 生命周期），避免 processing 状态永久卡死
func (s *Service) resetIssueStateForResubmit(cert *config.CertConfig, cause error) error {
	cert.Metadata.LastIssueState = ""
	if err := s.cfgManager.UpdateCert(cert); err != nil {
		s.log.Warn("重置证书 %s 签发状态失败: %v", cert.CertName, err)
	}
	return fmt.Errorf("%w（已重置签发状态，下轮将重新提交 CSR）", cause)
}

// hasLocalCSRIntent 判断本地是否持久化过一笔 CSR 提交意图。
// 历史配置可能只有 LastIssueState、没有 CSR 元数据；这类旧数据继续走兼容恢复，
// 新协议产生的提交则必须同时用服务端 CSR 验证归属。
func hasLocalCSRIntent(cert *config.CertConfig) bool {
	return !cert.Metadata.CSRSubmittedAt.IsZero() || cert.Metadata.LastCSRHash != ""
}

func clearLocalCSRIntent(cert *config.CertConfig, nextState string) {
	cert.Metadata.CSRSubmittedAt = time.Time{}
	cert.Metadata.LastCSRHash = ""
	cert.Metadata.LastIssueState = nextState
}

// discardLocalCSRIntent 丢弃已确认不属于当前服务端订单的本地提交意图。
// 签发尝试计数刻意保留，防止连续拒绝或错配绕过总尝试上限。
func (s *Service) discardLocalCSRIntent(cert *config.CertConfig, nextState string) error {
	snapshot := snapshotLocalCSRIntent(cert)
	clearLocalCSRIntent(cert, nextState)
	if err := s.cfgManager.UpdateCert(cert); err != nil {
		restoreLocalCSRIntent(cert, snapshot)
		return fmt.Errorf("保存 CSR 归一状态失败: %w", err)
	}
	if err := cleanupPendingKey(s.cfgManager.GetWorkDir(), cert.CertName); err != nil {
		// key 已删除、只剩目录清理失败时，提交意图已经安全清除，无需恢复。
		if _, readErr := readPendingKey(s.cfgManager.GetWorkDir(), cert.CertName); stderrors.Is(readErr, os.ErrNotExist) {
			s.log.Warn("证书 %s pending 私钥已删除，但目录清理失败: %v", cert.CertName, err)
			return nil
		}
		// 私钥仍可能存在或无法确认时恢复 metadata，让下一轮重新进入 query-first
		// 并重试清理，避免留下没有归属标记的长期私钥。
		restoreLocalCSRIntent(cert, snapshot)
		if restoreErr := s.cfgManager.UpdateCert(cert); restoreErr != nil {
			return fmt.Errorf("清理待确认私钥失败且恢复 CSR metadata 失败: %w",
				stderrors.Join(err, restoreErr))
		}
		return fmt.Errorf("清理待确认私钥失败: %w", err)
	}
	return nil
}

// matchingActiveKey 仅从服务端返回私钥和线上正式私钥中寻找 active 证书的配对私钥。
// 旧 pending 已被服务端 CSR 证明不属于当前签发结果，不能再参与候选。
func (s *Service) matchingActiveKey(ctx context.Context, cert *config.CertConfig, certData *fetcher.CertData, keyPath string) (string, bool) {
	if certData.PrivateKey != "" {
		if err := validator.New("").ValidateCertKeyPair(certData.Cert, certData.PrivateKey); err == nil {
			return certData.PrivateKey, true
		}
	}
	if keyPath == "" {
		return "", false
	}
	keyData, err := ReadBindingPrivateKey(ctx, pickKeyBinding(cert))
	if err != nil {
		return "", false
	}
	privateKey := consumePrivateKey(keyData)
	if err := validator.New("").ValidateCertKeyPair(certData.Cert, privateKey); err != nil {
		return "", false
	}
	return privateKey, true
}

type localCSRIntentSnapshot struct {
	issueRetryCount int
	submittedAt     time.Time
	hash            string
	state           string
}

func snapshotLocalCSRIntent(cert *config.CertConfig) localCSRIntentSnapshot {
	return localCSRIntentSnapshot{
		issueRetryCount: cert.Metadata.IssueRetryCount,
		submittedAt:     cert.Metadata.CSRSubmittedAt,
		hash:            cert.Metadata.LastCSRHash,
		state:           cert.Metadata.LastIssueState,
	}
}

func restoreLocalCSRIntent(cert *config.CertConfig, snapshot localCSRIntentSnapshot) {
	cert.Metadata.IssueRetryCount = snapshot.issueRetryCount
	cert.Metadata.CSRSubmittedAt = snapshot.submittedAt
	cert.Metadata.LastCSRHash = snapshot.hash
	cert.Metadata.LastIssueState = snapshot.state
}

func cloneCertMetadata(metadata config.CertMetadata) config.CertMetadata {
	cloned := metadata
	cloned.FailedBindings = append([]string(nil), metadata.FailedBindings...)
	cloned.StaleBindings = append([]string(nil), metadata.StaleBindings...)
	cloned.ValidationFiles = append([]string(nil), metadata.ValidationFiles...)
	return cloned
}

// refreshExpiryFromAPI 到期时间未知时查询 API 回填证书元数据，返回是否回填成功
// 查询失败或服务端无证书内容时记录告警并返回 false（下轮续签检查会再次尝试）
func (s *Service) refreshExpiryFromAPI(ctx context.Context, cert *config.CertConfig, api config.APIConfig) bool {
	certData, renewBeforeDays, err := s.queryOrder(ctx, api, cert.OrderID)
	if err != nil {
		// 服务端明确拒绝（订单不存在、token 失效、IP 不在白名单等）与传输失败区别对待：
		// 前者每轮重试都注定同样失败，需要人工核对配置，按 Error 记而非 Warn。
		// 本函数仍返回 false 让本轮跳过——真正的停止边界由无进展时限提供（spec §3.2）。
		if errors.IsBusinessError(err) {
			s.log.Error("证书 %s 到期时间未知且服务端拒绝查询（需人工核对配置，重试无用）: %v", cert.CertName, err)
			return false
		}
		s.log.Warn("证书 %s 到期时间未知且查询失败，跳过本轮: %v", cert.CertName, err)
		return false
	}
	s.tryUpdateRenewBeforeDays(renewBeforeDays)
	s.syncOrderID(cert, certData)
	if certData.Cert == "" {
		s.log.Warn("证书 %s 到期时间未知且服务端未返回证书内容 (status=%s)，跳过本轮", cert.CertName, certData.Status)
		return false
	}
	parsed, err := validator.New("").ValidateCert(certData.Cert)
	if err != nil || parsed == nil {
		s.log.Warn("证书 %s 回填到期时间失败（证书解析错误）: %v", cert.CertName, err)
		return false
	}
	cert.Metadata.CertExpiresAt = parsed.NotAfter
	cert.Metadata.CertSerial = fmt.Sprintf("%X", parsed.SerialNumber)
	if err := s.cfgManager.UpdateCert(cert); err != nil {
		s.log.Warn("证书 %s 回填元数据保存失败: %v", cert.CertName, err)
	}
	s.log.Info("证书 %s 到期时间已从服务端回填: %s", cert.CertName, parsed.NotAfter.Format("2006-01-02"))
	return true
}

// splitRetryTargets 把 FailedBindings 分成可重试集与幽灵集。
// 幽灵有两类：已不在 cert.Bindings（站点被改绑到其它证书）、仍在但被禁用（运维维护中）。
func splitRetryTargets(cert *config.CertConfig) (retryable, ghosts []string) {
	enabled := make(map[string]bool, len(cert.Bindings))
	for i := range cert.Bindings {
		if cert.Bindings[i].Enabled {
			enabled[cert.Bindings[i].ServerName] = true
		}
	}
	for _, name := range cert.Metadata.FailedBindings {
		if enabled[name] {
			retryable = append(retryable, name)
		} else {
			ghosts = append(ghosts, name)
		}
	}
	return retryable, ghosts
}

// annotateCapReached 给触顶那一次失败的原因前置标注，供服务端识别"已停止自动重试"。
// 措辞与 runDeployAttempt 的证书级标注区分，避免服务端在同一张证书上看到两个配额发出同样文本。
func annotateCapReached(err error) error {
	return fmt.Errorf("绑定重试已达上限（已停止自动重试，需人工介入）: %w", err)
}

// rollbackRetryCount 回滚本轮的重试计数（用于"未发生部署且不应计入配额"的出口）
func (s *Service) rollbackRetryCount(cert *config.CertConfig) {
	if cert.Metadata.RetryAttemptCount > 0 {
		cert.Metadata.RetryAttemptCount--
	}
	if err := s.cfgManager.UpdateCert(cert); err != nil {
		s.log.Warn("回滚证书 %s 重试计数失败: %v", cert.CertName, err)
	}
}

// parkExhaustedRetries 重试触顶停车：迁入 StaleBindings、清空失败列表、复位重试计数。
// **不设置 LastIssueState=CAPPED**——绑定级重试是 deploy-spec 未建模的平台扩展，
// 让它把整张证书打进 CAPPED 会连健康站点一起停掉续签直至过期。
// report 为 true 时返回带标注的 failure 结果由调用方上报（仅"确实发生了部署且仍失败"的出口）；
// 其余出口（查询失败、私钥不可读）未发生部署，按 deploy-spec §2.8:297「触顶路径不发送任何回调」静默。
func (s *Service) parkExhaustedRetries(cert *config.CertConfig, result *RenewResult, cause error, report bool) *RenewResult {
	parked := cert.Metadata.FailedBindings
	migrateToStale(cert, parked, cert.Metadata.FailedBindingsAt)
	cert.Metadata.FailedBindings = nil
	cert.Metadata.FailedBindingsAt = time.Time{}
	cert.Metadata.RetryAttemptCount = 0
	cert.Metadata.DeployStartedAt = time.Time{}
	if err := s.cfgManager.UpdateCert(cert); err != nil {
		s.log.Warn("持久化证书 %s 重试停车状态失败: %v", cert.CertName, err)
	}
	s.log.Error("证书 %s 的失败绑定 %v 重试已达上限 (%d)，停止重试并转入长期未部署告警，等待人工处理: %v",
		cert.CertName, parked, MaxRetryAttemptCount, cause)
	if !report {
		return nil
	}
	result.Status = "failure"
	result.Error = annotateCapReached(cause)
	return result
}

// retryFailedBindings 重试上次部署失败的绑定。
// 返回 nil 表示本轮无可上报的结果（幽灵条目已清理、或触顶静默停车），调用方不得解引用。
func (s *Service) retryFailedBindings(ctx context.Context, cert *config.CertConfig, api config.APIConfig) *RenewResult {
	result := &RenewResult{
		CertName: cert.CertName,
		Mode:     "retry",
	}

	// 前置预检（不发任何请求，故排在入口计数之前，纯记账清理不占配额）：
	// 失败集与启用绑定的交集为空时一个绑定都不会被重试，绝不能报 success。
	retryable, ghosts := splitRetryTargets(cert)
	if len(ghosts) > 0 {
		s.log.Warn("证书 %s 的失败绑定 %v 已不可重试（绑定被禁用或已改绑其它证书）", cert.CertName, ghosts)
	}
	if len(retryable) == 0 {
		// 仍在 Bindings 但被禁用的转入 stale 等待恢复；已改绑他证的由 migrateToStale 过滤丢弃
		migrateToStale(cert, cert.Metadata.FailedBindings, cert.Metadata.FailedBindingsAt)
		cert.Metadata.FailedBindings = nil
		cert.Metadata.FailedBindingsAt = time.Time{}
		cert.Metadata.RetryAttemptCount = 0
		cert.Metadata.DeployStartedAt = time.Time{}
		if err := s.cfgManager.UpdateCert(cert); err != nil {
			s.log.Warn("更新证书元数据失败: %v", err)
		}
		return nil
	}

	// 入口计数：独立配额，全程不触碰证书级 DeployAttemptCount / DeployStartedAt。
	// 计数点必须在 QueryOrder 之前——否则 API 持续不可达时永远走不到计数点，
	// 会产生无上限的每日 failure 回调流。
	cert.Metadata.RetryAttemptCount++
	exhausted := cert.Metadata.RetryAttemptCount >= MaxRetryAttemptCount
	if err := s.cfgManager.UpdateCert(cert); err != nil {
		s.log.Warn("持久化证书 %s 重试计数失败: %v", cert.CertName, err)
	}

	certData, renewBeforeDays, err := s.queryOrder(ctx, api, cert.OrderID)
	if err != nil {
		// 整批共通失败（限流 / token 或账号被禁 / IP 未放行）由中间件拦下、与订单无关，
		// 与「证书仍在签发中」同理不占重试配额：回滚本轮递增、不停车。否则 token 持续
		// 失效满 10 轮会清空 FailedBindings，token 换发后这些绑定反而不再重试。
		if fetcher.IsAuthBlockErrorCode(errors.ErrorCodeOf(err)) {
			s.rollbackRetryCount(cert)
			s.log.Error("重试失败绑定: 该 Token 被服务端拒绝，本轮跳过（不占重试配额）: %v", err)
			result.Status = "failure"
			result.Error = err
			return result
		}
		if errors.IsBusinessError(err) {
			s.log.Error("重试失败绑定: 服务端拒绝查询证书 %s（需人工核对配置，重试无用）: %v", cert.CertName, err)
		} else {
			s.log.Warn("重试失败绑定: 查询证书 %s 失败: %v", cert.CertName, err)
		}
		if exhausted {
			return s.parkExhaustedRetries(cert, result, err, false)
		}
		result.Status = "failure"
		result.Error = err
		return result
	}
	s.tryUpdateRenewBeforeDays(renewBeforeDays)
	s.syncOrderID(cert, certData)
	if certData.Status != config.OrderStatusActive || certData.Cert == "" || certData.IntermediateCert == "" {
		// 证书仍在签发中：上游在途状态，既非部署尝试也非部署结果。
		// 不计入配额（回滚本轮递增）、不停车、不回调，等服务端签完自愈——
		// 否则合法 processing 满 10 轮会清空 FailedBindings，证书真正签发后反而不再重试。
		s.rollbackRetryCount(cert)
		s.log.Warn("重试失败绑定: 证书 %s 未就绪 (status=%s)", cert.CertName, certData.Status)
		result.Status = "pending"
		return result
	}

	// pending 感知：续签部署全失败后 pending 私钥尚未转正，重试须能读到它，
	// 否则旧私钥与新证书配对必败，站点走向真实过期
	privateKey, err := GetPrivateKeyForCert(ctx, s.cfgManager.GetWorkDir(), cert, certData.Cert, certData.PrivateKey, s.log)
	if err != nil {
		s.log.Warn("重试失败绑定: 获取私钥失败: %v", err)
		if exhausted {
			return s.parkExhaustedRetries(cert, result, err, false)
		}
		result.Status = "failure"
		result.Error = err
		return result
	}

	retrySet := make(map[string]bool, len(retryable))
	for _, name := range retryable {
		retrySet[name] = true
	}

	var stillFailed []string
	for j := range cert.Bindings {
		binding := cert.Bindings[j]
		if !retrySet[binding.ServerName] {
			continue
		}
		if err := s.deployToBinding(ctx, &binding, certData, privateKey); err != nil {
			s.log.Error("重试部署到 %s 失败: %v", binding.ServerName, err)
			stillFailed = append(stillFailed, binding.ServerName)
			continue
		}
		s.log.Info("重试部署到 %s 成功", binding.ServerName)
		ClearStaleBinding(cert, binding.ServerName)
		result.DeployCount++
	}

	cert.Metadata.FailedBindings = stillFailed
	// 清除证书级崩溃安全标记：残留标记会让之后一次真正的 runDeployAttempt 被当成
	// "重放同一意图"而不递增计数，削弱部署触顶保护。
	cert.Metadata.DeployStartedAt = time.Time{}
	// 重试部署成功后补转正 pending 私钥（若本次使用的正是 pending 私钥）
	if result.DeployCount > 0 {
		s.commitPendingKeyAfterDeploy(cert, privateKey)
	}

	switch {
	case len(stillFailed) == 0:
		cert.Metadata.LastDeployAt = time.Now()
		cert.Metadata.FailedBindingsAt = time.Time{}
		cert.Metadata.RetryAttemptCount = 0
		result.Status = "success"
	case exhausted:
		// 确实发生了部署且仍失败：这是明确的部署结果，带标注上报一次后停车
		return s.parkExhaustedRetries(cert, result, fmt.Errorf("%d 个绑定仍然失败", len(stillFailed)), true)
	default:
		result.Status = "failure"
		result.Error = fmt.Errorf("%d 个绑定仍然失败", len(stillFailed))
	}
	if err := s.cfgManager.UpdateCert(cert); err != nil {
		s.log.Warn("更新证书元数据失败: %v", err)
	}
	return result
}

// callbackMessageMaxLen 回调 message 字段最大长度（按 rune 计）。
// 服务端上限为 500，客户端取更严格的 256，超长整条会被服务端拒收。
const callbackMessageMaxLen = 256

// CallbackFallbackBudget 回调兜底预算：父 ctx 已取消或余量不足时使用。
// 取值不低于 deploy-spec §11 规定的单次 POST 超时（60s），留出一轮退避余量；
// CLI 路径（ctx 无 deadline）也用它显式限定，避免部署已成功却让命令再挂几分钟。
const CallbackFallbackBudget = 90 * time.Second

// CallbackMessage 导出版本，供 CLI 部署链复用同一套脱敏与截断规则
func CallbackMessage(err error) string { return callbackMessage(err) }

// callbackMessage 从失败错误生成回调 message：先脱敏（复用 logger 过滤规则）再按 rune 截断，
// 确保 Bearer token / 私钥块 / URL token 参数不会随失败原因泄漏进回调请求体。
func callbackMessage(err error) string {
	if err == nil {
		return ""
	}
	return truncateRunes(logger.Sanitize(err.Error()), callbackMessageMaxLen)
}

// truncateRunes 按 rune 截断字符串，不劈开多字节字符
func truncateRunes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= max {
		return s
	}
	return string(runes[:max])
}

// sendRenewCallback 向 API 发送续签结果回调
// 非关键路径，失败仅记录日志（传输层已含网络错误/5xx 的指数退避重试）
// 失败回调携带脱敏后的原因摘要（message，仅 failure），同时记本地 Error 日志（spec 2.8）
func (s *Service) sendRenewCallback(ctx context.Context, cert *config.CertConfig, result *RenewResult) {
	callbackReq := &fetcher.CallbackRequest{
		OrderID:    cert.OrderID,
		Status:     result.Status,
		DeployedAt: time.Now().Format(time.RFC3339),
	}
	if result.Status == "failure" {
		callbackReq.Message = callbackMessage(result.Error)
		s.log.Error("证书 %s 续签失败（已上报 failure 回调）: %s", cert.CertName, callbackReq.Message)
	}

	fillCertMetadata(callbackReq, cert)
	renewBeforeDays := s.sendCallback(ctx, cert.GetAPI(s.log), callbackReq)
	s.tryUpdateRenewBeforeDays(renewBeforeDays)
}

// getRenewMode 获取续签模式（带默认值）
func getRenewMode(schedule *config.ScheduleConfig) string {
	mode := schedule.RenewMode
	if mode == "" {
		return config.RenewModePull
	}
	return mode
}

// progressMark 判定「证书状态是否真的往前走了」的字段快照（deploy-spec §3.2）。
//
// 只取明确表示前进的字段，编排层比对前后快照即可覆盖全部路径——
// 无进展的出口散布在 pull / local / 回填 / 重试等十余处返回点，
// 逐个手写标记必然漏掉，而漏掉一个就等于那条路径永远没有边界。
//
// 刻意**不含** LastIssueState：resetIssueStateForResubmit 会把它清空以便下轮重新提交，
// 那是本轮流程失效后的回退、不是前进；计入会让「pending 私钥反复缺失」永远清零计时。
// 也不含 LastOrderStatus：终态之间互相变化（cancelled → failed）不是进展。
type progressMark struct {
	lastDeployAt   time.Time
	certExpiresAt  time.Time
	certSerial     string
	csrSubmittedAt time.Time
}

// snapshotProgress 取当前进展快照
func snapshotProgress(cert *config.CertConfig) progressMark {
	return progressMark{
		lastDeployAt:   cert.Metadata.LastDeployAt,
		certExpiresAt:  cert.Metadata.CertExpiresAt,
		certSerial:     cert.Metadata.CertSerial,
		csrSubmittedAt: cert.Metadata.CSRSubmittedAt,
	}
}

// settleNoProgress 依据本轮前后快照结算无进展计时。
// 仅在本轮确实发起过 API 请求时结算——静默跳过（有效期充足、触顶等）不该计入。
func (s *Service) settleNoProgress(cert *config.CertConfig, before progressMark, madeAPICall bool) {
	if !madeAPICall {
		return
	}
	if snapshotProgress(cert) != before {
		s.clearNoProgress(cert)
		return
	}
	s.markNoProgress(cert)
}

// markNoProgress 记录「本轮只查询、没有任何进展」的起点。
//
// 锚定首次、不滑动窗口：每轮都刷新时间戳等于永远达不到时限，那正是要修的问题。
// 进展的判据是证书状态真的往前走了（部署发生、CSR 被接受、订单回到可用、
// 到期时间成功回填），而不是"这一轮跑完没报错"。
func (s *Service) markNoProgress(cert *config.CertConfig) {
	if !cert.Metadata.NoProgressSince.IsZero() {
		return
	}
	cert.Metadata.NoProgressSince = time.Now()
	if err := s.cfgManager.UpdateCert(cert); err != nil {
		s.log.Warn("记录证书 %s 无进展起点失败: %v", cert.CertName, err)
	}
}

// clearNoProgress 有实际进展时清零停更计时
func (s *Service) clearNoProgress(cert *config.CertConfig) {
	if cert.Metadata.NoProgressSince.IsZero() {
		return
	}
	cert.Metadata.NoProgressSince = time.Time{}
	if err := s.cfgManager.UpdateCert(cert); err != nil {
		s.log.Warn("清除证书 %s 无进展计时失败: %v", cert.CertName, err)
	}
}

// reanchorNoProgress 时间戳不可信时重新锚定到当前时刻
func (s *Service) reanchorNoProgress(cert *config.CertConfig) {
	cert.Metadata.NoProgressSince = time.Now()
	if err := s.cfgManager.UpdateCert(cert); err != nil {
		s.log.Warn("重锚证书 %s 无进展计时失败: %v", cert.CertName, err)
	}
}

// stalledTooLong 判断自首次无进展起是否已超过无进展时限。
//
// 时钟不可信时一律返回 false 并重新锚定（保守方向：宁可多查几轮，也不把还在正常
// 等待签发的证书误判成停更）。不重锚的话，一个坏时间戳会让该证书永远绕过这道闸门。
func (s *Service) stalledTooLong(cert *config.CertConfig) bool {
	since := cert.Metadata.NoProgressSince
	if since.IsZero() {
		return false
	}
	elapsed := time.Since(since)
	if elapsed < 0 {
		s.log.Warn("证书 %s 无进展起点晚于当前时间（时钟回拨），重新锚定", cert.CertName)
		s.reanchorNoProgress(cert)
		return false
	}
	if elapsed > time.Duration(config.ClockSanityMaxDays)*24*time.Hour {
		s.log.Warn("证书 %s 无进展间隔 %.0f 天超出可信范围（%d 天），按时钟跳变重新锚定",
			cert.CertName, elapsed.Hours()/24, config.ClockSanityMaxDays)
		s.reanchorNoProgress(cert)
		return false
	}
	return elapsed >= time.Duration(config.MaxNoProgressDays)*24*time.Hour
}

// markStalled 无进展时限触顶：进入 CAPPED（停更）并清理在途产物。
// 私钥不能因为一张永远签不出来的证书永久驻留磁盘；验证文件同样清理——
// 订单已停止跟进，留在 webroot 下的 challenge 文件既无用又对外可读。
func (s *Service) markStalled(cert *config.CertConfig) {
	s.log.Error("证书 %s 自 %s 起连续 %d 天无任何进展，准备进入 CAPPED（停更）并清理在途产物",
		cert.CertName, cert.Metadata.NoProgressSince.Format("2006-01-02"), config.MaxNoProgressDays)
	s.persistTerminalState(cert, config.IssueStateCapped, config.CappedPhaseStalled)
}

// trackOrderStatus 记录服务端返回的订单状态（展示专用，不参与门禁判定），
// 返回状态是否相对上一轮发生变化。未变化时不写盘，避免每轮无谓 IO。
func (s *Service) trackOrderStatus(cert *config.CertConfig, status string) bool {
	if cert.Metadata.LastOrderStatus == status {
		return false
	}
	cert.Metadata.LastOrderStatus = status
	if err := s.cfgManager.UpdateCert(cert); err != nil {
		s.log.Warn("记录证书 %s 订单状态失败: %v", cert.CertName, err)
	}
	return true
}

// logOrderStatusSkip 按状态类别输出跳过日志。
//
// 仅在状态变化时用 Error/Warn：终态订单会被每日查询自愈，逐轮告警是零信息增量的
// 噪声，只会淹没真正的新问题。未变化时降为 Debug。
// 全部路径都只记日志不落门禁状态——真正的停止边界由无进展时限提供（spec §3.2）。
func (s *Service) logOrderStatusSkip(cert *config.CertConfig, status string, changed bool) {
	if !changed {
		s.log.Debug("证书 %s 订单状态 %s 未变化，继续等待", cert.CertName, status)
		return
	}
	switch config.ClassifyOrderStatus(status) {
	case config.OrderClassTerminal:
		s.log.Error("证书 %s 订单已进入终态 %s，不再自动推进，等待人工处理", cert.CertName, status)
	case config.OrderClassChainAnomaly:
		s.log.Error("证书 %s 收到链式状态 %s：服务端本应自动跟随续费/重签链，说明链数据异常（断链或成环），需人工核对", cert.CertName, status)
	case config.OrderClassUnknown:
		s.log.Warn("证书 %s 收到未知订单状态 %s，按等待处理（受无进展时限约束）", cert.CertName, status)
	default:
		s.log.Debug("证书 %s 状态: %s，跳过", cert.CertName, status)
	}
}

// preparePullRenew 自动签发：等待服务端续签完成后拉取证书
func (s *Service) preparePullRenew(ctx context.Context, cert *config.CertConfig, api config.APIConfig) (*fetcher.CertData, string, error) {
	certData, renewBeforeDays, err := s.queryOrder(ctx, api, cert.OrderID)
	if err != nil {
		return nil, "", err
	}
	s.tryUpdateRenewBeforeDays(renewBeforeDays)
	s.syncOrderID(cert, certData)
	// 订单状态只落展示字段，不写 last_issue_state（deploy-spec §3.4）：
	// pull 模式从不 POST，无需用该字段区分「有无在途订单」
	statusChanged := s.trackOrderStatus(cert, certData.Status)

	if certData.Status != config.OrderStatusActive || certData.Cert == "" {
		// processing + 文件验证：放置验证文件（全部放置失败按失败处理，避免静默永远 pending）
		if certData.Status == config.OrderStatusProcessing {
			if err := s.applyValidationFiles(cert, certData.File, true); err != nil {
				return nil, "", err
			}
		}
		s.logOrderStatusSkip(cert, certData.Status, statusChanged)
		return nil, "", nil
	}

	if certData.IntermediateCert == "" {
		return nil, "", fmt.Errorf("中间证书为空，等待下一周期重试")
	}

	// 获取私钥：优先使用 API 返回，否则从本地读取（pending 感知，配对校验）
	privateKey, err := GetPrivateKeyForCert(ctx, s.cfgManager.GetWorkDir(), cert, certData.Cert, certData.PrivateKey, s.log)
	if err != nil {
		return nil, "", err
	}
	return certData, privateKey, nil
}

// prepareLocalRenew 本机提交：生成 CSR 并通过 API 触发续签
func (s *Service) prepareLocalRenew(ctx context.Context, cert *config.CertConfig, api config.APIConfig) (*fetcher.CertData, string, error) {
	workDir := s.cfgManager.GetWorkDir()
	keyPath := pickKeyPath(cert)
	if keyPath == "" {
		return nil, "", fmt.Errorf("missing local private key path")
	}
	if cert.OrderID <= 0 {
		return nil, "", fmt.Errorf("missing order_id")
	}

	// 已有本地提交意图时一律 query-first。历史版本可能只有 LastIssueState、没有
	// CSRSubmittedAt/LastCSRHash；这类旧状态继续兼容恢复，新协议提交则必须校验服务端 CSR 归属。
	entryState := normalizeIssueState(cert.Metadata.LastIssueState)
	localIntent := hasLocalCSRIntent(cert)
	reuseActivePreflight := false
	if entryState == "" && !localIntent {
		// pending 写入后、metadata 保存前崩溃或清理失败会留下无归属孤儿。
		// 建立任何新尝试前先幂等清掉，避免覆盖或长期残留。
		if err := cleanupPendingKey(workDir, cert.CertName); err != nil {
			return nil, "", fmt.Errorf("清理无 CSR metadata 的孤儿 pending 私钥失败: %w", err)
		}
	}
	if entryState != "" || localIntent {
		// 规范 3.5：证书已过期则停止，等待人工处理
		// 按时间点判定，避免整数天截断使过期不足 24 小时的证书仍被继续处理
		if cert.IsExpired() {
			s.log.Error("证书 %s 已过期且签发未完成部署（状态 %s），等待人工处理", cert.CertName, entryState)
			return nil, "", fmt.Errorf("证书已过期，等待人工处理")
		}
		certData, renewBeforeDays, err := s.queryOrder(ctx, api, cert.OrderID)
		if err != nil {
			return nil, "", fmt.Errorf("查询订单失败: %w", err)
		}
		if certData.OrderID <= 0 || strings.TrimSpace(certData.Status) == "" {
			return nil, "", fmt.Errorf("查询订单响应缺少有效 order_id 或 status")
		}
		s.tryUpdateRenewBeforeDays(renewBeforeDays)
		s.syncOrderID(cert, certData)
		statusChanged := s.trackOrderStatus(cert, certData.Status)

		// 新协议提交必须由服务端原样返回的 CSR 证明归属。服务端 CSR 缺失或损坏时
		// 无法安全判断结果，保留 pending 与元数据并停止，不猜测、不重签。
		if localIntent {
			if strings.TrimSpace(certData.CSR) == "" {
				s.log.Warn("证书 %s 服务端未返回 CSR，无法确认本机提交归属，保留待确认私钥并停止本轮", cert.CertName)
				return nil, "", nil
			}

			commonName := ""
			if len(cert.Domains) > 0 {
				commonName = cert.Domains[0]
			}
			pendingKey, pendingErr := readPendingKey(workDir, cert.CertName)
			ownershipErr := pendingErr
			if ownershipErr == nil {
				ownershipErr = csr.ValidateOwnership(certData.CSR, pendingKey, cert.Metadata.LastCSRHash, commonName)
			}
			if ownershipErr != nil {
				if !stderrors.Is(ownershipErr, csr.ErrOwnershipMismatch) {
					s.log.Warn("证书 %s 无法验证服务端 CSR 与本机提交的归属，保留待确认私钥并停止本轮: %v", cert.CertName, ownershipErr)
					return nil, "", nil
				}

				switch config.ClassifyOrderStatus(certData.Status) {
				case config.OrderClassActive:
					if certData.Cert == "" {
						if err := s.discardLocalCSRIntent(cert, config.IssueStateActive); err != nil {
							return nil, "", err
						}
						s.log.Warn("证书 %s 服务端 active CSR 不属于本机提交，但证书内容为空，已清理旧提交并停止本轮", cert.CertName)
						return nil, "", nil
					}
					privateKey := ""
					matched := false
					privateKey, matched = s.matchingActiveKey(ctx, cert, certData, keyPath)
					nextState := ""
					if matched {
						nextState = config.IssueStateActive
					}
					if err := s.discardLocalCSRIntent(cert, nextState); err != nil {
						return nil, "", err
					}
					if matched {
						if certData.IntermediateCert == "" {
							return nil, "", fmt.Errorf("中间证书为空，等待下一周期重试")
						}
						s.log.Info("证书 %s 服务端 active CSR 不属于本机提交，已改用服务端或正式私钥部署", cert.CertName)
						return certData, privateKey, nil
					}
					s.log.Info("证书 %s 服务端 active CSR 不属于本机提交，且没有可部署私钥；复用本次 active 查询建立新尝试", cert.CertName)
					reuseActivePreflight = true

				case config.OrderClassWaiting:
					if err := s.discardLocalCSRIntent(cert, config.IssueStateProcessing); err != nil {
						return nil, "", err
					}
					if err := s.applyValidationFiles(cert, certData.File, true); err != nil {
						return nil, "", err
					}
					s.log.Info("证书 %s 服务端在途 CSR 不属于本机提交，已清理本地旧提交并跟随服务端状态 %s", cert.CertName, certData.Status)
					return nil, "", nil

				default:
					s.logOrderStatusSkip(cert, certData.Status, statusChanged)
					s.log.Warn("证书 %s 服务端 CSR 不属于本机提交，当前状态 %s 不宜自动归一，保留本地提交等待人工核对", cert.CertName, certData.Status)
					return nil, "", nil
				}
			} else {
				canonicalHash, hashErr := csr.DERHash(certData.CSR)
				if hashErr != nil {
					return nil, "", fmt.Errorf("规范化服务端 CSR 哈希失败: %w", hashErr)
				}
				if !strings.EqualFold(cert.Metadata.LastCSRHash, canonicalHash) {
					cert.Metadata.LastCSRHash = canonicalHash
					if err := s.cfgManager.UpdateCert(cert); err != nil {
						return nil, "", fmt.Errorf("保存规范化 CSR DER 哈希失败: %w", err)
					}
				}
			}
		}

		if !reuseActivePreflight {
			switch config.ClassifyOrderStatus(certData.Status) {
			case config.OrderClassActive:
				if certData.Cert == "" {
					// active 但证书内容为空，继续等待
					s.log.Debug("证书 %s 状态 active 但内容为空，跳过", cert.CertName)
					return nil, "", nil
				}
				if certData.IntermediateCert == "" {
					return nil, "", fmt.Errorf("中间证书为空，等待下一周期重试")
				}
				// 新协议已在上方确认服务端 CSR 与 pending 私钥、DER 哈希和 CN 均一致；
				// 历史状态没有 CSR 元数据时，保留原有 pending→正式私钥兼容恢复。
				if !localIntent {
					// 跟随其它服务端在途动作或历史状态时，先用 API/正式私钥。
					// 遗留 orphan pending 即使清理失败，也不能阻断已知可部署私钥。
					if privateKey, matched := s.matchingActiveKey(ctx, cert, certData, keyPath); matched {
						return certData, privateKey, nil
					}
					if privateKey, err := readPendingKey(workDir, cert.CertName); err == nil {
						if pairErr := validator.New("").ValidateCertKeyPair(certData.Cert, privateKey); pairErr == nil {
							return certData, privateKey, nil
						}
					}
					return nil, "", s.resetIssueStateForResubmit(cert,
						fmt.Errorf("服务端 active 证书没有可用的 API、正式或兼容 pending 私钥"))
				}

				privateKey, err := readPendingKey(workDir, cert.CertName)
				if err != nil {
					return nil, "", fmt.Errorf("已确认归属的 pending 私钥不可读: %w", err)
				}
				// 部署前先校验服务端返回的证书与私钥配对，
				// 不配对时按失败处理（pending 私钥保留、线上私钥不受影响）
				if err := validator.New("").ValidateCertKeyPair(certData.Cert, privateKey); err != nil {
					return nil, "", fmt.Errorf("服务端返回的证书与本地私钥不配对（pending 私钥已保留，线上私钥未改动）: %w", err)
				}
				// active 自愈（秒签已签发、等待部署）：仅返回待部署证书数据，不在此计数。
				// 部署尝试计数（DeployAttemptCount）由编排层 runDeployAttempt 统一管理，
				// 与签发计数（IssueRetryCount）分离、互不污染（计划 3.1）；
				// "证书已签发但全部绑定部署失败"的续跑循环受 MaxDeployAttemptCount 约束并最终触顶停机。
				return certData, privateKey, nil

			case config.OrderClassWaiting:
				// pending / approving 归一 processing；unpaid / cancelling 同归此类——
				// 二者都不是终态：unpaid 由服务端 update 自动推进、孤儿单 60 分钟内清理，
				// cancelling 会转 cancelled。客户端只查询等待，**不主动 POST 推进**：
				// POST 会触发服务端 pay 扣费，涉及资金的动作不由客户端自动发起。
				// 不重复 POST、不增计数、不重生 CSR（spec 2.4/3.5），边界由无进展时限提供。
				if err := s.applyValidationFiles(cert, certData.File, true); err != nil {
					return nil, "", err
				}
				s.log.Debug("证书 %s 签发处理中 (status=%s)，等待", cert.CertName, certData.Status)
				return nil, "", nil

			default:
				// 真终态 / 链式异常只记展示字段；未知状态保守写客户端门禁 processing。
				// 原始服务端状态始终只保存在 last_order_status，两个概念不混用。
				s.logOrderStatusSkip(cert, certData.Status, statusChanged)
				if config.ClassifyOrderStatus(certData.Status) == config.OrderClassUnknown &&
					cert.Metadata.LastIssueState != config.IssueStateProcessing {
					// 未知新增状态保守当作在途；只写客户端门禁 processing，
					// 原始服务端状态仍由 LastOrderStatus 单独展示。
					cert.Metadata.LastIssueState = config.IssueStateProcessing
					if err := s.cfgManager.UpdateCert(cert); err != nil {
						return nil, "", fmt.Errorf("保存未知服务端状态的 query-only 门禁失败: %w", err)
					}
				}
				// 仅状态首次变化时报失败：让用户看到一次，之后静默等待自愈，
				// 避免终态证书每日刷一条 failure 统计。未知状态一律不报失败——
				// 服务端新增中间态不该把证书打进失败统计。
				if statusChanged && config.ClassifyOrderStatus(certData.Status) != config.OrderClassUnknown {
					return nil, "", fmt.Errorf("订单状态 %s 需人工处理", certData.Status)
				}
				return nil, "", nil
			}
		}
	}

	// 没有本地提交意图时，提交前必须先 GET。只有服务端明确返回 active 才能
	// 建立新逻辑尝试；其它状态只跟随查询结果，不生成 CSR、不落 pending、不增加计数。
	if !reuseActivePreflight {
		preflightData, renewBeforeDays, err := s.queryOrder(ctx, api, cert.OrderID)
		if err != nil {
			return nil, "", fmt.Errorf("提交 CSR 前查询订单失败: %w", err)
		}
		if preflightData.OrderID <= 0 || strings.TrimSpace(preflightData.Status) == "" {
			return nil, "", fmt.Errorf("提交 CSR 前查询响应缺少有效 order_id 或 status")
		}
		s.tryUpdateRenewBeforeDays(renewBeforeDays)
		s.syncOrderID(cert, preflightData)
		statusChanged := s.trackOrderStatus(cert, preflightData.Status)
		statusClass := config.ClassifyOrderStatus(preflightData.Status)
		if statusClass != config.OrderClassActive {
			if statusClass == config.OrderClassWaiting || statusClass == config.OrderClassUnknown {
				cert.Metadata.LastIssueState = config.IssueStateProcessing
				if err := s.cfgManager.UpdateCert(cert); err != nil {
					return nil, "", fmt.Errorf("保存服务端在途状态失败: %w", err)
				}
				if statusClass == config.OrderClassWaiting {
					if err := s.applyValidationFiles(cert, preflightData.File, true); err != nil {
						return nil, "", err
					}
				}
				s.log.Debug("证书 %s 提交前查询为 %s，仅等待服务端推进", cert.CertName, preflightData.Status)
				return nil, "", nil
			}
			s.logOrderStatusSkip(cert, preflightData.Status, statusChanged)
			if statusChanged && config.ClassifyOrderStatus(preflightData.Status) != config.OrderClassUnknown {
				return nil, "", fmt.Errorf("订单状态 %s 不允许提交 CSR", preflightData.Status)
			}
			return nil, "", nil
		}
	}

	currentConfig, err := s.cfgManager.Load()
	if err != nil {
		return nil, "", fmt.Errorf("检查 CSR 新尝试续签窗口失败: %w", err)
	}
	if !cert.NeedsRenewal(&currentConfig.Schedule) {
		return nil, "", fmt.Errorf("证书已不在续签窗口，停止建立新 CSR 尝试")
	}
	if !cert.Metadata.CertExpiresAt.IsZero() &&
		time.Until(cert.Metadata.CertExpiresAt) < AutoActionSafetyMargin {
		return nil, "", fmt.Errorf("证书剩余有效期不足安全余量，停止建立新 CSR 尝试")
	}

	// 即将提交新 CSR：签发触顶防御检查（编排层前置过滤后仍二次校验，绝无第 11 次提交）。
	if cert.Metadata.IssueRetryCount >= MaxIssueRetryCount {
		s.log.Error("证书 %s 签发尝试已达上限 (%d)，不再提交新 CSR，等待人工处理", cert.CertName, MaxIssueRetryCount)
		return nil, "", fmt.Errorf("exceeded max issue retry count (%d)", MaxIssueRetryCount)
	}

	// 生成新的私钥与 CSR
	commonName := ""
	if len(cert.Domains) > 0 {
		commonName = cert.Domains[0]
	}
	if commonName == "" {
		return nil, "", fmt.Errorf("缺少域名，无法生成 CSR")
	}

	privateKey, csrPEM, csrHash, err := csr.GenerateKeyAndCSR(csr.KeyOptions{}, csr.CSROptions{
		CommonName: commonName,
	})
	if err != nil {
		return nil, "", fmt.Errorf("生成 CSR 失败: %w", err)
	}

	// 新私钥保存到待确认目录（不覆盖正式私钥）
	if err := savePendingKey(workDir, cert.CertName, privateKey); err != nil {
		return nil, "", fmt.Errorf("保存待确认私钥失败: %w", err)
	}

	// POST 前一次性持久化完整提交意图。进程即使在请求发出或响应落盘前崩溃，
	// 下轮也能凭 pending + DER 哈希 query-first 收敛，绝不会直接重放 POST。
	intentSnapshot := snapshotLocalCSRIntent(cert)
	cert.Metadata.IssueRetryCount++
	cert.Metadata.CSRSubmittedAt = time.Now()
	cert.Metadata.LastCSRHash = csrHash
	cert.Metadata.LastIssueState = config.IssueStateProcessing
	if err := s.cfgManager.UpdateCert(cert); err != nil {
		restoreLocalCSRIntent(cert, intentSnapshot)
		if cleanupErr := cleanupPendingKey(workDir, cert.CertName); cleanupErr != nil {
			return nil, "", fmt.Errorf("持久化 CSR 提交意图失败且清理 pending 失败: %w",
				stderrors.Join(err, cleanupErr))
		}
		return nil, "", fmt.Errorf("持久化 CSR 提交意图失败: %w", err)
	}

	certData, renewBeforeDaysFromUpdate, err := s.fetcher.Update(ctx, api.URL, api.Token, cert.OrderID, csrPEM, strings.Join(cert.Domains, ","), cert.ValidationMethod)
	if err != nil {
		// 整批共通失败（限流 / token 或账号被禁 / IP 未放行）由认证与限流中间件拦下，
		// 服务端根本没收到这次提交：回滚签发计数、清理在途私钥，等同于本次提交没发生。
		// 不回滚的话 token 持续失效满 10 轮就把签发额度烧光，人工换发 token 后证书已是
		// CAPPED、还要再人工解除一次——与环境闸门「阻断不占配额、修好即自动恢复」同一纪律。
		if s.authGate.record(api, err) {
			restoreLocalCSRIntent(cert, intentSnapshot)
			if updateErr := s.cfgManager.UpdateCert(cert); updateErr != nil {
				// 落盘回滚失败时保留 pending：磁盘上的提交意图仍可能有效，删除私钥会
				// 造成下一轮有意图但无法核对归属。宁可留下待确认产物等待恢复。
				return nil, "", fmt.Errorf("提交 CSR 被服务端拒绝，且回滚本地提交意图失败（pending 已保留）: %w",
					stderrors.Join(err, updateErr))
			}
			if cleanupErr := cleanupPendingKey(workDir, cert.CertName); cleanupErr != nil {
				return nil, "", fmt.Errorf("提交 CSR 被服务端拒绝且清理 pending 失败: %w",
					stderrors.Join(err, cleanupErr))
			}
			return nil, "", fmt.Errorf("提交 CSR 被服务端拒绝（本轮不再使用该 Token）: %w", err)
		}
		// 服务端明确已有另一笔在途订单：本次 CSR 未被采用。清理本地 pending 与
		// CSR 元数据，保留已发生的逻辑尝试计数，后续只跟随服务端查询。
		if errors.ErrorCodeOf(err) == fetcher.ErrorCodeOrderInProgress {
			if discardErr := s.discardLocalCSRIntent(cert, config.IssueStateProcessing); discardErr != nil {
				return nil, "", fmt.Errorf("服务端报告订单已在途，但清理本地提交失败: %w",
					stderrors.Join(err, discardErr))
			}
			s.log.Info("证书 %s 订单已在途（服务端签发进行中），归一 processing 等待签发完成: %v", cert.CertName, err)
			return nil, "", nil
		}
		// 明确业务拒绝：服务端未接收本次 CSR。清理本地提交产物，保留计数，
		// 下轮从 active 预检开始建立新的逻辑尝试。
		if errors.IsBusinessError(err) {
			if discardErr := s.discardLocalCSRIntent(cert, ""); discardErr != nil {
				return nil, "", fmt.Errorf("提交 CSR 被服务端拒绝，且清理本地提交失败: %w",
					stderrors.Join(err, discardErr))
			}
			return nil, "", fmt.Errorf("提交 CSR 被服务端拒绝: %w", err)
		}
		// POST 超时 / 断连 / 响应解析失败属不确定结果：提交意图已在 POST 前持久化，
		// 原样保留即可；下轮 GET 并用服务端 CSR 判断，不做传输层或业务层重放。
		s.log.Warn("证书 %s 提交 CSR 结果不确定（保留 pending key，下轮查询归一 processing）: %v", cert.CertName, err)
		return nil, "", nil
	}
	s.tryUpdateRenewBeforeDays(renewBeforeDaysFromUpdate)

	s.syncOrderID(cert, certData)

	// pending 归一 processing（spec 2.6）
	cert.Metadata.LastIssueState = normalizeIssueState(certData.Status)
	if cert.Metadata.LastIssueState == "" && certData.Status != config.OrderStatusActive {
		cert.Metadata.LastIssueState = config.IssueStateProcessing
	}

	if certData.Status != config.OrderStatusActive || certData.Cert == "" {
		// 放置验证文件（如果有；全部放置失败按失败处理，但先保存元数据，
		// LastIssueState=processing 已持久化，下轮走 processing 分支重试放置）
		placeErr := s.applyValidationFiles(cert, certData.File, false)
		// 保存元数据变更（OrderID、CSRSubmittedAt、ValidationFiles 等）
		if err := s.cfgManager.UpdateCert(cert); err != nil {
			s.log.Warn("保存证书元数据失败: %v", err)
		}
		if placeErr != nil {
			return nil, "", placeErr
		}
		s.log.Info("证书 %s CSR 已提交，等待签发 (status=%s)", cert.CertName, certData.Status)
		return nil, "", nil
	}

	if certData.IntermediateCert == "" {
		return nil, "", fmt.Errorf("中间证书为空，等待下一周期重试")
	}

	// 部署前先校验服务端返回的证书与本次生成的私钥配对，
	// 不配对（如服务端返回旧订单证书）时按失败处理，pending 私钥保留、线上私钥不受影响。
	// 注意：私钥转正在部署成功后由 deployCertToBindings 执行，遵循规范 3.8。
	if err := validator.New("").ValidateCertKeyPair(certData.Cert, privateKey); err != nil {
		return nil, "", fmt.Errorf("服务端返回的证书与本次 CSR 私钥不配对（pending 私钥已保留，线上私钥未改动）: %w", err)
	}

	// 秒签：服务端在提交 CSR 后立即返回 active 证书。此处不清零签发状态——
	// 部署可能全部失败，一旦清零，下轮 NeedsRenewal 仍为 true 却因状态为空重新生成 CSR，
	// 覆盖与本次已签发证书配对的 pending 私钥，且 IssueRetryCount 复位旁路 MaxIssueRetryCount 停机保护，
	// 每个续签周期重签一次直到旧证书过期。
	// 保留 CSRSubmittedAt/LastCSRHash/IssueRetryCount，持久化 LastIssueState="active" 作为崩溃安全网，
	// 使部署失败后下轮走 active 自愈分支：查询订单→读 pending→配对→复用部署路径。
	// 部署成功由 deployCertToBindings 统一清零状态并转正 pending（规范 3.8）。
	cert.Metadata.LastIssueState = config.IssueStateActive
	if err := s.cfgManager.UpdateCert(cert); err != nil {
		s.log.Warn("保存证书元数据失败: %v", err)
	}

	return certData, privateKey, nil
}

// deployCertToBindings 部署证书到所有绑定
// 返回：成功部署数、失败的绑定 ServerName 列表、最后一个错误
func (s *Service) deployCertToBindings(ctx context.Context, cert *config.CertConfig, certData *fetcher.CertData, privateKey string) (int, []string, error) {
	// 验证证书与私钥
	v := validator.New("")
	parsedCert, err := v.ValidateCert(certData.Cert)
	if err != nil || parsedCert == nil {
		return 0, nil, fmt.Errorf("证书验证失败: %w", err)
	}
	if err := v.ValidateCertKeyPair(certData.Cert, privateKey); err != nil {
		return 0, nil, fmt.Errorf("私钥不匹配: %w", err)
	}

	// 纵深防御：零启用绑定时返回明确错误而非 (0, nil, nil)，否则调用方会把"一个站点都没部署"
	// 读成成功并向服务端上报 success。早退发生在下方 FailedBindings 赋值之前，
	// 失败绑定记录必须原样保留（在此清空会销毁重试与 stale 迁移所依赖的名单）。
	// 验证文件仍需清理：已经拿到证书，签发用途已尽。
	if !cert.HasEnabledBinding() {
		s.cleanupCertValidationFiles(cert)
		return 0, cert.Metadata.FailedBindings, ErrNoEnabledBinding
	}

	// 部署到所有绑定
	deployCount := 0
	var lastErr error
	var failedBindings []string
	for j := range cert.Bindings {
		// 使用值拷贝而非指针，确保深拷贝保护有效
		binding := cert.Bindings[j]
		if !binding.Enabled {
			continue
		}

		if err := s.deployToBinding(ctx, &binding, certData, privateKey); err != nil {
			s.log.Error("部署到 %s 失败: %v", binding.ServerName, err)
			lastErr = err
			failedBindings = append(failedBindings, binding.ServerName)
			continue
		}
		s.log.Info("证书已部署到 %s", binding.ServerName)
		ClearStaleBinding(cert, binding.ServerName)
		deployCount++
	}

	cert.Metadata.FailedBindings = failedBindings
	if len(failedBindings) > 0 && cert.Metadata.FailedBindingsAt.IsZero() {
		cert.Metadata.FailedBindingsAt = time.Now()
	} else if len(failedBindings) == 0 {
		cert.Metadata.FailedBindingsAt = time.Time{}
	}

	// 元数据不变式：仅至少一个绑定部署成功后才更新证书元数据与 CSR 状态。
	// 全部失败时保持旧 CertExpiresAt/Domains 与 pending 状态，下轮 NeedsRenewal 仍为 true，
	// 走完整 prepare→读 pending→部署 的自愈循环；若提前更新 CertExpiresAt，
	// 下轮只会走 retryFailedBindings，而未转正的 pending 私钥读不到，
	// 旧私钥与新证书配对必败，站点将挂着旧证书走向真实过期。
	if deployCount > 0 {
		// 从证书 PEM 提取域名更新配置（规范 5.5：确保 domains 反映实际部署的证书内容）
		if domains := extractDomainsFromParsedCert(parsedCert); len(domains) > 0 {
			cert.Domains = domains
		}
		cert.Metadata.CertExpiresAt = parsedCert.NotAfter
		cert.Metadata.CertSerial = fmt.Sprintf("%X", parsedCert.SerialNumber)
		cert.Metadata.LastDeployAt = time.Now()
		// 部署成功后才将 pending 私钥转正（规范 3.8：部署成功后清理 pending key）。
		// 部署路径（deployToBinding）已在覆盖前备份各绑定的旧证书与私钥。
		s.commitPendingKeyAfterDeploy(cert, privateKey)
		// 成功后清理本地续签与部署状态（签发计数与部署计数一并清零）
		cert.Metadata.CSRSubmittedAt = time.Time{}
		cert.Metadata.LastCSRHash = ""
		cert.Metadata.LastIssueState = ""
		cert.Metadata.CappedPhase = ""
		cert.Metadata.IssueRetryCount = 0
		cert.Metadata.DeployAttemptCount = 0
		cert.Metadata.DeployStartedAt = time.Time{}
		// 部署发生即最强的进展信号，一并清零停更计时（deploy-spec §3.8）。
		// 编排层的快照结算也会覆盖此处（LastDeployAt 已变），显式清零是为了让
		// 手动 deploy / setup 复用本函数时同样受益。
		cert.Metadata.NoProgressSince = time.Time{}
		// 注意：**不得**在此清零 UnchangedCertRounds。它的所有权属于
		// trackCertUnchanged（序列号变化时清零、相同时递增），而该检测在本函数之后执行——
		// 在这里清零会让计数每轮先归零再递增到 1，永远达不到升级阈值，整个检测失效。
		// sslbt 的实现正是踩了这个坑（unchanged_cert_rounds 被放进部署成功清零列表）。
	}

	s.cleanupCertValidationFiles(cert)

	return deployCount, failedBindings, lastErr
}

// cleanupCertValidationFiles 清理已放置的验证文件并清空记录。
// 签发已完成（拿到证书）后验证文件用途已尽，无论部署成败都清理，避免残留在 webroot。
func (s *Service) cleanupCertValidationFiles(cert *config.CertConfig) {
	if len(cert.Metadata.ValidationFiles) == 0 {
		return
	}
	cert.Metadata.ValidationFiles = cleanupValidationFiles(cert.Metadata.ValidationFiles, s.log)
}

// commitPendingKeyAfterDeploy 部署成功后将 pending 私钥转正（Service 包装）
func (s *Service) commitPendingKeyAfterDeploy(cert *config.CertConfig, deployedKey string) {
	CommitPendingKeyIfMatches(s.cfgManager.GetWorkDir(), cert, deployedKey, s.log)
}

// CommitPendingKeyIfMatches 部署成功后将与已部署私钥一致的 pending 私钥转正并清理 pending 文件。
// 供续签、失败绑定重试与 CLI 手动部署链共用（规范 3.8：部署成功后清理 pending key）。
// 仅当 pending 内容与本次部署使用的私钥一致才转正，防止误转不相关的残留文件
// （pull 模式或已清理时无 pending 文件，直接跳过）。
// 转正失败不影响部署结果：各绑定已通过部署路径写入新私钥，仅记录告警。
func CommitPendingKeyIfMatches(workDir string, cert *config.CertConfig, deployedKey string, log *logger.Logger) {
	pendingKey, err := readPendingKey(workDir, cert.CertName)
	if err != nil {
		return // 无 pending 私钥（pull 模式或已清理）
	}
	if pendingKey != deployedKey {
		if log != nil {
			log.Warn("证书 %s 的 pending 私钥与本次部署私钥不一致，保留 pending 文件待人工确认", cert.CertName)
		}
		return
	}
	if hasDockerCopyBinding(cert) {
		ctx, cancel := context.WithTimeout(context.Background(), RollbackBudget)
		defer cancel()
		for i := range cert.Bindings {
			binding := &cert.Bindings[i]
			if !binding.Enabled {
				continue
			}
			current, readErr := ReadBindingPrivateKey(ctx, binding)
			matches := matchPrivateKeyAndClear(current, deployedKey) && readErr == nil
			if matches {
				if err := cleanupPendingKey(workDir, cert.CertName); err != nil && log != nil {
					log.Warn("清理 pending 私钥失败: %v", err)
				}
				return
			}
		}
		if log != nil {
			log.Warn("正式私钥尚未确认，保留 pending 私钥")
		}
		return
	}

	keyPath := pickKeyPath(cert)
	if keyPath == "" {
		return
	}
	if err := commitPendingKey(workDir, cert.CertName, keyPath); err != nil && log != nil {
		log.Warn("转正 pending 私钥失败（部署已成功，不影响本次结果）: %v", err)
	}
}

// getPendingKeyPath 获取待确认私钥路径
func getPendingKeyPath(workDir, certName string) string {
	return filepath.Join(workDir, pendingKeyDir, certName, "pending-key.pem")
}

// savePendingKey 保存待确认私钥到临时位置
func savePendingKey(workDir, certName, keyPEM string) error {
	pendingPath := getPendingKeyPath(workDir, certName)
	pendingDir := filepath.Dir(pendingPath)
	if err := util.EnsureDir(pendingDir, 0700); err != nil {
		return err
	}
	return util.AtomicWrite(pendingPath, []byte(keyPEM), 0600)
}

// readPendingKey 读取待确认私钥
// 使用 SafeReadFile 进行安全读取：大小限制 + 符号链接防护 + TOCTOU 保护
func readPendingKey(workDir, certName string) (string, error) {
	pendingPath := getPendingKeyPath(workDir, certName)
	data, err := util.SafeReadFile(pendingPath, config.MaxPrivateKeySize)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

// commitPendingKey 签发成功后将待确认私钥移动到正式位置
// 失败时错误信息包含相对路径（脱敏），便于手动恢复
func commitPendingKey(workDir, certName, targetPath string) error {
	pendingPath := getPendingKeyPath(workDir, certName)
	if _, err := os.Lstat(pendingPath); os.IsNotExist(err) {
		return nil // 不存在则跳过
	}
	// 相对路径用于错误消息（脱敏）
	pendingRelPath := filepath.Join(pendingKeyDir, certName, "pending-key.pem")

	// 确保目标目录存在
	targetDir := filepath.Dir(targetPath)
	if err := util.EnsureDir(targetDir, 0700); err != nil {
		return fmt.Errorf("创建目标目录失败: %w (pending 私钥保留在: %s，请手动恢复)", err, pendingRelPath)
	}
	// 移动文件
	if err := os.Rename(pendingPath, targetPath); err != nil {
		// 如果跨文件系统，使用原子写入：先写临时文件，再重命名
		data, readErr := os.ReadFile(pendingPath)
		if readErr != nil {
			// 读取失败，保留 pending 私钥以便手动恢复
			return fmt.Errorf("读取待确认私钥失败: %w (pending 私钥保留在: %s，请手动恢复)", readErr, pendingRelPath)
		}
		// 使用 AtomicWrite 安全写入（带符号链接防护）
		if writeErr := util.AtomicWrite(targetPath, data, 0600); writeErr != nil {
			// 清零内存中的私钥材料
			for i := range data {
				data[i] = 0
			}
			return fmt.Errorf("写入目标私钥失败: %w (pending 私钥保留在: %s，请手动恢复)", writeErr, pendingRelPath)
		}
		// 清零内存中的私钥材料
		for i := range data {
			data[i] = 0
		}
		// 成功后才清理 pending 私钥
		_ = os.Remove(pendingPath)
	}
	// 清理待确认目录
	_ = os.Remove(filepath.Dir(pendingPath))
	return nil
}

// extractDomainsFromParsedCert 从已解析的证书中提取域名：SAN（DNSNames + IPAddresses）优先，CN 补充
func extractDomainsFromParsedCert(cert *x509.Certificate) []string {
	seen := make(map[string]bool)
	var domains []string
	add := func(d string) {
		if d != "" && !seen[d] {
			seen[d] = true
			domains = append(domains, d)
		}
	}
	for _, d := range cert.DNSNames {
		add(d)
	}
	for _, ip := range cert.IPAddresses {
		add(ip.String())
	}
	add(cert.Subject.CommonName)
	return domains
}

// copyPendingKey 证书改名（order_id 变更）时把 pending 私钥**复制**到新名目录（保留源）。
// 源不存在为空操作。改名采用两阶段提交：复制成功 → 配置落盘成功 → 才删除旧目录；
// 中途失败时配置名与 pending 目录始终保持一致，不会出现"配置已改名、私钥还在旧目录"的错配。
// 权限与 savePendingKey 一致（目录 0700、文件 0600、原子写入），
// 因为改为复制后不再有 os.Rename 自带的权限继承。
func copyPendingKey(workDir, oldName, newName string) error {
	if oldName == newName {
		return nil
	}
	oldPath := getPendingKeyPath(workDir, oldName)
	if _, err := os.Lstat(oldPath); os.IsNotExist(err) {
		return nil
	}
	data, err := util.SafeReadFile(oldPath, config.MaxPrivateKeySize)
	if err != nil {
		return err
	}
	defer func() { clear(data) }()

	newPath := getPendingKeyPath(workDir, newName)
	if err := util.EnsureDir(filepath.Dir(newPath), 0700); err != nil {
		return err
	}
	return util.AtomicWrite(newPath, data, 0600)
}

// cleanupPendingKey 清理待确认私钥，返回清理过程中遇到的第一个错误
func cleanupPendingKey(workDir, certName string) error {
	pendingPath := getPendingKeyPath(workDir, certName)
	var firstErr error
	if err := os.Remove(pendingPath); err != nil && !os.IsNotExist(err) {
		firstErr = err
	}
	if err := os.Remove(filepath.Dir(pendingPath)); err != nil && !os.IsNotExist(err) && firstErr == nil {
		firstErr = err
	}
	return firstErr
}
