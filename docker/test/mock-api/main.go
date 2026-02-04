// 模拟证书 API 服务器
// 用于测试证书部署流程
// 支持场景切换、请求记录、多端点模拟
package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// ==============================================================================
// 数据结构
// ==============================================================================

// FileChallenge 文件验证
type FileChallenge struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// CertData 证书数据（与 fetcher.CertData 字段名匹配）
type CertData struct {
	OrderID          int            `json:"order_id"`
	Status           string         `json:"status"`
	CommonName       string         `json:"common_name"`
	Domain           string         `json:"domain,omitempty"`
	Domains          string         `json:"domains,omitempty"`
	Cert             string         `json:"certificate"`       // 注意：使用 certificate 而非 cert
	IntermediateCert string         `json:"ca_certificate"`    // 注意：使用 ca_certificate 而非 intermediate_cert
	PrivateKey       string         `json:"private_key"`
	ExpiresAt        string         `json:"expires_at"`
	CreatedAt        string         `json:"created_at,omitempty"`
	File             *FileChallenge `json:"file,omitempty"`
}

// OrderData 订单数据
type OrderData struct {
	OrderID    int      `json:"order_id"`
	Status     string   `json:"status"`
	Domains    string   `json:"domains"`
	CommonName string   `json:"common_name"`
	CreatedAt  string   `json:"created_at"`
	ExpiresAt  string   `json:"expires_at"`
	RenewMode  string   `json:"renew_mode,omitempty"`
	CertData   CertData `json:"-"` // 内部使用
}

// APIResponse 统一响应格式
type APIResponse struct {
	Code    int         `json:"code"`
	Message string      `json:"msg"`
	Data    interface{} `json:"data"`
}

// CallbackRequest 部署回调请求
type CallbackRequest struct {
	Domain        string `json:"domain"`
	Status        string `json:"status"`
	DeployedAt    string `json:"deployed_at"`
	CertExpiresAt string `json:"cert_expires_at,omitempty"`
	CertSerial    string `json:"cert_serial,omitempty"`
	ServerType    string `json:"server_type,omitempty"`
	Message       string `json:"message,omitempty"`
}

// RenewRequest 续签请求
type RenewRequest struct {
	OrderID int    `json:"order_id"`
	CSR     string `json:"csr,omitempty"`
}

// RequestLog 请求日志
type RequestLog struct {
	Time      string              `json:"time"`
	Method    string              `json:"method"`
	Path      string              `json:"path"`
	Headers   map[string][]string `json:"headers"`
	Query     map[string][]string `json:"query"`
	Body      string              `json:"body,omitempty"`
	RemoteIP  string              `json:"remote_ip"`
	UserAgent string              `json:"user_agent"`
}

// ==============================================================================
// 全局状态
// ==============================================================================

var (
	certFile   string
	keyFile    string
	chainFile  string
	commonName string

	// 缓存的证书内容（启动时加载）
	cachedCert  string
	cachedKey   string
	cachedChain string

	// 场景模式
	currentScenario = "active"
	scenarioMutex   sync.RWMutex

	// 订单存储
	orders      = make(map[int]*OrderData)
	ordersMutex sync.RWMutex
	nextOrderID = 1000

	// 请求日志
	requestLogs      []RequestLog
	requestLogsMutex sync.Mutex
	maxLogSize       = 100

	// 回调记录
	callbacks      []CallbackRequest
	callbacksMutex sync.Mutex
)

// 场景配置
var scenarios = map[string]struct {
	status    string
	expiresIn time.Duration
	errorCode int
	errorMsg  string
}{
	"active":     {status: "active", expiresIn: 90 * 24 * time.Hour},
	"processing": {status: "processing", expiresIn: 0},
	"expired":    {status: "expired", expiresIn: -30 * 24 * time.Hour},
	"error":      {errorCode: 500, errorMsg: "Internal server error"},
	"unauthorized": {errorCode: 401, errorMsg: "Unauthorized"},
	"not_found":    {errorCode: 404, errorMsg: "Order not found"},
}

// ==============================================================================
// 主函数
// ==============================================================================

func main() {
	port := flag.Int("port", 8080, "API 服务端口")
	flag.StringVar(&certFile, "cert", "", "证书文件路径")
	flag.StringVar(&keyFile, "key", "", "私钥文件路径")
	flag.StringVar(&chainFile, "chain", "", "中间证书文件路径")
	flag.StringVar(&commonName, "cn", "example.com", "证书 CommonName")
	flag.Parse()

	// 启动时加载证书内容到内存（避免文件被删除后读取失败）
	loadCertFiles()

	// 初始化一些测试订单
	initTestOrders()

	// 注册路由
	mux := http.NewServeMux()

	// 主要 API 端点
	mux.HandleFunc("/api/deploy", handleDeploy)
	mux.HandleFunc("/api/cert", handleCert)
	mux.HandleFunc("/api/callback", handleCallback)

	// 管理端点
	mux.HandleFunc("/admin/scenario/", handleSetScenario)
	mux.HandleFunc("/admin/reset", handleReset)
	mux.HandleFunc("/admin/logs", handleGetLogs)
	mux.HandleFunc("/admin/callbacks", handleGetCallbacks)
	mux.HandleFunc("/admin/orders", handleManageOrders)

	// 健康检查
	mux.HandleFunc("/health", handleHealth)

	// 包装中间件
	handler := loggingMiddleware(mux)

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Mock API server starting on %s", addr)
	log.Printf("Cert: %s, Key: %s, Chain: %s", certFile, keyFile, chainFile)
	log.Printf("Default scenario: %s", currentScenario)
	log.Fatal(http.ListenAndServe(addr, handler))
}

// ==============================================================================
// 初始化
// ==============================================================================

// loadCertFiles 在启动时加载证书内容到内存
func loadCertFiles() {
	if certFile != "" {
		cert, err := os.ReadFile(certFile)
		if err != nil {
			log.Printf("Warning: Cannot read cert file %s: %v", certFile, err)
			cachedCert = generateValidSelfSignedCert(commonName)
		} else {
			cachedCert = string(cert)
			log.Printf("Loaded cert from %s", certFile)
		}
	} else {
		cachedCert = generateValidSelfSignedCert(commonName)
	}

	if keyFile != "" {
		key, err := os.ReadFile(keyFile)
		if err != nil {
			log.Printf("Warning: Cannot read key file %s: %v", keyFile, err)
			cachedKey = generateValidPrivateKey()
		} else {
			cachedKey = string(key)
			log.Printf("Loaded key from %s", keyFile)
		}
	} else {
		cachedKey = generateValidPrivateKey()
	}

	if chainFile != "" {
		chain, err := os.ReadFile(chainFile)
		if err != nil {
			log.Printf("Warning: Cannot read chain file %s: %v", chainFile, err)
		} else {
			cachedChain = string(chain)
			log.Printf("Loaded chain from %s", chainFile)
		}
	}
}

func initTestOrders() {
	ordersMutex.Lock()
	defer ordersMutex.Unlock()

	// 创建一些测试订单
	orders[1001] = &OrderData{
		OrderID:    1001,
		Status:     "active",
		Domains:    "test.example.com,*.test.example.com",
		CommonName: "test.example.com",
		CreatedAt:  time.Now().AddDate(0, -1, 0).Format(time.RFC3339),
		ExpiresAt:  time.Now().AddDate(0, 2, 0).Format(time.RFC3339),
		RenewMode:  "pull",
	}

	orders[1002] = &OrderData{
		OrderID:    1002,
		Status:     "processing",
		Domains:    "pending.example.com",
		CommonName: "pending.example.com",
		CreatedAt:  time.Now().Format(time.RFC3339),
		ExpiresAt:  "",
	}

	orders[1003] = &OrderData{
		OrderID:    1003,
		Status:     "expired",
		Domains:    "expired.example.com",
		CommonName: "expired.example.com",
		CreatedAt:  time.Now().AddDate(-1, 0, 0).Format(time.RFC3339),
		ExpiresAt:  time.Now().AddDate(0, 0, -30).Format(time.RFC3339),
	}

	nextOrderID = 1004
}

// ==============================================================================
// 中间件
// ==============================================================================

func loggingMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// 跳过健康检查的日志
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}

		// 记录请求
		logRequest(r)

		log.Printf("[%s] %s %s from %s", r.Method, r.URL.Path, r.URL.RawQuery, r.RemoteAddr)
		next.ServeHTTP(w, r)
	})
}

func logRequest(r *http.Request) {
	requestLogsMutex.Lock()
	defer requestLogsMutex.Unlock()

	entry := RequestLog{
		Time:      time.Now().Format(time.RFC3339),
		Method:    r.Method,
		Path:      r.URL.Path,
		Headers:   r.Header,
		Query:     r.URL.Query(),
		RemoteIP:  r.RemoteAddr,
		UserAgent: r.UserAgent(),
	}

	requestLogs = append(requestLogs, entry)

	// 限制日志大小
	if len(requestLogs) > maxLogSize {
		requestLogs = requestLogs[len(requestLogs)-maxLogSize:]
	}
}

// ==============================================================================
// API 处理函数
// ==============================================================================

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

// handleDeploy 处理部署相关 API
// GET /api/deploy - 获取订单列表
// GET /api/deploy?order_id=xxx - 获取指定订单
// POST /api/deploy - 续签请求
func handleDeploy(w http.ResponseWriter, r *http.Request) {
	// 检查 Authorization
	if !checkAuth(w, r) {
		return
	}

	// 检查场景
	scenario := getScenario()
	if cfg, ok := scenarios[scenario]; ok && cfg.errorCode > 0 {
		w.WriteHeader(cfg.errorCode)
		_ = json.NewEncoder(w).Encode(APIResponse{Code: 0, Message: cfg.errorMsg})
		return
	}

	switch r.Method {
	case http.MethodGet:
		handleGetOrders(w, r)
	case http.MethodPost:
		handleRenewRequest(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Code: 0, Message: "Method not allowed"})
	}
}

func handleGetOrders(w http.ResponseWriter, r *http.Request) {
	ordersMutex.RLock()
	defer ordersMutex.RUnlock()

	w.Header().Set("Content-Type", "application/json")

	// 检查是否请求特定订单
	orderIDStr := r.URL.Query().Get("order_id")
	if orderIDStr != "" {
		orderID, err := strconv.Atoi(orderIDStr)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_ = json.NewEncoder(w).Encode(APIResponse{Code: 0, Message: "Invalid order_id"})
			return
		}

		order, exists := orders[orderID]
		if !exists {
			w.WriteHeader(http.StatusNotFound)
			_ = json.NewEncoder(w).Encode(APIResponse{Code: 0, Message: "Order not found"})
			return
		}

		// 如果订单是 active，附加证书数据
		if order.Status == "active" {
			certData := getCertDataWithOrder(order.CommonName, order.OrderID)
			certData.Domains = order.Domains // 使用订单的域名
			_ = json.NewEncoder(w).Encode(APIResponse{
				Code:    1,
				Message: "success",
				Data:    certData,
			})
		} else {
			_ = json.NewEncoder(w).Encode(APIResponse{
				Code:    1,
				Message: "success",
				Data:    order,
			})
		}
		return
	}

	// 返回所有订单列表
	var orderList []OrderData
	for _, order := range orders {
		orderList = append(orderList, *order)
	}

	_ = json.NewEncoder(w).Encode(APIResponse{
		Code:    1,
		Message: "success",
		Data:    orderList,
	})
}

func handleRenewRequest(w http.ResponseWriter, r *http.Request) {
	var req RenewRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Code: 0, Message: "Invalid request body"})
		return
	}

	log.Printf("=== Renew request received ===")
	log.Printf("  OrderID: %d", req.OrderID)
	log.Printf("  CSR: %s...", truncate(req.CSR, 50))

	ordersMutex.Lock()
	defer ordersMutex.Unlock()

	order, exists := orders[req.OrderID]
	if !exists {
		w.WriteHeader(http.StatusNotFound)
		_ = json.NewEncoder(w).Encode(APIResponse{Code: 0, Message: "Order not found"})
		return
	}

	// 模拟续签：更新订单状态
	order.Status = "active"
	order.ExpiresAt = time.Now().AddDate(0, 3, 0).Format(time.RFC3339)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(APIResponse{
		Code:    1,
		Message: "success",
		Data:    getCertData(order.CommonName),
	})
}

func handleCert(w http.ResponseWriter, r *http.Request) {
	// 检查 Authorization header
	if !checkAuth(w, r) {
		return
	}

	// 检查场景
	scenario := getScenario()
	if cfg, ok := scenarios[scenario]; ok && cfg.errorCode > 0 {
		w.WriteHeader(cfg.errorCode)
		_ = json.NewEncoder(w).Encode(APIResponse{Code: 0, Message: cfg.errorMsg})
		return
	}

	certData := getCertData(commonName)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(APIResponse{
		Code:    1,
		Message: "success",
		Data:    certData,
	})
	log.Printf("Served certificate for %s to %s", commonName, r.RemoteAddr)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(APIResponse{Code: 0, Message: "Method not allowed"})
		return
	}

	// 检查 Authorization header
	if !checkAuth(w, r) {
		return
	}

	// 解析回调请求
	var req CallbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(APIResponse{Code: 0, Message: "Invalid request body"})
		return
	}

	// 记录回调
	callbacksMutex.Lock()
	callbacks = append(callbacks, req)
	callbacksMutex.Unlock()

	log.Printf("=== Callback received ===")
	log.Printf("  Domain: %s", req.Domain)
	log.Printf("  Status: %s", req.Status)
	log.Printf("  ServerType: %s", req.ServerType)
	log.Printf("  DeployedAt: %s", req.DeployedAt)
	log.Printf("  CertExpiresAt: %s", req.CertExpiresAt)
	log.Printf("  CertSerial: %s", req.CertSerial)
	log.Printf("========================")

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(APIResponse{Code: 1, Message: "success"})
}

// ==============================================================================
// 管理端点
// ==============================================================================

func handleSetScenario(w http.ResponseWriter, r *http.Request) {
	// 提取场景名称
	parts := strings.Split(r.URL.Path, "/")
	if len(parts) < 4 {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte("Missing scenario name"))
		return
	}

	scenario := parts[3]
	if _, ok := scenarios[scenario]; !ok {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = w.Write([]byte(fmt.Sprintf("Unknown scenario: %s", scenario)))
		return
	}

	setScenario(scenario)
	log.Printf("Scenario changed to: %s", scenario)

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"status":   "ok",
		"scenario": scenario,
	})
}

func handleReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// 重置状态
	setScenario("active")

	requestLogsMutex.Lock()
	requestLogs = nil
	requestLogsMutex.Unlock()

	callbacksMutex.Lock()
	callbacks = nil
	callbacksMutex.Unlock()

	initTestOrders()

	log.Printf("State reset to default")

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleGetLogs(w http.ResponseWriter, r *http.Request) {
	requestLogsMutex.Lock()
	logs := make([]RequestLog, len(requestLogs))
	copy(logs, requestLogs)
	requestLogsMutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(logs)
}

func handleGetCallbacks(w http.ResponseWriter, r *http.Request) {
	callbacksMutex.Lock()
	cbs := make([]CallbackRequest, len(callbacks))
	copy(cbs, callbacks)
	callbacksMutex.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(cbs)
}

func handleManageOrders(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		// 列出所有订单
		ordersMutex.RLock()
		var orderList []OrderData
		for _, order := range orders {
			orderList = append(orderList, *order)
		}
		ordersMutex.RUnlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(orderList)

	case http.MethodPost:
		// 创建新订单
		var order OrderData
		if err := json.NewDecoder(r.Body).Decode(&order); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("Invalid request body"))
			return
		}

		ordersMutex.Lock()
		order.OrderID = nextOrderID
		nextOrderID++
		order.CreatedAt = time.Now().Format(time.RFC3339)
		if order.Status == "" {
			order.Status = "active"
		}
		orders[order.OrderID] = &order
		ordersMutex.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(order)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// ==============================================================================
// 辅助函数
// ==============================================================================

func checkAuth(w http.ResponseWriter, r *http.Request) bool {
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(APIResponse{Code: 0, Message: "Unauthorized"})
		return false
	}
	return true
}

func getScenario() string {
	scenarioMutex.RLock()
	defer scenarioMutex.RUnlock()
	return currentScenario
}

func setScenario(s string) {
	scenarioMutex.Lock()
	defer scenarioMutex.Unlock()
	currentScenario = s
}

func getCertData(cn string) CertData {
	return getCertDataWithOrder(cn, 1001) // 默认使用订单 1001
}

func getCertDataWithOrder(cn string, orderID int) CertData {
	scenario := getScenario()
	cfg := scenarios[scenario]

	expiresAt := time.Now().Add(cfg.expiresIn).Format(time.RFC3339)
	createdAt := time.Now().AddDate(0, -1, 0).Format(time.RFC3339)

	// 使用启动时缓存的证书内容
	return CertData{
		OrderID:          orderID,
		Status:           cfg.status,
		CommonName:       cn,
		Domain:           cn,
		Domains:          cn + ",*." + cn,
		Cert:             cachedCert,
		IntermediateCert: cachedChain,
		PrivateKey:       cachedKey,
		ExpiresAt:        expiresAt,
		CreatedAt:        createdAt,
	}
}

func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// generatedKeyPair 缓存生成的密钥对
var generatedKeyPair struct {
	cert string
	key  string
	once sync.Once
}

// generateValidSelfSignedCert 动态生成一个有效的自签名测试证书
func generateValidSelfSignedCert(cn string) string {
	generatedKeyPair.once.Do(func() {
		generateKeyPairOnce(cn)
	})
	return generatedKeyPair.cert
}

// generateValidPrivateKey 返回生成的私钥
func generateValidPrivateKey() string {
	generatedKeyPair.once.Do(func() {
		generateKeyPairOnce("test.example.com")
	})
	return generatedKeyPair.key
}

// generateKeyPairOnce 生成匹配的证书和私钥对
func generateKeyPairOnce(cn string) {
	// 生成 RSA 私钥
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Printf("Failed to generate private key: %v", err)
		return
	}

	// 创建证书模板
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test"},
			Country:      []string{"CN"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(1, 0, 0), // 1年有效期
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{cn, "*." + cn},
	}

	// 生成证书
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		log.Printf("Failed to create certificate: %v", err)
		return
	}

	// 编码证书为 PEM
	var certPEM bytes.Buffer
	pem.Encode(&certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	generatedKeyPair.cert = certPEM.String()

	// 编码私钥为 PKCS8 格式的 PEM
	pkcs8Key, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		log.Printf("Failed to marshal private key to PKCS8: %v", err)
		return
	}
	var keyPEM bytes.Buffer
	pem.Encode(&keyPEM, &pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8Key})
	generatedKeyPair.key = keyPEM.String()

	log.Printf("Generated self-signed certificate for %s", cn)
}

func generateSelfSignedCert(cn string) string {
	return generateValidSelfSignedCert(cn)
}

func generatePrivateKey() string {
	return generateValidPrivateKey()
}

func randomHex(n int) string {
	bytes := make([]byte, n)
	_, _ = rand.Read(bytes)
	return hex.EncodeToString(bytes)
}
