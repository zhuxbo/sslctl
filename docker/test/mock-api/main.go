// 模拟证书 API 服务器
// 用于测试证书部署流程
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
)

type FileChallenge struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type CertData struct {
	Status           string         `json:"status"`
	CommonName       string         `json:"common_name"`
	Cert             string         `json:"cert"`
	IntermediateCert string         `json:"intermediate_cert"`
	PrivateKey       string         `json:"private_key"`
	ExpiresAt        string         `json:"expires_at"`
	File             *FileChallenge `json:"file,omitempty"`
}

type APIResponse struct {
	Code    int      `json:"code"`
	Message string   `json:"msg"`
	Data    CertData `json:"data"`
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

// CallbackResponse 回调响应
type CallbackResponse struct {
	Code    int    `json:"code"`
	Message string `json:"msg"`
}

var (
	certFile    string
	keyFile     string
	chainFile   string
	commonName  string
)

func main() {
	port := flag.Int("port", 8080, "API 服务端口")
	flag.StringVar(&certFile, "cert", "", "证书文件路径")
	flag.StringVar(&keyFile, "key", "", "私钥文件路径")
	flag.StringVar(&chainFile, "chain", "", "中间证书文件路径")
	flag.StringVar(&commonName, "cn", "example.com", "证书 CommonName")
	flag.Parse()

	http.HandleFunc("/api/cert", handleCert)
	http.HandleFunc("/api/callback", handleCallback)
	http.HandleFunc("/health", handleHealth)

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Mock API server starting on %s", addr)
	log.Printf("Cert: %s, Key: %s, Chain: %s", certFile, keyFile, chainFile)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func handleHealth(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("OK"))
}

func handleCert(w http.ResponseWriter, r *http.Request) {
	// 检查 Authorization header
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(APIResponse{Code: 0, Message: "Unauthorized"})
		return
	}

	// 读取证书文件
	cert, err := os.ReadFile(certFile)
	if err != nil {
		log.Printf("Error reading cert file: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Code: 0, Message: "Failed to read cert"})
		return
	}

	key, err := os.ReadFile(keyFile)
	if err != nil {
		log.Printf("Error reading key file: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		_ = json.NewEncoder(w).Encode(APIResponse{Code: 0, Message: "Failed to read key"})
		return
	}

	var chain []byte
	if chainFile != "" {
		chain, _ = os.ReadFile(chainFile)
	}

	resp := APIResponse{
		Code:    1,
		Message: "success",
		Data: CertData{
			Status:           "active",
			CommonName:       commonName,
			Cert:             string(cert),
			IntermediateCert: string(chain),
			PrivateKey:       string(key),
			ExpiresAt:        "2026-12-18T00:00:00Z",
		},
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(resp)
	log.Printf("Served certificate for %s to %s", commonName, r.RemoteAddr)
}

func handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		_ = json.NewEncoder(w).Encode(CallbackResponse{Code: 0, Message: "Method not allowed"})
		return
	}

	// 检查 Authorization header
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer ") {
		w.WriteHeader(http.StatusUnauthorized)
		_ = json.NewEncoder(w).Encode(CallbackResponse{Code: 0, Message: "Unauthorized"})
		return
	}

	// 解析回调请求
	var req CallbackRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_ = json.NewEncoder(w).Encode(CallbackResponse{Code: 0, Message: "Invalid request body"})
		return
	}

	log.Printf("=== Callback received ===")
	log.Printf("  Domain: %s", req.Domain)
	log.Printf("  Status: %s", req.Status)
	log.Printf("  ServerType: %s", req.ServerType)
	log.Printf("  DeployedAt: %s", req.DeployedAt)
	log.Printf("  CertExpiresAt: %s", req.CertExpiresAt)
	log.Printf("  CertSerial: %s", req.CertSerial)
	log.Printf("========================")

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(CallbackResponse{Code: 1, Message: "success"})
}
