package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os" // 确保 os 被导入，尽管在这个版本中可能没有直接使用 os.Exit 等
	"time"

	"github.com/gin-gonic/gin"
	"github.com/lestrrat-go/jwx/v2/jwa" // 用于算法常量
	"github.com/lestrrat-go/jwx/v2/jwk" // 用于 JWK 操作，包括 jwk.WithKeyID
	"github.com/lestrrat-go/jwx/v2/jwt" // 用于 JWT 构建和签名
)

const (
	issuerURL      = "http://host.docker.internal:18080" // 修改为你 OIDC Provider 的实际地址
	privateKeyFile = "private.pem"
	publicKeyFile  = "public.pem"
	keyID          = "minio-oidc-key-2024" // 为你的密钥选择一个唯一的 ID
	tokenAudience  = "sts.amazonaws.com"   // MinIO STS 期望的默认 Audience
	minioClientID  = "minio-console-client"
	// tokenAudience = "your-custom-minio-audience" // 如果你在 MinIO 中配置了 sts_audience
)

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
	jwks       jwk.Set // JWK Set (公钥集)
)

func loadKeys() error {
	// 加载私钥
	privKeyBytes, err := ioutil.ReadFile(privateKeyFile)
	if err != nil {
		return fmt.Errorf("读取私钥文件失败 (%s): %w", privateKeyFile, err)
	}
	privBlock, _ := pem.Decode(privKeyBytes)
	if privBlock == nil {
		return fmt.Errorf("解析 PEM 块失败 (私钥)")
	}

	var parsedPrivKey interface{}
	if privBlock.Type == "RSA PRIVATE KEY" { // PKCS#1
		parsedPrivKey, err = x509.ParsePKCS1PrivateKey(privBlock.Bytes)
	} else if privBlock.Type == "PRIVATE KEY" { // PKCS#8
		parsedPrivKey, err = x509.ParsePKCS8PrivateKey(privBlock.Bytes)
	} else {
		return fmt.Errorf("不支持的私钥 PEM 类型: %s", privBlock.Type)
	}
	if err != nil {
		return fmt.Errorf("解析私钥失败: %w", err)
	}

	var ok bool
	privateKey, ok = parsedPrivKey.(*rsa.PrivateKey)
	if !ok {
		return fmt.Errorf("私钥不是 RSA 类型")
	}
	log.Println("私钥加载成功。")

	// 加载公钥
	pubKeyBytes, err := ioutil.ReadFile(publicKeyFile)
	if err != nil {
		return fmt.Errorf("读取公钥文件失败 (%s): %w", publicKeyFile, err)
	}
	pubBlock, _ := pem.Decode(pubKeyBytes)
	if pubBlock == nil || pubBlock.Type != "PUBLIC KEY" {
		return fmt.Errorf("解析 PEM 块失败 (公钥) 或类型不为 'PUBLIC KEY'")
	}
	parsedPubKey, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return fmt.Errorf("解析公钥失败: %w", err)
	}
	publicKey, ok = parsedPubKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("公钥不是 RSA 类型")
	}
	log.Println("公钥加载成功。")

	// 从公钥创建 JWK (JSON Web Key)
	jwkKey, err := jwk.FromRaw(publicKey) // 从原始公钥创建 JWK
	if err != nil {
		return fmt.Errorf("从公钥创建 JWK 失败: %w", err)
	}
	// 设置 JWK 的元数据
	// 这些元数据会出现在 /jwks 端点的响应中
	if err := jwkKey.Set(jwk.KeyIDKey, keyID); err != nil { // 设置 'kid' (Key ID)
		return fmt.Errorf("设置 JWK Key ID 失败: %w", err)
	}
	if err := jwkKey.Set(jwk.AlgorithmKey, jwa.RS256); err != nil { // 设置 'alg' (Algorithm)
		return fmt.Errorf("设置 JWK Algorithm 失败: %w", err)
	}
	if err := jwkKey.Set(jwk.KeyUsageKey, jwk.ForSignature); err != nil { // 设置 'use' (Key Usage)
		return fmt.Errorf("设置 JWK Key Usage 失败: %w", err)
	}

	// 创建 JWK Set 并添加我们的公钥
	jwks = jwk.NewSet()
	if err := jwks.AddKey(jwkKey); err != nil { // 将键添加到集合中
		return fmt.Errorf("添加 JWK 到 JWK Set 失败: %w", err)
	}
	log.Printf("JWK (公钥) 准备完毕, Key ID: %s", keyID)

	return nil
}

func main() {
	if err := loadKeys(); err != nil {
		log.Fatalf("初始化密钥失败: %v", err)
		os.Exit(1) // 确保在致命错误时退出
	}

	r := gin.Default()

	// OIDC Discovery Endpoint
	r.GET("/.well-known/openid-configuration", func(c *gin.Context) {
		config := map[string]interface{}{
			"issuer":                                issuerURL,
			"jwks_uri":                              fmt.Sprintf("%s/jwks", issuerURL),
			"response_types_supported":              []string{"id_token"},
			"subject_types_supported":               []string{"public"},
			"id_token_signing_alg_values_supported": []string{jwa.RS256.String()}, // 明确使用 jwa 包的常量
			"token_endpoint":                        fmt.Sprintf("%s/token", issuerURL),
			"scopes_supported":                      []string{"openid", "profile", "email", "groups"},
			"claims_supported":                      []string{"sub", "iss", "aud", "exp", "iat", "name", "email", "preferred_username", "groups"},
		}

		c.JSON(http.StatusOK, config)
	})

	// JWKS Endpoint (提供公钥给 MinIO 等客户端)
	r.GET("/jwks", func(c *gin.Context) {
		// jwks 对象已经构建并在 loadKeys 中填充
		jsonBytes, err := json.MarshalIndent(jwks, "", "  ") // 使用 MarshalIndent 提高可读性
		if err != nil {
			log.Printf("错误：序列化 JWKS 失败: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "无法序列化 JWKS"})
			return
		}
		c.Data(http.StatusOK, "application/json; charset=utf-8", jsonBytes)
	})

	// 简化的 Token Endpoint
	r.POST("/token", func(c *gin.Context) {
		subject := c.PostForm("subject")
		if subject == "" {
			subject = c.Query("subject") // 也允许通过查询参数传递 subject
		}
		if subject == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "请求中必须包含 'subject' 参数"})
			return
		}

		requestedAudience := c.PostForm("audience")
		if requestedAudience == "" {
			requestedAudience = c.Query("audience")
		}
		finalAudience := tokenAudience
		if requestedAudience != "" {
			finalAudience = requestedAudience
		}

		now := time.Now()
		tokenBuilder := jwt.NewBuilder().
			Issuer(issuerURL).
			Subject(subject).
			Audience([]string{finalAudience}).
			IssuedAt(now).
			Expiration(now.Add(1*time.Hour)).
			Claim("azp", minioClientID).
			Claim("name", subject).
			Claim("preferred_username", subject).
			Claim("email", subject+"@example.com")

		idToken, err := tokenBuilder.Build()
		if err != nil {
			log.Printf("错误：构建 ID Token 失败: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "构建 ID Token 失败"})
			return
		}

		// --- 开始修改：使用替代的签名方法 ---
		// 1. 从原始 privateKey 创建一个 jwk.Key 对象
		//    注意：我们在这里不直接使用全局的 publicKey 或 privateKey 变量来构建 jwk.Key
		//    而是从 rsa.PrivateKey 重新构建一个临时的 jwk.Key 用于签名。
		//    公钥的 JWK (jwks 变量中的那个) 是用于 /jwks 端点的。
		//    签名的 JWK 需要基于私钥。
		signingKey, err := jwk.FromRaw(privateKey) // 使用 privateKey 创建用于签名的 JWK
		if err != nil {
			log.Printf("错误：从 privateKey 创建签名 JWK 失败: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "准备签名密钥失败"})
			return
		}

		// 2. 在这个 jwk.Key 对象上设置 Key ID
		//    jwk.KeyIDKey 是 "kid" 的常量字符串。
		err = signingKey.Set(jwk.KeyIDKey, keyID)
		if err != nil {
			log.Printf("错误：设置签名 JWK 的 Key ID 失败: %v", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "设置签名密钥的 KID 失败"})
			return
		}
		// 可选：明确在 signingKey 上设置算法，虽然 jwt.WithKey 也会做
		// err = signingKey.Set(jwk.AlgorithmKey, jwa.RS256)
		// if err != nil { ... }

		// 3. 使用这个配置好的 jwk.Key 对象进行签名
		//    现在 jwt.WithKey 的第三个参数就不需要了，因为 'kid' 已经包含在 signingKey 对象中了。
		signedToken, err := jwt.Sign(idToken, jwt.WithKey(jwa.RS256, signingKey)) // 注意这里是 signingKey
		if err != nil {
			log.Printf("错误：使用 JWK 对象签名 ID Token 失败 (Key ID: %s): %v", keyID, err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "签名 ID Token 失败"})
			return
		}
		// --- 结束修改 ---

		log.Printf("成功为 subject '%s' 生成 ID Token, Audience: '%s'", subject, finalAudience)
		c.JSON(http.StatusOK, gin.H{
			"id_token":   string(signedToken),
			"token_type": "Bearer",
			"expires_in": int64(1 * time.Hour.Seconds()),
		})
	})

	// 健康检查端点
	r.GET("/ping", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok", "timestamp": time.Now().UTC().Format(time.RFC3339)})
	})

	port := "18080"
	log.Printf("OIDC Provider 正在启动，监听地址: %s (端口: %s)", issuerURL, port)
	log.Printf(" - OIDC Discovery: %s/.well-known/openid-configuration", issuerURL)
	log.Printf(" - JWKS URI: %s/jwks", issuerURL)
	log.Printf(" - Token Endpoint: %s/token (POST, form-data: subject=[username])", issuerURL)

	if err := r.Run(":" + port); err != nil {
		log.Fatalf("启动 Gin 服务失败: %v", err)
	}
}
