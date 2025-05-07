package main

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	oidcTokenURL     = "http://localhost:18080/token" // 你的 OIDC Provider 的 Token 端点
	oidcSubject      = "testuser-from-sts-client"     // 用于获取 ID Token 的 subject (用户名)
	minioSTSEndpoint = "http://localhost:9000"        // 你的 MinIO S3/STS 端点
	// roleArn          = "arn:aws:iam:::role/some-minio-role" // 对于 MinIO 通常是占位符，实际角色由 token sub 决定
	roleArn         = ""
	roleSessionName = "minio-webidentity-session"
	durationSeconds = "3600" // 临时凭证有效期 (1小时)
)

// OIDC Token 响应结构体
type OIDCTokenResponse struct {
	IDToken      string `json:"id_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"` // 可选
	Scope        string `json:"scope,omitempty"`         // 可选
}

// MinIO (AWS STS兼容) AssumeRoleWithWebIdentity 响应的 XML 结构体
type AssumeRoleWithWebIdentityResponse struct {
	XMLName                         xml.Name                        `xml:"AssumeRoleWithWebIdentityResponse"`
	AssumeRoleWithWebIdentityResult AssumeRoleWithWebIdentityResult `xml:"AssumeRoleWithWebIdentityResult"`
	ResponseMetadata                ResponseMetadata                `xml:"ResponseMetadata"`
}

type AssumeRoleWithWebIdentityResult struct {
	Credentials                 Credentials     `xml:"Credentials"`
	AssumedRoleUser             AssumedRoleUser `xml:"AssumedRoleUser"`
	Audience                    string          `xml:"Audience,omitempty"`                    // MinIO 可能会返回 audience
	ProviderId                  string          `xml:"ProviderId,omitempty"`                  // MinIO 可能会返回 OIDC provider 的 issuer
	SubjectFromWebIdentityToken string          `xml:"SubjectFromWebIdentityToken,omitempty"` // Token 中的 subject
}

type Credentials struct {
	AccessKeyId     string    `xml:"AccessKeyId"`
	SecretAccessKey string    `xml:"SecretAccessKey"`
	SessionToken    string    `xml:"SessionToken"`
	Expiration      time.Time `xml:"Expiration"`
}

type AssumedRoleUser struct {
	Arn           string `xml:"Arn"`
	AssumedRoleId string `xml:"AssumedRoleId"`
}

type ResponseMetadata struct {
	RequestId string `xml:"RequestId"`
}

// 1. 从 OIDC Provider 获取 ID Token
func getIDToken() (string, error) {
	log.Printf("正在从 %s 获取 ID Token，subject: %s\n", oidcTokenURL, oidcSubject)

	resp, err := http.PostForm(oidcTokenURL, url.Values{
		"subject": {oidcSubject},
		// 如果你的 OIDC provider 需要 client_id 和 client_secret (对于简化的 token 端点可能不需要)
		// "client_id": {"my-sts-client"},
		// "grant_type": {"password"}, // 或其他合适的 grant type
	})
	if err != nil {
		return "", fmt.Errorf("请求 OIDC Token 失败: %w", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取 OIDC Token 响应体失败: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OIDC Token 请求失败，状态码: %d, 响应: %s", resp.StatusCode, string(body))
	}

	var tokenResponse OIDCTokenResponse
	if err := json.Unmarshal(body, &tokenResponse); err != nil {
		return "", fmt.Errorf("解析 OIDC Token JSON 响应失败: %w. 响应体: %s", err, string(body))
	}

	if tokenResponse.IDToken == "" {
		return "", fmt.Errorf("从 OIDC Provider 获取的 ID Token 为空。响应体: %s", string(body))
	}

	log.Println("成功获取 ID Token。")
	return tokenResponse.IDToken, nil
}

// 2. 使用 ID Token 调用 MinIO STS AssumeRoleWithWebIdentity
func assumeRoleWithMinIO(idToken string) (*AssumeRoleWithWebIdentityResponse, string, error) {
	log.Printf("正在使用 ID Token 调用 MinIO STS (%s)...\n", minioSTSEndpoint)

	form := url.Values{}
	form.Add("Action", "AssumeRoleWithWebIdentity")
	form.Add("Version", "2011-06-15") // AWS STS API 版本
	form.Add("WebIdentityToken", idToken)
	form.Add("RoleArn", roleArn)
	form.Add("RoleSessionName", roleSessionName)
	form.Add("DurationSeconds", durationSeconds)
	// 如果MinIO配置了sts_audience，并且它与ID Token中的aud不匹配，
	// MinIO将拒绝。我们的OIDC provider ID Token中的aud默认为 "sts.amazonaws.com"
	// 或者在获取token时可以指定 audience 参数给 /token 端点
	// form.Add("Audience", "minio-client") // 如果需要

	// MinIO STS 端点通常与 S3 端点相同
	// 注意：AWS CLI 使用 HTTP GET 并将参数放在查询字符串中，
	// 但标准的 STS API 也接受 POST application/x-www-form-urlencoded
	resp, err := http.PostForm(minioSTSEndpoint, form)
	if err != nil {
		return nil, "", fmt.Errorf("请求 MinIO STS 失败: %w", err)
	}
	defer resp.Body.Close()

	responseBodyBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, "", fmt.Errorf("读取 MinIO STS 响应体失败: %w", err)
	}
	responseBodyString := string(responseBodyBytes)

	if resp.StatusCode != http.StatusOK {
		return nil, responseBodyString, fmt.Errorf("MinIO STS 请求失败，状态码: %d", resp.StatusCode)
	}

	var stsResponse AssumeRoleWithWebIdentityResponse
	if err := xml.Unmarshal(responseBodyBytes, &stsResponse); err != nil {
		return nil, responseBodyString, fmt.Errorf("解析 MinIO STS XML 响应失败: %w", err)
	}

	log.Println("成功从 MinIO STS 获取临时凭证。")
	return &stsResponse, responseBodyString, nil
}

func main() {
	// 确保 OIDC Provider 和 MinIO 正在运行并已正确配置
	// 特别是 MinIO 需要配置 identity_openid 指向 http://localhost:8080
	// 并且需要有一个名为 `oidcSubject` (即 "testuser-from-sts-client") 的 IAM策略/用户
	// 例如: mc admin policy create myminio testuser-from-sts-client testuser-policy.json
	//       mc admin policy attach myminio testuser-from-sts-client --user testuser-from-sts-client

	r := gin.Default()

	r.GET("/get-temp-credentials", func(c *gin.Context) {
		// 步骤 1: 获取 ID Token
		idToken, err := getIDToken()
		if err != nil {
			log.Printf("错误：获取 ID Token 失败: %v\n", err)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":   "获取 ID Token 失败",
				"details": err.Error(),
			})
			return
		}

		// 步骤 2: Assume Role
		stsResponse, rawSTSResponseBody, err := assumeRoleWithMinIO(idToken)
		if err != nil {
			log.Printf("错误：AssumeRoleWithWebIdentity 失败: %v\n原始响应: %s\n", err, rawSTSResponseBody)
			c.JSON(http.StatusInternalServerError, gin.H{
				"error":          "AssumeRoleWithWebIdentity 失败",
				"details":        err.Error(),
				"id_token_used":  idToken, // 包含它以便调试
				"sts_raw_output": rawSTSResponseBody,
			})
			return
		}

		log.Println("成功获取临时凭证！")
		c.JSON(http.StatusOK, gin.H{
			"message":               "成功获取临时凭证",
			"id_token":              idToken,
			"sts_response_parsed":   stsResponse,
			"sts_response_raw_xml":  rawSTSResponseBody, // 返回原始XML以便调试
			"temporary_credentials": stsResponse.AssumeRoleWithWebIdentityResult.Credentials,
			"how_to_use_aws_cli": fmt.Sprintf(
				"aws configure set aws_access_key_id %s --profile temp_minio_user && "+
					"aws configure set aws_secret_access_key %s --profile temp_minio_user && "+
					"aws configure set aws_session_token %s --profile temp_minio_user && "+
					"aws configure set region us-east-1 --profile temp_minio_user && "+ // MinIO 通常不关心 region
					"aws s3 ls --endpoint-url %s --profile temp_minio_user",
				stsResponse.AssumeRoleWithWebIdentityResult.Credentials.AccessKeyId,
				stsResponse.AssumeRoleWithWebIdentityResult.Credentials.SecretAccessKey,
				stsResponse.AssumeRoleWithWebIdentityResult.Credentials.SessionToken,
				minioSTSEndpoint,
			),
		})
	})

	port := "8081" // 在不同于OIDC provider的端口上运行
	log.Printf("STS 测试客户端正在监听 http://localhost:%s\n", port)
	log.Printf("访问 http://localhost:%s/get-temp-credentials 来测试。\n", port)
	if err := r.Run(":" + port); err != nil {
		log.Fatalf("启动 Gin STS 客户端失败: %v", err)
	}
}
