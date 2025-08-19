package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
	"unicode"

	authv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

const (
	// Defines how long ServiceAccount tokens are valid (1 week)
	TokenExpirationSeconds = 7 * 24 * 60 * 60
	// A target namespace that all the ServiceAccounts belong to
	TargetNamespace = "poolc-users"
	// An API endpoint with which the CronJob should interact
	PoolcApiEndpoint = "https://api.poolc.org/kubernetes/"
	// A path from which API_KEY is retrieved
	ApiKeyMountPath = "/etc/credentials-updater-secret/API_KEY"
)

type Uuid = string
type ServiceAccountToken = string
type ServiceAccountMappings = map[Uuid]ServiceAccountToken

type User struct {
	UUID    Uuid   `json:"member_uuid"`
	LoginId string `json:"login_id"`
}

type APIResponse struct {
	ActiveMembers []User `json:"activeMembers"`
}

type OperationSummary struct {
	TotalUsers int
	NumCreated int
	NumErrors  int
}

type CredentialsUpdater struct {
	clientset        *kubernetes.Clientset
	namespace        string
	poolcApiEndpoint string
	httpClient       *http.Client
	summary          *OperationSummary
}

func main() {
	namespace := os.Getenv("TARGET_NAMESPACE")
	if namespace == "" {
		namespace = TargetNamespace
	}

	poolcApiEndpoint := os.Getenv("POOLC_API_ENDPOINT")
	if poolcApiEndpoint == "" {
		poolcApiEndpoint = PoolcApiEndpoint
	}

	updater, err := NewCredentialsUpdater(namespace, poolcApiEndpoint)
	if err != nil {
		Logger.Errorf("Failed to create credentials updater: %v", err)
		os.Exit(1)
	}

	Logger.Infof("Starting credentials rotation for namespace: %s", namespace)
	Logger.Infof("Using API server: %s", poolcApiEndpoint)

	if err := updater.RotateCredentials(); err != nil {
		Logger.Errorf("Failed to rotate credentials: %v", err)
		os.Exit(1)
	}

	Logger.Infof("Credentials rotation completed!")
	Logger.Infof("Operation summary - Created: %d, Errors: %d",
		updater.summary.NumCreated,
		updater.summary.NumErrors)
}

func NewCredentialsUpdater(namespace, poolcApiEndpoint string) (*CredentialsUpdater, error) {
	// Create Kubernetes client using in-cluster config
	config, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("failed to get in-cluster config: %v", err)
	}

	clientset, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %v", err)
	}

	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	return &CredentialsUpdater{
		clientset:        clientset,
		namespace:        namespace,
		poolcApiEndpoint: poolcApiEndpoint,
		httpClient:       httpClient,
		summary:          &OperationSummary{},
	}, nil
}

func (cu *CredentialsUpdater) RotateCredentials() error {
	Logger.Infof("Starting credentials rotation process...")

	ctx := context.Background()

	// Fetch users from API
	users, err := cu.fetchUsers()
	if err != nil {
		return fmt.Errorf("failed to fetch users: %v", err)
	}

	Logger.Infof("Found %d users to process", len(users))
	cu.summary.TotalUsers = len(users)

	// Delete existing namespace (this removes all ServiceAccounts)
	if err := cu.deleteNamespace(ctx); err != nil {
		return fmt.Errorf("failed to delete namespace: %v", err)
	}

	// Recreate namespace
	if err := cu.createNamespace(ctx); err != nil {
		return fmt.Errorf("failed to recreate namespace: %v", err)
	}

	// Create ServiceAccounts for all users
	serviceAccountMap := make(ServiceAccountMappings)
	for _, user := range users {
		serviceAccountName := cu.generateServiceAccountName(user)

		if err := cu.createServiceAccount(ctx, user, serviceAccountName); err != nil {
			Logger.Errorf("Failed to create ServiceAccount for user %s: %v", user.LoginId, err)
			cu.summary.NumErrors++
			continue
		}

		// Generate token for the ServiceAccount
		token, err := cu.generateServiceAccountToken(ctx, serviceAccountName)
		if err != nil {
			Logger.Errorf("Failed to generate token for ServiceAccount %s: %v", serviceAccountName, err)
			cu.summary.NumErrors++
			continue
		}

		// Add to the map for API report
		serviceAccountMap[user.UUID] = token
		cu.summary.NumCreated++
	}

	// Send ServiceAccount mappings to API
	if err := cu.sendServiceAccountMappings(serviceAccountMap); err != nil {
		return fmt.Errorf("failed to send mappings to API: %v", err)
	}

	return nil
}

func (cu *CredentialsUpdater) fetchUsers() ([]User, error) {
	Logger.Infof("Fetching users from API: %s", cu.poolcApiEndpoint)

	req, err := http.NewRequest("GET", cu.poolcApiEndpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %v", err)
	}

	// Add API key header
	apiKey, err := getApiKeyFrom(ApiKeyMountPath)
	if err != nil {
		return nil, fmt.Errorf("faild to retrieve API key: %v", err)
	}
	req.Header.Set("X-API-KEY", apiKey)

	resp, err := cu.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to make request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("API returned status %d", resp.StatusCode)
	}

	var apiResponse APIResponse
	if err := json.NewDecoder(resp.Body).Decode(&apiResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return apiResponse.ActiveMembers, nil
}

func (cu *CredentialsUpdater) deleteNamespace(ctx context.Context) error {
	const WaitSeconds = 30

	Logger.Infof("Deleting namespace: %s", cu.namespace)

	err := cu.clientset.CoreV1().Namespaces().Delete(ctx, cu.namespace, metav1.DeleteOptions{})
	if err != nil {
		// If namespace doesn't exist, that's fine
		if errors.IsNotFound(err) {
			Logger.Infof("Namespace %s does not exist, skipping deletion", cu.namespace)
			return nil
		}
		return fmt.Errorf("failed to delete namespace: %v", err)
	}

	// Wait for namespace to be fully deleted
	Logger.Infof("Waiting for namespace %s to be deleted...", cu.namespace)
	for i := 0; i < WaitSeconds; i++ { // Wait up to `WaitSeconds` seconds
		_, err := cu.clientset.CoreV1().Namespaces().Get(ctx, cu.namespace, metav1.GetOptions{})
		if err != nil && errors.IsNotFound(err) {
			return nil
		}
		time.Sleep(1 * time.Second)
	}

	return fmt.Errorf("timeout waiting for namespace %s to be deleted", cu.namespace)
}

func (cu *CredentialsUpdater) createNamespace(ctx context.Context) error {
	Logger.Infof("Creating namespace: %s", cu.namespace)

	namespace := &corev1.Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: cu.namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "credentials-updater",
			},
		},
	}

	_, err := cu.clientset.CoreV1().Namespaces().Create(ctx, namespace, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create namespace: %v", err)
	}

	return nil
}

func (cu *CredentialsUpdater) createServiceAccount(ctx context.Context, user User, serviceAccountName string) error {
	Logger.Infof("Creating ServiceAccount: %s", serviceAccountName)

	serviceAccount := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name:      serviceAccountName,
			Namespace: cu.namespace,
			Labels: map[string]string{
				"app.kubernetes.io/managed-by": "credentials-updater",
			},
			Annotations: map[string]string{
				"credentials-updater/user-uuid":  user.UUID,
				"credentials-updater/created-at": time.Now().Format(time.RFC3339),
			},
		},
	}

	_, err := cu.clientset.CoreV1().ServiceAccounts(cu.namespace).Create(ctx, serviceAccount, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to create service account: %v", err)
	}

	return nil
}

func (cu *CredentialsUpdater) generateServiceAccountName(user User) string {
	const SuffixLen = 4
	// ServiceAccount names cannot contain uppercase letters, while user IDs
	// can contain uppercase letters and are case-sensitive (so we can't simply
	// lowercase the given `user.LoginId`). To work around this, we append the
	// last `SuffixLen` characters of the UUID to the lowercased `user.LoginId`
	// if it contains uppercase letters.
	if strings.IndexFunc(user.LoginId, unicode.IsUpper) != -1 {
		if len(user.UUID) >= SuffixLen {
			return fmt.Sprintf(
				"%s-%s", strings.ToLower(user.LoginId), user.UUID[len(user.UUID)-SuffixLen:],
			)
		}
		Logger.Warnf("Malformed UUID '%s' for user %s", user.UUID, user.LoginId)
		return fmt.Sprintf("%s-%s", strings.ToLower(user.LoginId), user.UUID)
	}
	return user.LoginId
}

func (cu *CredentialsUpdater) generateServiceAccountToken(ctx context.Context, serviceAccountName string) (string, error) {
	Logger.Infof("Generating token for ServiceAccount: %s", serviceAccountName)

	// Create a TokenRequest for the ServiceAccount
	tokenRequest := &authv1.TokenRequest{
		Spec: authv1.TokenRequestSpec{
			// A URL to talk with kube-apiserver
			Audiences: []string{"https://kubernetes.default.svc"},
			// Set token expiration to 1 week
			ExpirationSeconds: func() *int64 { i := int64(TokenExpirationSeconds); return &i }(),
		},
	}

	// Request the token from Kubernetes API
	tokenResponse, err := cu.clientset.CoreV1().ServiceAccounts(cu.namespace).CreateToken(
		ctx,
		serviceAccountName,
		tokenRequest,
		metav1.CreateOptions{},
	)
	if err != nil {
		return "", fmt.Errorf("failed to create token for ServiceAccount %s: %v", serviceAccountName, err)
	}

	return tokenResponse.Status.Token, nil
}

func (cu *CredentialsUpdater) sendServiceAccountMappings(serviceAccountMap ServiceAccountMappings) error {
	Logger.Infof("Sending service account token mappings to API: %d mappings", len(serviceAccountMap))

	// Convert map to JSON
	serviceAccountMapJson, err := json.Marshal(serviceAccountMap)
	if err != nil {
		return fmt.Errorf("failed to marshal mappings: %v", err)
	}

	// Create POST request
	req, err := http.NewRequest("POST", cu.poolcApiEndpoint, bytes.NewReader(serviceAccountMapJson))
	if err != nil {
		return fmt.Errorf("failed to create POST request: %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	// Add API key header
	apiKey, err := getApiKeyFrom(ApiKeyMountPath)
	if err != nil {
		return fmt.Errorf("faild to retrieve API key: %v", err)
	}
	req.Header.Set("X-API-KEY", apiKey)

	// Send request
	resp, err := cu.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send POST request: %v", err)
	}
	defer resp.Body.Close()

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("API returned non-success status %d", resp.StatusCode)
	}

	Logger.Infof("Sent %d service account token mappings", len(serviceAccountMap))

	return nil
}

func getApiKeyFrom(path string) (string, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("failed to read secret API key: %v", err)
	}

	apiKey := string(content)

	return apiKey, nil
}
