package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

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
	TargetNamespace = "user-credentials"
	// An API endpoint with which the CronJob should interact
	PoolcApiEndpoint = "dev.poolc.org:8080/kubernetes/"
)

type Uuid = string
type ServiceAccountToken = string
type ServiceAccountMappings = map[Uuid]ServiceAccountToken

type User struct {
	UUID Uuid
}

type APIResponse struct {
	ActiveMembers []string `json:"activeMembers"`
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

// TODO: Bind ClusterRole to each ServiceAccount
// TODO: Rotate only ServiceAccounts to preserve Secret that contains API key
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

	Logger.Infof("Operation summary - Created: %d, Errors: %d",
		updater.summary.NumCreated,
		updater.summary.NumErrors)
	Logger.Infof("Credentials rotation completed successfully")
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
		serviceAccountName := cu.generateServiceAccountName(user.UUID)

		if err := cu.createServiceAccount(ctx, user, serviceAccountName); err != nil {
			Logger.Errorf("Failed to create ServiceAccount for user %s: %v", user.UUID, err)
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
		Logger.Infof("Successfully created ServiceAccount and token for user: %s", user.UUID)
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
	apiKey, err := getApiKeyFromEnv()
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

	// Convert UUIDs to User objects
	users := make([]User, 0, len(apiResponse.ActiveMembers))
	for _, uuid := range apiResponse.ActiveMembers {
		user := User{
			UUID: uuid,
		}
		users = append(users, user)
	}

	return users, nil
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
			Logger.Infof("Namespace %s successfully deleted", cu.namespace)
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

	Logger.Infof("Successfully created namespace: %s", cu.namespace)
	return nil
}

func (cu *CredentialsUpdater) createServiceAccount(ctx context.Context, user User, serviceAccountName string) error {
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

	Logger.Infof("Created ServiceAccount: %s", serviceAccountName)
	return nil
}

func (cu *CredentialsUpdater) generateServiceAccountName(uuid string) string {
	return fmt.Sprintf("user-%s", uuid)
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

	Logger.Infof("Successfully generated token for ServiceAccount: %s", serviceAccountName)
	return tokenResponse.Status.Token, nil
}

func (cu *CredentialsUpdater) sendServiceAccountMappings(serviceAccountMap ServiceAccountMappings) error {
	Logger.Infof("Sending service account token mappings to API: %d mappings", len(serviceAccountMap))

	// Convert map to JSON
	reportJSON, err := json.Marshal(serviceAccountMap)
	if err != nil {
		return fmt.Errorf("failed to marshal mappings: %v", err)
	}

	// Create POST request
	req, err := http.NewRequest("POST", cu.poolcApiEndpoint, bytes.NewReader(reportJSON))
	if err != nil {
		return fmt.Errorf("failed to create POST request: %v", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")

	// Add API key header
	apiKey, err := getApiKeyFromEnv()
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

	Logger.Infof("Successfully sent mappings to API (status: %d)", resp.StatusCode)
	Logger.Infof("Sent %d service account token mappings", len(serviceAccountMap))

	return nil
}

func getApiKeyFromEnv() (string, error) {
	apiKey := os.Getenv("API_KEY")
	if apiKey == "" {
		return "", fmt.Errorf("API_KEY environment variable is required for sending mappings")
	}
	return apiKey, nil
}
