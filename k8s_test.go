package vaultk8s

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"testing"
	"time"

	vault "github.com/hashicorp/vault/api"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/net/context"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
)

const (
	// Vault
	rootToken = "90b03685-e17b-7e5e-13a0-e14e45baeb2f" //nolint:gosec // test token
	vaultAddr = "127.0.0.1:8200"
	testPath  = "secret/data/unittest"
	// Kubernetes
	namespace      = "default"
	serviceaccount = "vault-auth"
)

func TestMain(m *testing.M) {
	flag.Parse()

	code, err := run(m)

	if err != nil {
		log.Fatal(err)
	}

	os.Exit(code)
}

func TestFixAuthMountPath(t *testing.T) {
	testData := [][2]string{
		{"kubernetes", "kubernetes"},
		{"auth/kubernetes", "kubernetes"},
		{"/kubernetes", "kubernetes"},
		{"/kubernetes/", "kubernetes"},
		{"kubernetes/", "kubernetes"},
		{"auth/kubernetes/something", "kubernetes/something"},
	}

	for _, td := range testData {
		assert.Equal(t, td[1], FixAuthMountPath(td[0]))
	}
}

func TestNewVaultFromEnvironment(t *testing.T) {
	vaultTokenPath := filepath.Join(os.TempDir(), "vault-token")

	require.NoError(t, os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath))

	defer os.Remove(vaultTokenPath)

	t.Run("without minimal attributes", func(t *testing.T) {
		defer os.Setenv("VAULT_TOKEN_PATH", os.Getenv("VAULT_TOKEN_PATH"))

		require.NoError(t, os.Setenv("VAULT_TOKEN_PATH", ""))

		v, err := NewFromEnvironment()
		assert.Nil(t, v)
		assert.Error(t, err)
	})

	t.Run("with minimal attributes", func(t *testing.T) {
		defer os.Setenv("SERVICE_ACCOUNT_TOKEN_PATH", os.Getenv("SERVICE_ACCOUNT_TOKEN_PATH"))

		require.NoError(t, os.Setenv("SERVICE_ACCOUNT_TOKEN_PATH", ""))

		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		assert.Equal(t, "", v.Role)
		assert.Equal(t, vaultTokenPath, v.TokenPath)
		assert.Equal(t, false, v.ReAuth)
		assert.Equal(t, 0, v.TTL)
		assert.Equal(t, AuthMountPath, v.AuthMountPath)
		assert.Equal(t, ServiceAccountTokenPath, v.ServiceAccountTokenPath)
		assert.Equal(t, false, v.AllowFail)
	})

	t.Run("invalid VAULT_TTL", func(t *testing.T) {
		defer os.Setenv("VAULT_TTL", os.Getenv("VAULT_TTL"))

		require.NoError(t, os.Setenv("VAULT_TTL", "1std"))

		v, err := NewFromEnvironment()
		assert.Nil(t, v)
		assert.Error(t, err)
	})

	t.Run("valid VAULT_TTL", func(t *testing.T) {
		defer os.Setenv("VAULT_TTL", os.Getenv("VAULT_TTL"))

		require.NoError(t, os.Setenv("VAULT_TTL", "1h"))

		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		assert.Equal(t, 3600, v.TTL)
	})

	t.Run("invalid VAULT_REAUTH", func(t *testing.T) {
		defer os.Setenv("VAULT_REAUTH", os.Getenv("VAULT_REAUTH"))

		require.NoError(t, os.Setenv("VAULT_REAUTH", "no"))

		v, err := NewFromEnvironment()
		assert.Nil(t, v)
		assert.Error(t, err)
	})

	t.Run("valid VAULT_REAUTH", func(t *testing.T) {
		defer os.Setenv("VAULT_REAUTH", os.Getenv("VAULT_REAUTH"))

		require.NoError(t, os.Setenv("VAULT_REAUTH", "true"))

		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		assert.Equal(t, true, v.ReAuth)
	})

	t.Run("invalid ALLOW_FAIL", func(t *testing.T) {
		defer os.Setenv("ALLOW_FAIL", os.Getenv("ALLOW_FAIL"))

		require.NoError(t, os.Setenv("ALLOW_FAIL", "no"))

		v, err := NewFromEnvironment()
		assert.Nil(t, v)
		assert.Error(t, err)
	})

	t.Run("valid ALLOW_FAIL", func(t *testing.T) {
		defer os.Setenv("ALLOW_FAIL", os.Getenv("ALLOW_FAIL"))

		require.NoError(t, os.Setenv("ALLOW_FAIL", "true"))

		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		assert.Equal(t, true, v.AllowFail)
	})

	t.Run("valid LOGIN_TIMEOUT", func(t *testing.T) {
		defer os.Setenv("LOGIN_TIMEOUT", os.Getenv("LOGIN_TIMEOUT"))

		require.NoError(t, os.Setenv("LOGIN_TIMEOUT", "1h"))

		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		assert.Equal(t, 1*time.Hour, v.LoginTimeout)
	})

	t.Run("invalid LOGIN_TIMEOUT", func(t *testing.T) {
		defer os.Setenv("LOGIN_TIMEOUT", os.Getenv("LOGIN_TIMEOUT"))

		require.NoError(t, os.Setenv("LOGIN_TIMEOUT", "1"))

		v, err := NewFromEnvironment()
		assert.Nil(t, v)
		assert.Error(t, err)
	})
}

//nolint:funlen // tests
func TestToken(t *testing.T) {
	vaultTokenPath := filepath.Join(os.TempDir(), "vault-token")

	require.NoError(t, os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath))

	defer os.Remove(vaultTokenPath)

	t.Run("failed to store token", func(t *testing.T) {
		defer os.Setenv("VAULT_TOKEN_PATH", os.Getenv("VAULT_TOKEN_PATH"))

		require.NoError(t, os.Setenv("VAULT_TOKEN_PATH", "/not/existing/path"))

		v, err := NewFromEnvironment()
		assert.NoError(t, err)
		assert.NotNil(t, v)
		assert.Error(t, v.StoreToken(rootToken))
	})

	t.Run("failed to load token", func(t *testing.T) {
		defer os.Setenv("VAULT_TOKEN_PATH", os.Getenv("VAULT_TOKEN_PATH"))

		require.NoError(t, os.Setenv("VAULT_TOKEN_PATH", "/not/existing/path"))

		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		token, err := v.LoadToken()
		assert.Error(t, err)
		assert.Equal(t, "", token)
	})

	t.Run("load empty token", func(t *testing.T) {
		defer os.Remove(vaultTokenPath)

		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		require.NoError(t, v.StoreToken(""))
		token, err := v.LoadToken()
		assert.Error(t, err)
		assert.Equal(t, "", token)
	})

	t.Run("store and load token", func(t *testing.T) {
		defer os.Remove(vaultTokenPath)

		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		require.NoError(t, v.StoreToken(rootToken))
		token, err := v.LoadToken()
		assert.NoError(t, err)
		assert.Equal(t, rootToken, token)
	})

	t.Run("failed to get token without ReAuth", func(t *testing.T) {
		defer os.Remove(vaultTokenPath)
		defer os.Setenv("VAULT_REAUTH", os.Getenv("VAULT_REAUTH"))

		require.NoError(t, os.Setenv("VAULT_REAUTH", "false"))

		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		token, err := v.GetToken()
		assert.Error(t, err)
		assert.Equal(t, "", token)
	})

	t.Run("failed to renew token without ReAuth", func(t *testing.T) {
		defer os.Remove(vaultTokenPath)
		defer os.Setenv("VAULT_REAUTH", os.Getenv("VAULT_REAUTH"))

		require.NoError(t, os.Setenv("VAULT_REAUTH", "false"))

		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		require.NoError(t, v.StoreToken(rootToken))
		token, err := v.GetToken()
		assert.Error(t, err)
		assert.Equal(t, "", token)
	})

	t.Run("successful renew token without ReAuth", func(t *testing.T) {
		defer os.Remove(vaultTokenPath)
		defer os.Setenv("VAULT_REAUTH", os.Getenv("VAULT_REAUTH"))

		require.NoError(t, os.Setenv("VAULT_REAUTH", "false"))

		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		// create a new token
		v.UseToken(rootToken)
		secret, err := v.Client().Auth().Token().CreateOrphan(&vault.TokenCreateRequest{
			TTL: "3600s",
		})
		assert.NoError(t, err)
		// store the new token
		require.NoError(t, v.StoreToken(secret.Auth.ClientToken))
		// the actual test
		token, err := v.GetToken()
		assert.NoError(t, err)
		assert.Equal(t, secret.Auth.ClientToken, token)
	})
}

//nolint:funlen // tests
func TestKubernetesAuth(t *testing.T) {
	vaultTokenPath := filepath.Join(os.TempDir(), "vault-token")

	require.NoError(t, os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath))
	require.NoError(t, os.Setenv("VAULT_ROLE", "unittest"))

	defer os.Remove(vaultTokenPath)

	t.Run("failed to load service account token", func(t *testing.T) {
		defer os.Setenv("SERVICE_ACCOUNT_TOKEN_PATH", os.Getenv("SERVICE_ACCOUNT_TOKEN_PATH"))

		require.NoError(t, os.Setenv("SERVICE_ACCOUNT_TOKEN_PATH", "/not/existing/path"))

		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)

		token, err := v.Authenticate()
		assert.Error(t, err)
		assert.Empty(t, token)
	})

	t.Run("failed to authenticate without role set", func(t *testing.T) {
		defer os.Setenv("VAULT_ROLE", os.Getenv("VAULT_ROLE"))

		require.NoError(t, os.Setenv("VAULT_ROLE", ""))

		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)

		token, err := v.Authenticate()
		assert.Error(t, err)
		assert.Empty(t, token)
	})

	t.Run("successful authentication", func(t *testing.T) {
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)

		token, err := v.Authenticate()
		assert.NoError(t, err)
		assert.NotEmpty(t, token)
	})

	t.Run("CRUD with Kubernetes Auth", func(t *testing.T) {
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)

		token, err := v.Authenticate()
		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		v.client.SetToken(token)

		key := "kubernetesAuthKey"
		value := testPath

		// create secret
		inputData := map[string]interface{}{
			"data": map[string]interface{}{
				key: value,
			},
		}
		cs, err := v.client.Logical().Write(testPath, inputData)
		require.NoError(t, err)
		require.NotNil(t, cs)

		// read secret
		rs, err := v.client.Logical().Read(testPath)
		require.NoError(t, err)
		require.NotNil(t, rs)
		m, ok := rs.Data["data"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, value, m[key].(string))

		// update secret
		value = "update"
		inputData = map[string]interface{}{
			"data": map[string]interface{}{
				key: value,
			},
		}
		us, err := v.client.Logical().Write(testPath, inputData)
		require.NoError(t, err)
		require.NotNil(t, us)
		// read secret
		usr, err := v.client.Logical().Read(testPath)
		require.NoError(t, err)
		require.NotNil(t, usr)
		m, ok = usr.Data["data"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, value, m[key].(string))

		// delete secret
		ds, err := v.client.Logical().Delete(testPath)
		require.NoError(t, err)
		require.Nil(t, ds)

		// read deleted secret
		rds, err := v.client.Logical().Read(testPath)
		require.NoError(t, err)
		require.NotNil(t, rds)
		m, ok = rds.Data["data"].(map[string]interface{})
		require.False(t, ok)
	})

	t.Run("failed to get token with ReAuth", func(t *testing.T) {
		defer os.Remove(vaultTokenPath)
		defer os.Setenv("VAULT_ROLE", os.Getenv("VAULT_ROLE"))
		defer os.Setenv("VAULT_REAUTH", os.Getenv("VAULT_REAUTH"))

		require.NoError(t, os.Setenv("VAULT_ROLE", "")) // Authenticate will fail without role
		require.NoError(t, os.Setenv("VAULT_REAUTH", "true"))

		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)

		token, err := v.GetToken()
		assert.Error(t, err)
		assert.Equal(t, "", token)
	})

	t.Run("failed to renew token with ReAuth", func(t *testing.T) {
		defer os.Remove(vaultTokenPath)
		defer os.Setenv("VAULT_ROLE", os.Getenv("VAULT_ROLE"))
		defer os.Setenv("VAULT_REAUTH", os.Getenv("VAULT_REAUTH"))

		require.NoError(t, os.Setenv("VAULT_ROLE", "")) // Authenticate will fail without role
		require.NoError(t, os.Setenv("VAULT_REAUTH", "true"))

		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		require.NoError(t, v.StoreToken(rootToken))

		token, err := v.GetToken()
		assert.Error(t, err)
		assert.Equal(t, "", token)
	})
}

func TestAppRoleAuth(t *testing.T) {
	defer os.Setenv("VAULT_AUTH_MOUNT_PATH", os.Getenv("VAULT_AUTH_MOUNT_PATH"))

	vaultTokenPath := filepath.Join(os.TempDir(), "vault-token")

	defer os.Remove(vaultTokenPath)

	require.NoError(t, os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath))
	require.NoError(t, os.Setenv("VAULT_AUTH_MOUNT_PATH", "approle"))
	require.NoError(t, os.Setenv("VAULT_ROLE_ID", os.Getenv("_VAULT_ROLE_ID")))
	require.NoError(t, os.Setenv("VAULT_SECRET_ID", os.Getenv("_VAULT_SECRET_ID")))

	t.Run("AppRole auth", func(t *testing.T) {
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)

		token, err := v.Authenticate()
		assert.NoError(t, err)
		assert.NotEmpty(t, token)
	})

	t.Run("CRUD with AppRole auth", func(t *testing.T) {
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)

		token, err := v.Authenticate()
		assert.NoError(t, err)
		assert.NotEmpty(t, token)

		v.client.SetToken(token)

		key := "appRoleAuthKey"
		value := testPath

		// create secret
		inputData := map[string]interface{}{
			"data": map[string]interface{}{
				key: value,
			},
		}
		cs, err := v.client.Logical().Write(testPath, inputData)
		require.NoError(t, err)
		require.NotNil(t, cs)

		// read secret
		rs, err := v.client.Logical().Read(testPath)
		require.NoError(t, err)
		require.NotNil(t, rs)
		m, ok := rs.Data["data"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, value, m[key].(string))

		// update secret
		value = "update"
		inputData = map[string]interface{}{
			"data": map[string]interface{}{
				key: value,
			},
		}
		us, err := v.client.Logical().Write(testPath, inputData)
		require.NoError(t, err)
		require.NotNil(t, us)
		// read secret
		usr, err := v.client.Logical().Read(testPath)
		require.NoError(t, err)
		require.NotNil(t, usr)
		m, ok = usr.Data["data"].(map[string]interface{})
		require.True(t, ok)
		assert.Equal(t, value, m[key].(string))

		// delete secret
		ds, err := v.client.Logical().Delete(testPath)
		require.NoError(t, err)
		require.Nil(t, ds)

		// read deleted secret
		rds, err := v.client.Logical().Read(testPath)
		require.NoError(t, err)
		require.NotNil(t, rds)
		m, ok = rds.Data["data"].(map[string]interface{})
		require.False(t, ok)
	})
}

func TestRenew(t *testing.T) {
	vaultTokenPath := filepath.Join(os.TempDir(), "vault-token")

	require.NoError(t, os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath))
	require.NoError(t, os.Setenv("VAULT_ROLE", "unittest"))

	defer os.Remove(vaultTokenPath)

	t.Run("failed to get renewer", func(t *testing.T) {
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)

		r, err := v.NewRenewer(rootToken)
		assert.Error(t, err)
		assert.Nil(t, r)
	})

	t.Run("failed to get renewer", func(t *testing.T) {
		defer os.Setenv("VAULT_REAUTH", os.Getenv("VAULT_REAUTH"))

		require.NoError(t, os.Setenv("VAULT_REAUTH", "false"))

		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)

		// create a new token
		v.UseToken(rootToken)
		secret, err := v.Client().Auth().Token().CreateOrphan(&vault.TokenCreateRequest{
			TTL: "3600s",
		})
		assert.NoError(t, err)

		r, err := v.NewRenewer(secret.Auth.ClientToken)
		assert.NoError(t, err)
		assert.NotNil(t, r)
	})
}

// setup helper

func run(m *testing.M) (int, error) {
	code := -1

	saTokenPath := filepath.Join(os.TempDir(), "test-service-account-token")
	defer os.Remove(saTokenPath)

	k8sConfig, err := setupKubernetes(saTokenPath)
	if err != nil {
		return code, err
	}

	if err := os.Setenv("SERVICE_ACCOUNT_TOKEN_PATH", saTokenPath); err != nil {
		return code, err
	}

	if err := setupVault(k8sConfig, saTokenPath); err != nil {
		return code, err
	}

	code = m.Run()

	return code, err
}

func setupVault(k8sConfig *rest.Config, saTokenPath string) error {
	_ = os.Setenv("VAULT_ADDR", fmt.Sprintf("http://%s", vaultAddr))
	_ = os.Setenv("VAULT_TOKEN", rootToken)

	log.Printf("vault: VAULT_ADDR=%q", os.Getenv("VAULT_ADDR"))

	vaultConfig := vault.DefaultConfig()
	if err := vaultConfig.ReadEnvironment(); err != nil {
		return err
	}

	vaultClient, err := vault.NewClient(vaultConfig)
	if err != nil {
		return err
	}

	// enable AppRole Auth Method
	if err := vaultClient.Sys().EnableAuth("approle", "approle", "approle authentication"); err != nil {
		return fmt.Errorf("failed to enable AppRole auth: %w", err)
	}

	// enable Kubernetes Auth Method
	if err := vaultClient.Sys().EnableAuth("kubernetes", "kubernetes", "kubernetes authentication"); err != nil {
		return fmt.Errorf("failed to enable AppRole auth: %w", err)
	}

	// list auth methods
	auth, err := vaultClient.Sys().ListAuth()
	if err != nil {
		return fmt.Errorf("failed to list auth: %w", err)
	}

	log.Println("vault: available auth methods")
	for k, v := range auth {
		log.Printf("vault: auth method=%q path=%q", v.Description, k)
	}

	// create unittest policy
	policyName := "unittest"
	policy := `
	path %q {
		capabilities = ["create", "read", "update", "delete", "list"]
	}`

	if err := vaultClient.Sys().PutPolicy(policyName, fmt.Sprintf(policy, testPath)); err != nil {
		return fmt.Errorf("failed to create policy: %w", err)
	}

	p, err := vaultClient.Sys().GetPolicy(policyName)
	if err != nil {
		return fmt.Errorf("failed to get policy:; %w", err)
	}
	log.Printf("vault: policy=%q %s", policyName, p)

	// configure AppRole Auth Method

	// create unittest role
	roleName := policyName
	_, err = vaultClient.Logical().Write(filepath.Join("auth/approle/role", roleName), map[string]interface{}{
		"policies": policyName,
	})
	if err != nil {
		return fmt.Errorf("failed to write role: %w", err)
	}

	// read role-id
	s, err := vaultClient.Logical().Read(filepath.Join("auth/approle/role", roleName, "role-id"))
	if err != nil {
		return fmt.Errorf("failed to read role: %w", err)
	}

	_ = os.Setenv("_VAULT_ROLE_ID", s.Data["role_id"].(string))

	log.Printf("vault: role_id=%q", s.Data["role_id"].(string))

	// create and read secret-id
	s, err = vaultClient.Logical().Write(filepath.Join("auth/approle/role", roleName, "secret-id"), nil)
	if err != nil {
		return fmt.Errorf("failed to create secret_id: %w", err)
	}
	_ = os.Setenv("_VAULT_SECRET_ID", s.Data["secret_id"].(string))

	log.Printf("vault: secret_id=%q", s.Data["secret_id"].(string))

	// configure Kubernetes Auth Method
	token, err := os.ReadFile(saTokenPath)
	if err != nil {
		return fmt.Errorf("failed to read service account token: %w", err)
	}

	_, err = vaultClient.Logical().Write("auth/kubernetes/config", map[string]interface{}{
		"token_reviewer_jwt":     string(token),
		"kubernetes_host":        k8sConfig.Host,
		"kubernetes_ca_cert":     string(k8sConfig.CAData),
		"disable_iss_validation": true,
	})
	if err != nil {
		return fmt.Errorf("failed to configure Kubernetes Auth Method: %w", err)
	}

	// create named role for Kubernetes Auth Method
	roleName = policyName
	_, err = vaultClient.Logical().Write(filepath.Join("auth/kubernetes/role", roleName), map[string]interface{}{
		"bound_service_account_names":      serviceaccount,
		"bound_service_account_namespaces": namespace,
		"policies":                         policyName,
		"ttl":                              1 * time.Hour,
	})
	if err != nil {
		return fmt.Errorf("failed to write named role for Kubernetes Auth Method: %w", err)
	}

	return nil
}

func setupKubernetes(tokenfile string) (*rest.Config, error) {
	var kubeconfig *string
	if home := homedir.HomeDir(); home != "" {
		kubeconfig = flag.String("kubeconfig", filepath.Join(home, ".kube", "config"), "(optional) absolute path to the kubeconfig file")
	} else {
		kubeconfig = flag.String("kubeconfig", "", "absolute path to the kubeconfig file")
	}
	flag.Parse()

	// use the current context in kubeconfig
	config, err := clientcmd.BuildConfigFromFlags("", *kubeconfig)
	if err != nil {
		return nil, err
	}

	cs, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, err
	}

	log.Printf("k8s: namespace=%q serviceaccount=%q", namespace, serviceaccount)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	sa, err := cs.CoreV1().ServiceAccounts(namespace).Get(ctx, serviceaccount, metav1.GetOptions{})
	if err != nil {
		return nil, err
	}

	for _, o := range sa.Secrets {
		log.Printf("k8s: secret=%q", o.Name)
		s, err := cs.CoreV1().Secrets(namespace).Get(ctx, o.Name, metav1.GetOptions{})
		if err != nil {
			log.Println("ERROR:", err)

			continue
		}

		t, ok := s.Data["token"]
		if !ok {
			log.Println("ERROR:", fmt.Errorf("token not found"))

			continue
		}

		return config, os.WriteFile(tokenfile, t, 0o600)
	}

	return nil, fmt.Errorf("no access token for service account %s in namespace %s found", serviceaccount, namespace)
}
