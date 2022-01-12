package vaultk8s

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"
	"testing"
	"time"

	vault "github.com/hashicorp/vault/api"
	"github.com/ory/dockertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	rootToken = "90b03685-e17b-7e5e-13a0-e14e45baeb2f" //nolint:gosec // test token
)

func TestMain(m *testing.M) {
	flag.Parse()

	cleanup, err := setupVault()
	if err != nil {
		cleanup()
		log.Fatal(err)
	}

	code := m.Run()

	cleanup()

	os.Exit(code)
}

func setupVault() (func(), error) {
	cleanup := func() {}

	pool, err := dockertest.NewPool("unix:///var/run/docker.sock")
	if err != nil {
		return cleanup, fmt.Errorf("Could not connect to docker: %w", err)
	}

	// pulls an image, creates a container based on it and runs it
	resource, err := pool.Run("vault", "latest", []string{
		"VAULT_DEV_ROOT_TOKEN_ID=" + rootToken,
		"VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200",
	})
	if err != nil {
		return cleanup, fmt.Errorf("Could not start resource: %w", err)
	}

	cleanup = func() {
		if err := pool.Purge(resource); err != nil {
			log.Printf("could not purge resource: %v", err)
		}
	}

	host := os.Getenv("DOCKER_HOST")
	if host == "" {
		host = "localhost"
	}

	if host != "localhost" && !strings.Contains(host, ".") {
		host += ".pnet.ch"
	}

	vaultAddr := fmt.Sprintf("http://%s:%s", host, resource.GetPort("8200/tcp"))

	_ = os.Setenv("VAULT_ADDR", vaultAddr)
	_ = os.Setenv("VAULT_TOKEN", rootToken)

	fmt.Println("VAULT_ADDR:", vaultAddr)

	vaultConfig := vault.DefaultConfig()
	if err := vaultConfig.ReadEnvironment(); err != nil {
		return cleanup, err
	}

	vaultClient, err := vault.NewClient(vaultConfig)
	if err != nil {
		return cleanup, err
	}

	// exponential backoff-retry, because the application in the container might not be ready to accept connections yet
	if err := pool.Retry(func() error {
		_, err = vaultClient.Sys().ListMounts()
		return err
	}); err != nil {
		return cleanup, fmt.Errorf("could not connect to vault in docker: %w", err)
	}

	// enable approle auth method
	if err := vaultClient.Sys().EnableAuth("approle", "approle", "approle authentication"); err != nil {
		return cleanup, fmt.Errorf("failed to enable AppRole auth: %w", err)
	}

	// enable kubernetes auth method
	if err := vaultClient.Sys().EnableAuth("kubernetes", "kubernetes", "kubernetes authentication"); err != nil {
		return cleanup, fmt.Errorf("failed to enable AppRole auth: %w", err)
	}

	// list auth methods
	auth, err := vaultClient.Sys().ListAuth()
	if err != nil {
		return cleanup, fmt.Errorf("failed to list auth: %w", err)
	}

	log.Println("available auth methods")
	for k, v := range auth {
		log.Println("path:", k, "desc:", v.Description)
	}

	// create unittest policy
	policy := `
	path "secret/unittest" {
		capabilities = ["create", "read", "update", "delete", "list"]
	   }
	`
	if err := vaultClient.Sys().PutPolicy("unittest", policy); err != nil {
		return cleanup, fmt.Errorf("failed to create policy: %w", err)
	}

	// create uinttest role
	_, err = vaultClient.Logical().Write("auth/approle/role/unittest", map[string]interface{}{
		"secret_id_ttl": 300 * time.Second,
		"token_ttl":     300 * time.Second,
		"token_max_tll": 300 * time.Second,
		"policies":      "unittest",
	})
	if err != nil {
		return cleanup, fmt.Errorf("failed to write role: %w", err)
	}

	// read role-id
	s, err := vaultClient.Logical().Read("auth/approle/role/unittest/role-id")
	if err != nil {
		return cleanup, fmt.Errorf("failed to read role: %w", err)
	}
	_ = os.Setenv("_VAULT_ROLE_ID", s.Data["role_id"].(string))

	log.Println("role_id", s.Data["role_id"].(string))

	// create and read secret-id
	s, err = vaultClient.Logical().Write("auth/approle/role/unittest/secret-id", nil)
	if err != nil {
		return cleanup, fmt.Errorf("failed to create secret_id: %w", err)
	}
	_ = os.Setenv("_VAULT_SECRET_ID", s.Data["secret_id"].(string))

	log.Println("secret_id", s.Data["secret_id"].(string))

	return cleanup, nil
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
	vaultTokenPath, err := ioutil.TempFile("", "vault-token")
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove(vaultTokenPath.Name())

	t.Run("without minimal attributes", func(t *testing.T) {
		v, err := NewFromEnvironment()
		assert.Nil(t, v)
		assert.Error(t, err)
	})

	t.Run("with minimal attributes", func(t *testing.T) {
		_ = os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		assert.Equal(t, "", v.Role)
		assert.Equal(t, vaultTokenPath.Name(), v.TokenPath)
		assert.Equal(t, false, v.ReAuth)
		assert.Equal(t, 0, v.TTL)
		assert.Equal(t, AuthMountPath, v.AuthMountPath)
		assert.Equal(t, ServiceAccountTokenPath, v.ServiceAccountTokenPath)
		assert.Equal(t, false, v.AllowFail)
	})

	t.Run("invalid VAULT_TTL", func(t *testing.T) {
		_ = os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		_ = os.Setenv("VAULT_TTL", "1std")
		defer os.Setenv("VAULT_TTL", "")
		v, err := NewFromEnvironment()
		assert.Nil(t, v)
		assert.Error(t, err)
	})

	t.Run("valid VAULT_TTL", func(t *testing.T) {
		_ = os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		_ = os.Setenv("VAULT_TTL", "1h")
		defer os.Setenv("VAULT_TTL", "")
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		assert.Equal(t, 3600, v.TTL)
	})

	t.Run("invalid VAULT_REAUTH", func(t *testing.T) {
		_ = os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		_ = os.Setenv("VAULT_REAUTH", "no")
		defer os.Setenv("VAULT_REAUTH", "")
		v, err := NewFromEnvironment()
		assert.Nil(t, v)
		assert.Error(t, err)
	})

	t.Run("valid VAULT_REAUTH", func(t *testing.T) {
		_ = os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		_ = os.Setenv("VAULT_REAUTH", "true")
		defer os.Setenv("VAULT_REAUTH", "")
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		assert.Equal(t, true, v.ReAuth)
	})

	t.Run("invalid ALLOW_FAIL", func(t *testing.T) {
		_ = os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		_ = os.Setenv("ALLOW_FAIL", "no")
		defer os.Setenv("ALLOW_FAIL", "")
		v, err := NewFromEnvironment()
		assert.Nil(t, v)
		assert.Error(t, err)
	})

	t.Run("valid ALLOW_FAIL", func(t *testing.T) {
		_ = os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		_ = os.Setenv("ALLOW_FAIL", "true")
		defer os.Setenv("ALLOW_FAIL", "")
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		assert.Equal(t, true, v.AllowFail)
	})

	t.Run("valid LOGIN_TIMEOUT", func(t *testing.T) {
		_ = os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		_ = os.Setenv("LOGIN_TIMEOUT", "1h")
		defer os.Setenv("LOGIN_TIMEOUT", "")
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		assert.Equal(t, 1*time.Hour, v.LoginTimeout)
	})

	t.Run("invalid LOGIN_TIMEOUT", func(t *testing.T) {
		_ = os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		_ = os.Setenv("LOGIN_TIMEOUT", "1")
		defer os.Setenv("LOGIN_TIMEOUT", "")
		v, err := NewFromEnvironment()
		assert.Nil(t, v)
		assert.Error(t, err)
	})
}

//nolint:funlen // tests
func TestToken(t *testing.T) {
	t.Run("failed to store token", func(t *testing.T) {
		_ = os.Setenv("VAULT_TOKEN_PATH", "/not/existing/path")
		v, err := NewFromEnvironment()
		assert.NoError(t, err)
		assert.NotNil(t, v)
		assert.Error(t, v.StoreToken(rootToken))
	})

	t.Run("failed to load token", func(t *testing.T) {
		_ = os.Setenv("VAULT_TOKEN_PATH", "/not/existing/path")
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		token, err := v.LoadToken()
		assert.Error(t, err)
		assert.Equal(t, "", token)
	})

	t.Run("load empty token", func(t *testing.T) {
		vaultTokenPath, err := ioutil.TempFile("", "vault-token")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(vaultTokenPath.Name())
		_ = os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		require.NoError(t, v.StoreToken(""))
		token, err := v.LoadToken()
		assert.Error(t, err)
		assert.Equal(t, "", token)
	})

	t.Run("store and load token", func(t *testing.T) {
		vaultTokenPath, err := ioutil.TempFile("", "vault-token")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(vaultTokenPath.Name())
		_ = os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		require.NoError(t, v.StoreToken(rootToken))
		token, err := v.LoadToken()
		assert.NoError(t, err)
		assert.Equal(t, rootToken, token)
	})

	t.Run("failed to get token without ReAuth", func(t *testing.T) {
		vaultTokenPath, err := ioutil.TempFile("", "vault-token")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(vaultTokenPath.Name())
		_ = os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		_ = os.Setenv("VAULT_REAUTH", "false")
		defer os.Setenv("VAULT_REAUTH", "")
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		token, err := v.GetToken()
		assert.Error(t, err)
		assert.Equal(t, "", token)
	})

	t.Run("failed to renew token without ReAuth", func(t *testing.T) {
		vaultTokenPath, err := ioutil.TempFile("", "vault-token")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(vaultTokenPath.Name())
		_ = os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		_ = os.Setenv("VAULT_REAUTH", "false")
		defer os.Setenv("VAULT_REAUTH", "")
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		require.NoError(t, v.StoreToken(rootToken))
		token, err := v.GetToken()
		assert.Error(t, err)
		assert.Equal(t, "", token)
	})

	t.Run("successful renew token without ReAuth", func(t *testing.T) {
		vaultTokenPath, err := ioutil.TempFile("", "vault-token")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(vaultTokenPath.Name())
		_ = os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		_ = os.Setenv("VAULT_REAUTH", "false")
		defer os.Setenv("VAULT_REAUTH", "")
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
	vaultTokenPath, err := ioutil.TempFile("", "vault-token")
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove(vaultTokenPath.Name())

	serviceAccountTokenPath, err := ioutil.TempFile("", "sa-token")
	if err != nil {
		t.Fatal(err)
	}

	defer os.Remove(serviceAccountTokenPath.Name())

	t.Run("failed to load service account token", func(t *testing.T) {
		_ = os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		_ = os.Setenv("SERVICE_ACCOUNT_TOKEN_PATH", "/not/existing/path")
		defer os.Setenv("SERVICE_ACCOUNT_TOKEN_PATH", "")
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		token, err := v.Authenticate()
		assert.Error(t, err)
		assert.Equal(t, "", token)
	})

	t.Run("failed authentication", func(t *testing.T) {
		_ = os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		_ = os.Setenv("SERVICE_ACCOUNT_TOKEN_PATH", serviceAccountTokenPath.Name())
		defer os.Setenv("SERVICE_ACCOUNT_TOKEN_PATH", "")
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		token, err := v.Authenticate()
		assert.Error(t, err)
		assert.Equal(t, "", token)
	})
	/*
		t.Run("successful authentication", func(t *testing.T) {
			_ = os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
			_ = os.Setenv("SERVICE_ACCOUNT_TOKEN_PATH", serviceAccountTokenPath.Name())
			defer os.Setenv("SERVICE_ACCOUNT_TOKEN_PATH", "")
			v, err := NewFromEnvironment()
			assert.NotNil(t, v)
			assert.NoError(t, err)
			token, err := v.Authenticate()
			assert.NoError(t, err)
			assert.Equal(t, rootToken, token)
		})

		t.Run("failed authentication with warnings", func(t *testing.T) {
			_ = os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
			_ = os.Setenv("SERVICE_ACCOUNT_TOKEN_PATH", serviceAccountTokenPath.Name())
			defer os.Setenv("SERVICE_ACCOUNT_TOKEN_PATH", "")
			v, err := NewFromEnvironment()
			assert.NotNil(t, v)
			assert.NoError(t, err)
			vaultLogicalBackup := vaultLogical
			vaultLogical = func(c *vault.Client) vaultLogicalWriter {
				return &fakeWriterWithWarnings{}
			}
			defer func() { vaultLogical = vaultLogicalBackup }()
			token, err := v.Authenticate()
			assert.Error(t, err)
			assert.Equal(t, "", token)
		})
	*/
	t.Run("failed to get token with ReAuth", func(t *testing.T) {
		vaultTokenPath, err := ioutil.TempFile("", "vault-token")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(vaultTokenPath.Name())
		_ = os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		_ = os.Setenv("VAULT_REAUTH", "true")
		defer os.Setenv("VAULT_REAUTH", "")
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		token, err := v.GetToken()
		assert.Error(t, err)
		assert.Equal(t, "", token)
	})

	t.Run("failed to renew token with ReAuth", func(t *testing.T) {
		vaultTokenPath, err := ioutil.TempFile("", "vault-token")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(vaultTokenPath.Name())
		_ = os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		_ = os.Setenv("VAULT_REAUTH", "true")
		defer os.Setenv("VAULT_REAUTH", "")
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
	vaultTokenPath, err := ioutil.TempFile("", "vault-token")
	if err != nil {
		t.Fatal(err)
	}

	_ = os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
	_ = os.Setenv("VAULT_AUTH_MOUNT_PATH", "approle")
	_ = os.Setenv("VAULT_ROLE_ID", os.Getenv("_VAULT_ROLE_ID"))
	_ = os.Setenv("VAULT_SECRET_ID", os.Getenv("_VAULT_SECRET_ID"))

	defer os.Setenv("VAULT_AUTH_MOUNT_PATH", "")

	t.Run("", func(t *testing.T) {
		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		token, err := v.Authenticate()
		assert.NoError(t, err)
		assert.NotEmpty(t, token)
	})
}

func TestRenew(t *testing.T) {
	t.Run("failed to get renewer", func(t *testing.T) {
		vaultTokenPath, err := ioutil.TempFile("", "vault-token")
		if err != nil {
			t.Fatal(err)
		}

		defer os.Remove(vaultTokenPath.Name())

		_ = os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())

		v, err := NewFromEnvironment()
		assert.NotNil(t, v)
		assert.NoError(t, err)
		// the actual test
		r, err := v.NewRenewer(rootToken)
		assert.Error(t, err)
		assert.Nil(t, r)
	})

	t.Run("failed to get renewer", func(t *testing.T) {
		vaultTokenPath, err := ioutil.TempFile("", "vault-token")
		if err != nil {
			t.Fatal(err)
		}
		defer os.Remove(vaultTokenPath.Name())
		_ = os.Setenv("VAULT_TOKEN_PATH", vaultTokenPath.Name())
		_ = os.Setenv("VAULT_REAUTH", "false")
		defer os.Setenv("VAULT_REAUTH", "")
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
