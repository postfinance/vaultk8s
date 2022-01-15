// Package vaultk8s provides authentication with Vault on Kubernetes
package vaultk8s

import (
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	vault "github.com/hashicorp/vault/api"
)

// Constants
const (
	AuthMountPath           = "kubernetes"
	ServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token" //nolint: gosec // not the token
	DefaultTimeout          = 30 * time.Second
)

// Vault represents the configuration to get a valid Vault token
type Vault struct {
	// approle auth
	RoleID   string
	SecretID string

	// kubernetes auth
	Role                    string
	ServiceAccountTokenPath string

	TokenPath     string
	AuthMountPath string
	TTL           int

	ReAuth    bool
	AllowFail bool

	LoginTimeout time.Duration

	authenticate Authenticate
	client       *vault.Client
}

// NewFromEnvironment returns a initialized Vault type for authentication
func NewFromEnvironment() (*Vault, error) {
	v := &Vault{
		authenticate: func() (string, error) {
			return "", fmt.Errorf("authenticate function not defined")
		},
	}

	v.RoleID = os.Getenv("VAULT_ROLE_ID")
	v.SecretID = os.Getenv("VAULT_SECRET_ID")

	v.Role = os.Getenv("VAULT_ROLE")

	v.ServiceAccountTokenPath = os.Getenv("SERVICE_ACCOUNT_TOKEN_PATH")
	if v.ServiceAccountTokenPath == "" {
		v.ServiceAccountTokenPath = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	}

	v.TokenPath = os.Getenv("VAULT_TOKEN_PATH")
	if v.TokenPath == "" {
		return nil, fmt.Errorf("missing VAULT_TOKEN_PATH")
	}

	v.AuthMountPath = FixAuthMountPath(AuthMountPath) // use default
	if p := os.Getenv("VAULT_AUTH_MOUNT_PATH"); p != "" {
		v.AuthMountPath = FixAuthMountPath(p) // if set, use value from environment
	}

	if s := os.Getenv("VAULT_TTL"); s != "" {
		d, err := time.ParseDuration(s)
		if err != nil {
			return nil, fmt.Errorf("%s is not a valid duration for VAULT_TTL: %w", s, err)
		}

		v.TTL = int(d.Seconds())
	}

	if s := os.Getenv("VAULT_REAUTH"); s != "" {
		b, err := strconv.ParseBool(s)
		if err != nil {
			return nil, fmt.Errorf("1, t, T, TRUE, true, True, 0, f, F, FALSE, false, False are valid values for ALLOW_FAIL: %w", err)
		}

		v.ReAuth = b
	}

	if s := os.Getenv("ALLOW_FAIL"); s != "" {
		b, err := strconv.ParseBool(s)
		if err != nil {
			return nil, fmt.Errorf("1, t, T, TRUE, true, True, 0, f, F, FALSE, false, False are valid values for ALLOW_FAIL: %w", err)
		}

		v.AllowFail = b
	}

	v.LoginTimeout = DefaultTimeout

	if s := os.Getenv("LOGIN_TIMEOUT"); s != "" {
		t, err := time.ParseDuration(s)
		if err != nil {
			return nil, fmt.Errorf("not a valid duration: %w", err)
		}

		v.LoginTimeout = t
	}

	// create vault client
	vaultConfig := vault.DefaultConfig()
	if err := vaultConfig.ReadEnvironment(); err != nil {
		return nil, fmt.Errorf("failed to read environment for vault: %w", err)
	}

	var err error

	v.client, err = vault.NewClient(vaultConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create vault client: %w", err)
	}

	v.setAuthenticator()

	return v, nil
}

func (v *Vault) setAuthenticator() {
	v.authenticate = newKubernetesAuth(v)

	if v.RoleID != "" && v.SecretID != "" {
		v.authenticate = newAppRoleAuth(v)
	}
}

// Client returns a Vault *vault.Client
func (v *Vault) Client() *vault.Client {
	return v.client
}

// Authenticate with vault
func (v *Vault) Authenticate() (string, error) {
	return v.authenticate()
}

// StoreToken in VaultTokenPath
func (v *Vault) StoreToken(token string) error {
	//nolint:gosec // 0644 is fine here
	if err := os.WriteFile(v.TokenPath, []byte(token), 0o644); err != nil {
		return fmt.Errorf("failed to store token: %w", err)
	}

	return nil
}

// LoadToken from VaultTokenPath
func (v *Vault) LoadToken() (string, error) {
	content, err := os.ReadFile(v.TokenPath)
	if err != nil {
		return "", fmt.Errorf("failed to load token: %w", err)
	}

	if len(content) == 0 {
		return "", fmt.Errorf("found empty token")
	}

	return string(content), nil
}

// UseToken directly for requests with Vault
func (v *Vault) UseToken(token string) {
	v.client.SetToken(token)
}

// GetToken tries to load the vault token from VaultTokenPath
// if token is not available, invalid or not renewable
// and VaultReAuth is true, try to re-authenticate
func (v *Vault) GetToken() (string, error) {
	var empty string

	token, err := v.LoadToken()
	if err != nil {
		if v.ReAuth {
			return v.Authenticate()
		}

		return empty, fmt.Errorf("failed to load token form %s: %w", v.TokenPath, err)
	}

	v.client.SetToken(token)

	if _, err = v.client.Auth().Token().RenewSelf(v.TTL); err != nil {
		if v.ReAuth {
			return v.Authenticate()
		}

		return empty, fmt.Errorf("failed to renew token: %w", err)
	}

	return token, nil
}

// NewRenewer returns a *vault.Renewer to renew the vault token regularly
func (v *Vault) NewRenewer(token string) (*vault.Renewer, error) {
	v.client.SetToken(token)
	// renew the token to get a secret usable for renewer
	secret, err := v.client.Auth().Token().RenewSelf(v.TTL)
	if err != nil {
		return nil, fmt.Errorf("failed to renew-self token: %w", err)
	}

	renewer, err := v.client.NewLifetimeWatcher(&vault.RenewerInput{Secret: secret})
	if err != nil {
		return nil, fmt.Errorf("failed to get token renewer: %w", err)
	}

	return renewer, nil
}

// FixAuthMountPath add the auth prefix
// kubernetes      -> kubernetes
// /kubernetes     -> kubernetes
// auth/kubernetes -> kubernetes
// presumes a valid path
func FixAuthMountPath(p string) string {
	return strings.TrimRight(strings.TrimPrefix(strings.TrimLeft(p, "/"), "auth/"), "/")
}
