package vaultk8s

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/api/auth/approle"
	"github.com/hashicorp/vault/api/auth/kubernetes"
)

// Authenticate is the function for the Vault authentication.
type Authenticate func() (string, error)

func newKubernetesAuth(v *Vault) Authenticate {
	return func() (string, error) {
		opts := []kubernetes.LoginOption{
			kubernetes.WithMountPath(FixAuthMountPath(v.AuthMountPath)),
			kubernetes.WithServiceAccountTokenPath(v.ServiceAccountTokenPath),
		}

		a, err := kubernetes.NewKubernetesAuth(
			v.Role,
			opts...,
		)
		if err != nil {
			return "", fmt.Errorf("unable to initialize Kubernetes auth method: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), v.LoginTimeout)
		defer cancel()

		authInfo, err := v.client.Auth().Login(ctx, a)
		if err != nil {
			return "", err
		}

		if authInfo == nil {
			return "", fmt.Errorf("no auth info was returned after login")
		}

		return authInfo.Auth.ClientToken, nil
	}
}

func newAppRoleAuth(v *Vault) Authenticate {
	return func() (string, error) {
		secretID := &approle.SecretID{
			FromString: v.SecretID,
		}

		// TODO: wrapping token
		opts := []approle.LoginOption{
			approle.WithMountPath(FixAuthMountPath(v.AuthMountPath)),
		}

		a, err := approle.NewAppRoleAuth(
			v.RoleID,
			secretID,
			opts...,
		)
		if err != nil {
			return "", fmt.Errorf("unable to initialize AppRole auth method: %w", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), v.LoginTimeout)
		defer cancel()

		authInfo, err := v.client.Auth().Login(ctx, a)
		if err != nil {
			return "", err
		}

		if authInfo == nil {
			return "", fmt.Errorf("no auth info was returned after login")
		}

		return authInfo.Auth.ClientToken, nil
	}
}
