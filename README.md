[![Go Report Card](https://goreportcard.com/badge/github.com/postfinance/vaultk8s)](https://goreportcard.com/report/github.com/postfinance/vaultk8s)
[![GoDoc](https://godoc.org/github.com/postfinance/vaultk8s?status.svg)](https://godoc.org/github.com/postfinance/vaultk8s)
[![Build Status](https://github.com/postfinance/vaultk8s/workflows/build/badge.svg)](https://github.com/postfinance/vaultk8s/actions)
[![Coverage Status](https://coveralls.io/repos/github/postfinance/vaultk8s/badge.svg?branch=master)](https://coveralls.io/github/postfinance/vaultk8s?branch=master)


# Package vaultk8s

Package vaultk8s provides authentication with Vault on Kubernetes

> Replaces `github.com/postfinance/vault/k8s`

Authentication is done either with Vault's  *Kubernetes Auth Method* or *AppRole Auth Method*.

Checkout the Vault documentation for details:
- [Kubernetes Auth Method](https://www.vaultproject.io/docs/auth/kubernetes)
- [AppRole Auth Method](https://www.vaultproject.io/docs/auth/approle)

If the environment variables `VAULT_ROLE_ID` and `VAULT_SECRET_ID` are set, *AppRole Auth Method* will be used, *Kubernetes Auth Method* otherwise.

For a successful Kubernetes authentication the environment variable `VAULT_ROLE` must be set.

## Tests

### HashiCorp Vault

[Install Vault](https://www.vaultproject.io/docs/install)

Start Vault:
```
export VAULT_DEV_ROOT_TOKEN_ID="90b03685-e17b-7e5e-13a0-e14e45baeb2f"
export VAULT_DEV_LISTEN_ADDRESS="127.0.0.1:8200"
vault server -dev
```
> [Dev Options](https://www.vaultproject.io/docs/commands/server#dev-options)
> Start vault with the same root token and listen address as defined in `k8s_test.go`.

### Kubernetes
A running Kubernetes cluster is required for testing - use [kind](https://kind.sigs.k8s.io/docs/user/quick-start/).

