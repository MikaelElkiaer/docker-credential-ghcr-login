package auth

import (
	"context"
	"fmt"
	"log"
	"strings"

	"github.com/cli/go-gh/v2"
	"github.com/cli/go-gh/v2/pkg/api"
	"github.com/cli/go-gh/v2/pkg/auth"
)

// EnsureValidTokenForHost wil check for an existing token. If one is not found,
// or found without the required scopes (`read:packages`), a new login flow will
// run to get a new one
func EnsureValidTokenForHost(hostname string, requiredScopes string, version string) error {
	token, tokenSource := auth.TokenForHost(hostname)
	if !hasRequiredScopes(hostname, requiredScopes, token) {
		log.Printf("Token found did not have required scopes. Source: %s\n", tokenSource)
		err := loginFlow(hostname, requiredScopes, version)
		if err != nil {
			return err
		}
	}
	return nil
}

func hasRequiredScopes(hostname string, requiredScopes string, token string) bool {
	if token == "" {
		return false
	}

	client, err := api.NewRESTClient(api.ClientOptions{
		Host:      hostname,
		AuthToken: token,
	})
	if err != nil {
		return false
	}

	resp, err := client.Request("GET", "", nil)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	scopes := resp.Header.Get("X-OAuth-Scopes")
	return strings.Contains(scopes, requiredScopes)
}

func loginFlow(hostname string, requiredScopes string, version string) error {
	fmt.Printf("Running login flow for %s with scopes %s\n", hostname, requiredScopes)
	return gh.ExecInteractive(context.Background(), "auth", "login", "-h", hostname, "-s", requiredScopes)
}
