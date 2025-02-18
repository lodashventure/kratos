package oidc

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/pkg/errors"
	"golang.org/x/oauth2"

	"github.com/ory/herodot"
)

type ProviderLine struct {
	*ProviderGenericOIDC
}

var _ OAuth2Provider = (*ProviderLine)(nil)

func NewProviderLine(
	config *Configuration,
	reg Dependencies,
) Provider {
	// Assign base configuration to the provider
	config.IssuerURL = "https://access.line.me"
	return &ProviderLine{
		ProviderGenericOIDC: &ProviderGenericOIDC{
			config: config,
			reg:    reg,
		},
	}
}

// Modify claims for LINE provider to use API that provided from LINE to verify the token
// Following the documentation: https://developers.line.biz/en/reference/line-login/#verify-id-token
func (l *ProviderLine) Claims(ctx context.Context, exchange *oauth2.Token, _ url.Values) (*Claims, error) {
	// Extract the ID token from the exchange
	idToken, ok := exchange.Extra("id_token").(string)

	// Check if the ID token is missing
	if !ok {
		return nil, errors.WithStack(herodot.ErrBadRequest.WithReasonf("ID token is missing"))
	}

	// Create a request to verify the ID token
	endpoint := "https://api.line.me/oauth2/v2.1/verify"
	body := url.Values{}
	body.Set("id_token", idToken)
	body.Set("client_id", l.config.ClientID)

	// Send the request to verify the ID token
	res, err := l.reg.HTTPClient(ctx).PostForm(endpoint, body)
	// Check if the request failed
	if err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("Failed to verify ID token: %s", err))
	}

	// Close the response body
	defer res.Body.Close()

	// Check if the response is not OK
	if res.StatusCode != 200 {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("Failed to verify ID token: %s", res.Status))
	}

	// Parse the response
	var claims Claims
	if err := json.NewDecoder(res.Body).Decode(&claims); err != nil {
		return nil, errors.WithStack(herodot.ErrInternalServerError.WithReasonf("Failed to decode ID token: %s", err))
	}

	// Return the claims
	return &claims, nil
}
