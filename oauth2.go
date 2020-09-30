package rocho

import "golang.org/x/oauth2"

// OAuth2AuthData is AuthData for OAuth2 flow.
type OAuth2AuthData struct {
	OAuth2ServiceName string // used for determinging which OAuth2 provider has been used.

	Config         *oauth2.Config
	ExchangedToken *oauth2.Token
}

// GetAccessToken returns access token from OAuth2AuthData.
func (ad *OAuth2AuthData) GetAccessToken() string {
	return ad.ExchangedToken.AccessToken
}
