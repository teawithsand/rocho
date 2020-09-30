package providers

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/teawithsand/rocho"
)

// Google OAuth2 provider. Gets user info from google's api.
//
// Right now it uses only "https://www.googleapis.com/oauth2/v2/userinfo" endpoint.
type Google struct {
}

// GoogleUserInfo contains user information, which may be fetched from google's api.
type GoogleUserInfo struct {
	ID    string `json:"id"`
	Email string `json:"email,omitempty"`

	Link       string `json:"link,omitempty"`
	PictureURL string `json:"picture,omitempty"`

	Name       string `json:"name,omitempty"`
	GivenName  string `json:"given_name,omitempty"`
	FamilyName string `json:"family_name,omitempty"`
}

func (*GoogleUserInfo) ProviderName() string {
	return "google"
}

func (ui *GoogleUserInfo) UserID() string {
	return ui.ID
}

// GetUserData fetches user
func (p *Google) GetUserData(ctx context.Context, ad rocho.AuthData) (userInfo rocho.UserData, err error) {
	const googleUserInfoEndpoint string = "https://www.googleapis.com/oauth2/v2/userinfo"

	oauthAd, ok := ad.(rocho.TokenAuthData)
	if !ok {
		err = rocho.ErrAuthDataNotSupported
		return
	}

	request, err := http.NewRequestWithContext(ctx, "GET", fmt.Sprintf("%s?access_token=%s", googleUserInfoEndpoint, url.QueryEscape(oauthAd.GetAccessToken())), nil)
	if err != nil {
		return
	}
	request.Header.Set("Accept", "application/json")
	request.Close = true

	client := getHTTPClient(ctx)
	response, err := client.Do(request)
	if err != nil {
		err = &rocho.ProviderFiledError{Err: err}
		return
	}
	defer response.Body.Close()

	if response.StatusCode != http.StatusOK {
		err = &rocho.ProviderFiledError{Err: errors.New("rocho/providers: Google provider: non 200 HTTP response from google's api")}
		return
	}

	u := &GoogleUserInfo{}
	err = json.NewDecoder(io.LimitReader(response.Body, 1024*1024)).Decode(u) // 1MB limit for user data should be enough
	if err != nil {
		err = &rocho.ProviderFiledError{Err: err}
	}

	userInfo = u
	return
}
