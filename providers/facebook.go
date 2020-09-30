package providers

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/teawithsand/rocho"
)

// Facebook takes data from facebook's api.
//
// It uses "https://graph.facebook.com/me" endpoint.
type Facebook struct {
	// Used to create appsecret_proof for api calls.
	AppSecret string

	// List of fields. If femptry, populated with defaults: "id,email".
	// Fields MUST contain ID in order to make serialization work.
	Fields []string
}

type internalFacebookUserInfo struct {
	ID    string `json:"id"`
	Email string `json:"email,omitempty"`

	Link string `json:"link,omitempty"`

	Hometown string `json:"hometown,omitempty"`
	Birthday string `json:"birthday,omitempty"`
	About    string `json:"about,omitempty"`

	Name      string `json:"name,omitempty"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`

	Picture struct {
		Data struct {
			URL string `json:"url"`
		} `json:"data"`
	} `json:"picture,omitempty"`

	Location struct {
		Name string `json:"name"`
	} `json:"location,omitempty"`
}

// FacebookUserInfo
type FacebookUserInfo struct {
	ID    string `json:"id"`
	Email string `json:"email,omitempty"`

	Link string `json:"link,omitempty"`

	Hometown string `json:"hometown,omitempty"`
	Birthday string `json:"birthday,omitempty"`
	About    string `json:"about,omitempty"`

	Name      string `json:"name,omitempty"`
	FirstName string `json:"first_name,omitempty"`
	LastName  string `json:"last_name,omitempty"`

	PictureURL string `json:"picture_url,omitempty"`
	Location   string `json:"location,omitempty"`
}

func (*FacebookUserInfo) ProviderName() string {
	return "facebook"
}

func (ui *FacebookUserInfo) UserID() string {
	return ui.ID
}

// GetUserData fetches user
func (p *Facebook) GetUserData(ctx context.Context, ad rocho.AuthData) (userInfo rocho.UserData, err error) {
	const facebookUserInfoEndpoint = "https://graph.facebook.com/me"

	oauthAd, ok := ad.(rocho.TokenAuthData)
	if !ok {
		err = rocho.ErrAuthDataNotSupported
		return
	}

	token := oauthAd.GetAccessToken()

	var apiURL string

	// TODO(teawithsand): make these contain more reasonalbe defaults
	fields := "id,email"
	if len(p.Fields) > 0 {
		fields = strings.Join(p.Fields, ",")
	}

	fields = url.QueryEscape(fields)

	if p.AppSecret != "" {
		// https://developers.facebook.com/docs/graph-api/securing-requests/
		h := hmac.New(sha256.New, []byte(p.AppSecret))
		_, err = h.Write([]byte(token))
		if err != nil {
			return
		}

		proof := url.QueryEscape(hex.EncodeToString(h.Sum(nil)))

		apiURL = fmt.Sprintf(
			"%s?access_token=%s&appsecret_proof=%s&fields=%s",
			facebookUserInfoEndpoint,
			url.QueryEscape(oauthAd.GetAccessToken()),
			proof,
			fields,
		)
	} else {
		apiURL = fmt.Sprintf(
			"%s?access_token=%s&fields=%s",
			facebookUserInfoEndpoint,
			url.QueryEscape(oauthAd.GetAccessToken()),
			fields,
		)
	}

	request, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
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
		err = &rocho.ProviderFiledError{Err: errors.New("rocho/providers: Facebook provider: non 200 HTTP response from facebooks's api")}
		return
	}

	u := &internalFacebookUserInfo{}
	err = json.NewDecoder(io.LimitReader(response.Body, 1024*1024)).Decode(u) // 1MB limit for user data should be enough
	if err != nil {
		err = &rocho.ProviderFiledError{Err: err}
	}

	userInfo = &FacebookUserInfo{
		ID:        u.ID,
		Email:     u.Email,
		Link:      u.Link,
		Hometown:  u.Hometown,
		Birthday:  u.Birthday,
		About:     u.About,
		Name:      u.Name,
		FirstName: u.FirstName,
		LastName:  u.LastName,

		PictureURL: u.Picture.Data.URL,
		Location:   u.Location.Name,
	}
	return
}
