package rocho

import (
	"context"
	"encoding/json"
	"net/http"
)

// ClassicAuthData contains username and passsword.
// It's preimplemented for sake of simplicty for end user.
type ClassicAuthData struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// ClassicAuthDataParser parses ClassicAuthData from request.
type ClassicAuthDataParser struct {
}

// ParseAuthData parses ClassicAuthData from request as if it's JSON.
func (adp *ClassicAuthDataParser) ParseAuthData(ctx context.Context, r *http.Request) (ad AuthData, err error) {
	rad := ClassicAuthData{}
	err = json.NewDecoder(r.Body).Decode(&rad)
	ad = rad
	return
}
