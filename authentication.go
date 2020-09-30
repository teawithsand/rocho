package rocho

import (
	"context"
	"errors"
	"net/http"
)

// ErrAuthDataNotSupported is returned when Authenticator or UserProvider does not support given type of AuthData.
var ErrAuthDataNotSupported = errors.New("rocho: Given type of AuthData is not supported")

// ErrNoUserData is returned when none of UserDataProviders is able to process AuthData and cretae UserData.
var ErrNoUserData = errors.New("rocho: No UserData can be supplied for given AuthData. No provider matched")

// AuthData contains data needed to authenticate user, for instance username and password.
type AuthData = interface{}

// TokenAuthData is any kind of AuthData, which contains token.
type TokenAuthData interface {
	GetAccessToken() string
}

// AuthDataParser is responsible for parsing AuthData from incoming request.
type AuthDataParser interface {
	// Use context for convention here, despite the fact that it's part of request since go 1.7(?).
	ParseAuthData(ctx context.Context, r *http.Request) (AuthData, error)
}

// UserData contains user data.
// It can be any type.
type UserData = interface{}

// UserDataProvider fetches user data from AuthData.
// It may call some 3rd party service or query database.
type UserDataProvider interface {
	GetUserData(ctx context.Context, ad AuthData) (UserData, error)
}

// Authenticator is responsible for getting AuthData/Userdata and creating AuthToken from it.
type Authenticator interface {
	Authenticate(ctx context.Context, ad AuthData, ud UserData) (AuthToken, error)
}
