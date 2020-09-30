package rocho

import (
	"context"
	"net/http"
)

// AuthToken contains result of authentication.
// It should have info about user being authenticated, for instance contain entire user entity.
//
// Secret data can be stripped from it by implementing StripSecretInfo function.
type AuthToken = interface{}

// HasSecretInfo is something that has secret info, which can be stripped.
type HasSecretInfo interface {
	StripSecretInfo() // removes secret info from this AuthToken.
}

// AuthTokenValidator is validator, which validates AuthToken.
// It's responsible for things like expiration.
type AuthTokenValidator interface {
	ValidatePreRefill(ctx context.Context, at AuthToken) (err error)
	ValidateAfterRefill(ctx context.Context, at AuthToken) (err error)
}

// AuthDataValidators merges many AuthTokenValidator into one.
type AuthDataValidators []AuthTokenValidator

func (advs AuthDataValidators) ValidatePreRefill(ctx context.Context, at AuthToken) (err error) {
	for _, adv := range advs {
		err = adv.ValidatePreRefill(ctx, at)
		if err != nil {
			return
		}
	}
	return
}

func (advs AuthDataValidators) ValidateAfterRefill(ctx context.Context, at AuthToken) (err error) {
	for _, adv := range advs {
		err = adv.ValidateAfterRefill(ctx, at)
		if err != nil {
			return
		}
	}
	return
}

// AuthTokenSerializer is responsible for serializing whatever type(s) of AuthToken are used by application.
//
// Serializer is responsible for token authenticity and integrity.
//
// Serializer is also responsible for stipping secret info by calling HasSecretInfo.StripSecretInfo() if token
// implements HasSecretInfo interface.
//
// Above thing is not obligatory if serialized token is encrypted, not only signed.
type AuthTokenSerializer interface {
	SerializeAuthToken(ctx context.Context, at AuthToken) (data []byte, err error)
	// Do not use JSON-unmarshal like syntax but return one in order to
	// allow using many types of AuthTokens for library user.
	DeserializeAuthToken(ctx context.Context, data []byte) (at AuthToken, err error)
}

// HTTPAuthTokenSerializer serializes AuthToken to HTTP responses and deserializes them from HTTP requests.
//
// Serializer is also responsible for stipping secret info by calling HasSecretInfo.StripSecretInfo() if token
// implements HasSecretInfo interface.
type HTTPAuthTokenSerializer interface {
	SerializeAuthTokenToResponse(ctx context.Context, at AuthToken, w http.ResponseWriter) (err error)
	// Do not use JSON-unmarshal like syntax but return one in order to
	// allow using many types of AuthTokens for library user.
	DeserializeAuthTokenFromRequest(ctx context.Context, r *http.Request) (at AuthToken, err error)
}

// AuthTokenLoader is responsible for loading AuthToken from incoming HTTP request.
type AuthTokenLoader interface {
	LoadToken(ctx context.Context, r *http.Request) (at AuthToken, err error)
}

// AuthTokenRefiller reverses transformation applied by StripSecretInfo() on given AuthToken.
// It returns new token OR old one populated with data.
type AuthTokenRefiller interface {
	ProcessAuthToken(ctx context.Context, at AuthToken) (rat AuthToken, err error)
}
