package rocho

import (
	"context"
	"errors"
	"net/http"
)

// SessionEngine authenticates incoming requests.
// It's high-level utility intended to be used in controller.
type SessionEngine interface {
	GetRequestAuthToken(ctx context.Context, r *http.Request) (at AuthToken, err error)
	GetRawAuthToken(ctx context.Context, rat []byte) (at AuthToken, err error)
	// TODO(teawithsand): refill-only function
}

// AuthEngine authenticates user using incoming request.
// It creates AuthTokens.
type AuthEngine interface {
	AuthenticateRequest(ctx context.Context, r *http.Request) (at AuthToken, err error)
	AuthenticateAuthData(ctx context.Context, ad AuthData) (at AuthToken, err error)

	SerializeAuthTokenToResponse(ctx context.Context, at AuthToken, w http.ResponseWriter) (err error)
	SerializerAuthToken(ctx context.Context, at AuthToken) (data []byte, err error)
}

// DefaultAuthEngine implements defautl behaviour of AuthEngine with rocho's components.
type DefaultAuthEngine struct {
	AuthDataParser    AuthDataParser
	UserDataProviders []UserDataProvider
	Authenticator     Authenticator

	AuthTokenSerializer     AuthTokenSerializer
	HTTPAuthTokenSerializer HTTPAuthTokenSerializer
}

// AuthenticateAuthData creates AuthToken for user comming with request.
func (dae *DefaultAuthEngine) AuthenticateAuthData(ctx context.Context, ad AuthData) (at AuthToken, err error) {
	var ud UserData
	for _, udp := range dae.UserDataProviders {
		ud, err = udp.GetUserData(ctx, ad)
		if errors.Is(err, ErrAuthDataNotSupported) {
			ud = nil
			continue
		} else if err != nil {
			return
		}

		// ud should never be nil anyway
		// but let's check it
		if ud != nil {
			break
		}
	}

	if ud == nil {
		err = ErrNoUserData
		return
	}

	at, err = dae.Authenticator.Authenticate(ctx, ad, ud)
	if err != nil {
		return
	}

	return
}

// AuthenticateRequest creates AuthToken for user comming with request.
func (dae *DefaultAuthEngine) AuthenticateRequest(ctx context.Context, r *http.Request) (at AuthToken, err error) {
	ad, err := dae.AuthDataParser.ParseAuthData(ctx, r)
	if err != nil {
		return
	}

	var ud UserData
	for _, udp := range dae.UserDataProviders {
		ud, err = udp.GetUserData(ctx, ad)
		if errors.Is(err, ErrAuthDataNotSupported) {
			ud = nil
			continue
		} else if err != nil {
			return
		}

		// ud should never be nil anyway
		// but let's check it
		if ud != nil {
			break
		}
	}

	if ud == nil {
		err = ErrNoUserData
		return
	}

	at, err = dae.Authenticator.Authenticate(ctx, ad, ud)
	if err != nil {
		return
	}

	return
}

func (dae *DefaultAuthEngine) SerializeAuthTokenToResponse(ctx context.Context, at AuthToken, w http.ResponseWriter) (err error) {
	// Call it, despite the fact that it's serializers responsibility.
	hsi, ok := at.(HasSecretInfo)
	if ok {
		hsi.StripSecretInfo()
	}

	err = dae.HTTPAuthTokenSerializer.SerializeAuthTokenToResponse(ctx, at, w)
	return
}

func (dae *DefaultAuthEngine) SerializerAuthToken(ctx context.Context, at AuthToken) (data []byte, err error) {
	// Call it, despite the fact that it's serializers responsibility.
	hsi, ok := at.(HasSecretInfo)
	if ok {
		hsi.StripSecretInfo()
	}

	data, err = dae.AuthTokenSerializer.SerializeAuthToken(ctx, at)
	return
}

// DefaultSessionEngine implements default behaviour of SessionEngine with rocho's components.
type DefaultSessionEngine struct {
	AuthTokenDeserializer     AuthTokenSerializer
	HTTPAuthTokenDeserializer HTTPAuthTokenSerializer
	AuthTokenValidator        AuthTokenValidator

	AuthTokenRefillers []AuthTokenRefiller
}

// GetRequestAuthToken gets AuthToken from HTTP request.
func (dse *DefaultSessionEngine) GetRequestAuthToken(ctx context.Context, r *http.Request) (at AuthToken, err error) {
	at, err = dse.HTTPAuthTokenDeserializer.DeserializeAuthTokenFromRequest(ctx, r)
	if err != nil {
		return
	}

	if dse.AuthTokenValidator != nil {
		err = dse.AuthTokenValidator.ValidatePreRefill(ctx, at)
		if err != nil {
			return
		}
	}

	var nat AuthToken
	for _, atr := range dse.AuthTokenRefillers {
		nat, err = atr.ProcessAuthToken(ctx, at)
		if errors.Is(err, ErrAuthDataNotSupported) {
			continue
		} else if err != nil {
			return
		}

		at = nat
		return
	}

	if dse.AuthTokenValidator != nil {
		err = dse.AuthTokenValidator.ValidateAfterRefill(ctx, at)
		if err != nil {
			return
		}
	}

	return
}

// GetRawAuthToken creates AuthToken from bytes it's given.
func (dse *DefaultSessionEngine) GetRawAuthToken(ctx context.Context, rat []byte) (at AuthToken, err error) {
	at, err = dse.AuthTokenDeserializer.DeserializeAuthToken(ctx, rat)
	if err != nil {
		return
	}

	if dse.AuthTokenValidator != nil {
		err = dse.AuthTokenValidator.ValidatePreRefill(ctx, at)
		if err != nil {
			return
		}
	}

	var nat AuthToken
	for _, atr := range dse.AuthTokenRefillers {
		nat, err = atr.ProcessAuthToken(ctx, at)
		if errors.Is(err, ErrAuthDataNotSupported) {
			continue
		} else if err != nil {
			return
		}

		at = nat
		return
	}

	if dse.AuthTokenValidator != nil {
		err = dse.AuthTokenValidator.ValidateAfterRefill(ctx, at)
		if err != nil {
			return
		}
	}

	return
}
