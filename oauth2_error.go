package rocho

import "fmt"

// OAuth2StateError is returned when state from redirect is not equal to state stored in session.
type OAuth2StateError struct{}

func (*OAuth2StateError) Error() string {
	return "rocho: OAuth2 state mismatch"
}

type OAuth2StateManagerError struct {
	Err error
}

func (err *OAuth2StateManagerError) Error() string {
	if err == nil {
		return "<nil>"
	}

	if err.Err == nil {
		return "rocho: OAuth2 state manager error"
	}

	return fmt.Sprintf("rocho: OAuth2 state manager error: %s", err.Err.Error())
}
func (err *OAuth2StateManagerError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Err
}

type OAuth2TokenExchangeError struct {
	Err error
}

func (err *OAuth2TokenExchangeError) Error() string {
	if err == nil {
		return "<nil>"
	}

	if err.Err == nil {
		return "rocho: OAuth2 token exchange error"
	}

	return fmt.Sprintf("rocho: OAuth2 token exchange error: %s", err.Err.Error())
}
func (err *OAuth2TokenExchangeError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Err
}
