package rocho

import "fmt"

// ProviderFiledError is returned when provider fails for some reason.
type ProviderFiledError struct {
	Err error
}

func (err *ProviderFiledError) Error() string {
	if err == nil {
		return "<nil>"
	}
	if err.Err == nil {
		return "outher: Provider failed to get user's detail info"
	}
	return fmt.Sprintf("outher: Provider failed to get user's detail info: %s", err.Err.Error())
}
func (err *ProviderFiledError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.Err
}
