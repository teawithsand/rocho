package perm

import "context"

// Permission is kind of permission that user can have on subject.
// It should be declared on library level.
type Permission string

// CheckResult contains data about voting that was done.
type CheckResult struct {
	IsAllowed     bool
	Permission    Permission
	User, Subject interface{}

	VoterResults map[string]VoterResult
}

// GetVoterResult returns result of given voter(if provided).
// Returns zero result if not provided.
func (cr *CheckResult) GetVoterResult(voterName string) (vr VoterResult) {
	if cr == nil {
		return
	}
	if cr.VoterResults == nil {
		return
	}
	vr, _ = cr.VoterResults[voterName]
	return
}

// Allow is true if voting succeed for given user on given subject.
func (cr *CheckResult) Allow() bool {
	if cr == nil {
		return false
	}
	return cr.IsAllowed
}

// VoterResult is type of result, that voter may return.
type VoterResult uint16

// IsZero checks if VoterResult is zero, which means that it's undefined.
func (vr VoterResult) IsZero() bool {
	return vr == 0
}

const (
	VoterNeutral VoterResult = iota + 1
	VoterNoSupport
	VoterAgree
	VoterDeny
)

// Check contains single request for checking given permission for given user on given subject.
type Check struct {
	Permission Permission
	User       interface{}
	Subject    interface{}
}

// Voter votes on specific permission on given subject, for given user.
type Voter interface {
	// TODO(teawithsand): add methods that allow optimization on per-type basis?
	// OR compile-time codegen for allowing inlining all calls to these methods yielding faster code as a result?
	VoteOnAccess(ctx context.Context, c Check) (res VoterResult, err error)
}

// VoterFunc contains function
type VoterFunc func(ctx context.Context, c Check) (res VoterResult, err error)

// VoteOnAccess votes if given permission should be granted.
func (f VoterFunc) VoteOnAccess(ctx context.Context, c Check) (res VoterResult, err error) {
	return f(ctx, c)
}

// Manager takes care of checking permission.
type Manager interface {
	CheckPermission(ctx context.Context, c Check) (res CheckResult, err error)
}

// NamedVoter is tuple of Voter and Name.
type NamedVoter struct {
	Voter
	Name string
}

// DefaultManager implements default voting logic.
// It denies permission if at least one voter votes against.
// It denies permission on neutral/not supported results.
// It allows permission if no voter votes against, and at least one voter votes for it.
type DefaultManager struct {
	Voters []NamedVoter
}

func (dm *DefaultManager) CheckPermission(ctx context.Context, c Check) (res CheckResult, err error) {
	res.VoterResults = map[string]VoterResult{}
	agreed := 0
	for _, dm := range dm.Voters {
		var vr VoterResult
		vr, err = dm.Voter.VoteOnAccess(ctx, c)
		if err != nil {
			return
		}
		res.VoterResults[dm.Name] = vr
		switch vr {
		case VoterAgree:
			agreed++
		case VoterDeny:
			return
		}
	}

	if agreed > 0 {
		res.IsAllowed = true
	}

	return
}
