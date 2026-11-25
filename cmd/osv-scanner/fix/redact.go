package fix

import (
	"errors"

	"github.com/google/osv-scalibr/guidedremediation/result"
	"github.com/google/osv-scanner/v2/internal/fixplan"
)

type redactedUserError struct {
	err error
}

func (e *redactedUserError) Error() string {
	if e == nil || e.err == nil {
		return ""
	}

	return fixplan.RedactText(e.err.Error())
}

func (e *redactedUserError) Unwrap() error { return e.err }

func redactError(err error) error {
	if err == nil {
		return nil
	}
	if _, ok := errors.AsType[*redactedUserError](err); ok {
		return err
	}

	return &redactedUserError{err: err}
}

func redactResultSecrets(res *result.Result) {
	if res == nil {
		return
	}
	for i := range res.Errors {
		res.Errors[i].Error = fixplan.RedactText(res.Errors[i].Error)
	}
}
