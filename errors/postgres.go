package errors

import (
	"errors"

	"github.com/AntonioBR9998/go-common/validation"
	"github.com/lib/pq"
)

// Returns an error wrapping the error specified, and one of these errors:
// errors:
//
//	**validation.NewErrValidation**: if NOT NULL constraint or foreign key is violated
//	**errors.AlreadyExistsError**: if a UNIQUE constraint is violated
func WrapPostgresErrorCode(err error, resourceType string, id ...string) error {
	var pqErr *pq.Error
	if errors.As(err, &pqErr) {
		switch pqErr.Code.Name() {
		case "not_null_violation":
			fallthrough
		case "foreign_key_violation":
			return validation.NewErrValidation([]error{err})
		case "unique_violation":
			return Wrap(NewAlreadyExistsError(resourceType, getIdsStr(id)), err)
		}
	}
	return err
}
