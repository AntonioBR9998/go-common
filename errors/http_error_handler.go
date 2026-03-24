package errors

import (
	"errors"

	"github.com/AntonioBR9998/go-common/validation"
	log "github.com/sirupsen/logrus"
)

type StatusError interface {
	GetStatus() int
	Error() string
}

type statusError struct {
	statusCode int
	message    string
}

func (e *statusError) Error() string {
	return e.message
}

func (e *statusError) GetStatus() int {
	return e.statusCode
}

func APIErrorHandler(err error) StatusError {
	var statErr statusError
	var validationErr validation.ErrValidation

	if errors.As(err, &validationErr) {
		statErr.statusCode = 400
		statErr.message = validationErr.Error()
		return &statErr
	}

	var notFoundErr NotFoundError
	if errors.As(err, &notFoundErr) {
		statErr.statusCode = 404
		statErr.message = notFoundErr.Error()
		return &statErr
	}

	var alreadyExistsErr AlreadyExistsError
	if errors.As(err, &alreadyExistsErr) {
		statErr.statusCode = 409
		statErr.message = alreadyExistsErr.Error()
		return &statErr
	}

	var alreadyInUseErr AlreadyInUseError
	if errors.As(err, &alreadyInUseErr) {
		statErr.statusCode = 409
		statErr.message = alreadyInUseErr.Error()
		return &statErr
	}

	var expiredError ExpiredError
	if errors.As(err, &expiredError) {
		statErr.statusCode = 410
		statErr.message = expiredError.Error()
		return &statErr
	}

	log.Error(err.Error())
	statErr.statusCode = 500
	statErr.message = "Internal server error"
	return &statErr
}
