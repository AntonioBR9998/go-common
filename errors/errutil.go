package errors

import (
	"fmt"
	"strings"
)

func getIdsStr(ids []string) string {
	if len(ids) == 0 {
		return ""
	} else if len(ids) == 1 {
		return ids[0]
	} else {
		joinedIds := strings.Join(ids, "', '")
		return joinedIds
	}
}

type NotFoundError struct {
	resourceType string
	ids          []string
}

func NewNotFoundError(resourceType string, ids ...string) error {
	return NotFoundError{
		resourceType: resourceType,
		ids:          ids,
	}
}

func (e NotFoundError) Error() string {
	return fmt.Sprintf("Resource of type '%s' with ids: %s was not found", e.resourceType, getIdsStr(e.ids))
}

type AlreadyExistsError struct {
	resourceType string
	ids          []string
}

func NewAlreadyExistsError(resourceType string, ids ...string) error {
	return AlreadyExistsError{
		resourceType: resourceType,
		ids:          ids,
	}
}

func (e AlreadyExistsError) Error() string {
	return fmt.Sprintf("Resource of type '%s' with ids: %s already exists", e.resourceType, getIdsStr(e.ids))
}

type ExpiredError struct {
	resourceType string
	ids          []string
}

func NewExpiredError(resourceType string, ids ...string) error {
	return ExpiredError{
		resourceType: resourceType,
		ids:          ids,
	}
}

func (e ExpiredError) Error() string {
	return fmt.Sprintf("Resource of type '%s' with ids: %s has been expired", e.resourceType, getIdsStr(e.ids))
}

type AlreadyInUseError struct {
	resourceType string
	ids          []string
}

func NewAlreadyInUseError(resourceType string, ids ...string) error {
	return AlreadyInUseError{
		resourceType: resourceType,
		ids:          ids,
	}
}

func (e AlreadyInUseError) Error() string {
	return fmt.Sprintf("Resource of type '%s' with ids: %s is already in use", e.resourceType, getIdsStr(e.ids))
}

func Wrap(err1 error, err2 error) error {
	return fmt.Errorf("%w: %w", err1, err2)
}
