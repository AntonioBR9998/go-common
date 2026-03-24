package validation

import (
	"regexp"

	"github.com/go-playground/validator/v10"
)

var nameRegex = regexp.MustCompile(`^\S(.{0,126}\S)?$`)

// ValidateNameFormat is the function for validating if the current field
// has 128 characters max and it does not begin or end with spaces.
func ValidateNameFormat(fl validator.FieldLevel) bool {

	if name, ok := fl.Field().Interface().(string); ok {
		return nameRegex.MatchString(name)
	}

	return false
}
