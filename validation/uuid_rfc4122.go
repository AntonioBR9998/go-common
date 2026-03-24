package validation

import (
	"regexp"

	"github.com/go-playground/validator/v10"
)

const (
	uuidRegexString = "^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)

var (
	uuidRegex = regexp.MustCompile(uuidRegexString)
)

func ValidateUUID(fl validator.FieldLevel) bool {
	switch v := fl.Field().Interface().(type) {
	case []string:
		for _, value := range v {
			if !uuidRegex.MatchString(value) {
				return false
			}
		}
		return true

	default:
		value := fl.Field().String()
		return uuidRegex.MatchString(value)
	}
}
