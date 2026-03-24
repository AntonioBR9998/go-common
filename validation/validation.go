package validation

import (
	"bytes"
	"errors"
	"reflect"
	"strings"

	"github.com/go-playground/locales/en"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
	en_translations "github.com/go-playground/validator/v10/translations/en"
)

type ErrValidation struct {
	errors []error
}

func (e ErrValidation) Error() string {
	buff := bytes.NewBufferString("")

	for _, err := range e.errors {
		buff.WriteString(err.Error())
		buff.WriteString("\n")
	}

	return strings.TrimSpace(buff.String())
}

func (e ErrValidation) Errors() []error {
	return e.errors
}

func NewErrValidation(errs []error) error {
	return ErrValidation{
		errors: errs,
	}
}

var translations = []struct {
	tag      string
	msg      string
	override bool
}{
	{
		tag:      "uuid_rfc4122",
		msg:      "{0} must be a valid UUID",
		override: true,
	},
}

type Validator struct {
	*validator.Validate
	trans ut.Translator
}

func NewValidator() (*Validator, error) {
	en := en.New()
	uni := ut.New(en, en)

	if trans, ok := uni.GetTranslator("en"); ok {
		// Create a new validator
		val := validator.New()
		// Get field's name from json tag
		val.RegisterTagNameFunc(func(field reflect.StructField) string {
			name := strings.SplitN(field.Tag.Get("json"), ",", 2)[0]
			// Maybe we could return the name of the struct's field
			if name == "-" {
				return ""
			}

			return "'" + name + "'"
		})

		// Using the default english translation
		if err := en_translations.RegisterDefaultTranslations(val, trans); err != nil {
			return nil, err
		}
		// To override translation
		for _, t := range translations {
			if err := val.RegisterTranslation(t.tag, trans, func(ut ut.Translator) error {
				return ut.Add(t.tag, t.msg, t.override)
			}, func(ut ut.Translator, fe validator.FieldError) string {
				t, _ := ut.T(t.tag, fe.Field())
				return t
			}); err != nil {
				return nil, err
			}
		}
		if err := val.RegisterValidation("uuid_rfc4122", ValidateUUID); err != nil {
			return nil, err
		}
		if err := val.RegisterValidation("128_character_name", ValidateNameFormat); err != nil {
			return nil, err
		}

		return &Validator{
			Validate: val,
			trans:    trans,
		}, nil
	}

	return nil, errors.New("translation 'en' not found")

}
