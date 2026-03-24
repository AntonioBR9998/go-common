package humamw

import (
	"context"
	"strings"

	"github.com/danielgtaylor/huma/v2"
)

// Context[T any] is the generic function to extract a value from golang context
func Context[K any, V any](ctx context.Context, key K) (V, bool) {
	val, ok := ctx.Value(key).(V)
	return val, ok
}

func ContextKeyWithNamespace(namespace string, key string, separator string) string {
	return string(namespace + separator + strings.ToLower(strings.TrimSpace(key)))
}

func setHeaderCallbackContextKey(key string) string {
	return ContextKeyWithNamespace("header-cb", key, ":")
}

func GetSetHeaderCallback(ctx context.Context, header string) (func(string, string), bool) {
	return Context[string, func(string, string)](ctx, setHeaderCallbackContextKey(header))
}

func setHeader(ctx huma.Context, name string, value string) {
	if name != "" && value != "" {
		ctx.SetHeader(name, value)
	}
}

// SetHeaderUsingCallback allows to set a header dynamically using a callback
// This functions is useful if you need to set a not static header
func SetHeaderUsingCallback(header string) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		callbackFn := func(header string, value string) {
			setHeader(ctx, header, value)
		}
		next(huma.WithValue(ctx, setHeaderCallbackContextKey(header), callbackFn))
	}
}
