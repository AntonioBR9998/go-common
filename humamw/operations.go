package humamw

import "github.com/danielgtaylor/huma/v2"

// UserMiddlewares is a huma's operation that allows to set a list of given middlewares to existing ones
func UseMiddlewares(mw ...func(huma.Context, func(huma.Context))) func(o *huma.Operation) {
	return func(o *huma.Operation) {
		o.Middlewares = append(o.Middlewares, mw...)
	}
}
