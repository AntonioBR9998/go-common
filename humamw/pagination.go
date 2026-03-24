package humamw

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	"github.com/danielgtaylor/huma/v2"
)

const PaginationContextKey string = "pagination"

func GetPagination(ctx context.Context) (*OffsetPaginator, bool) {
	return ContextValue[string, *OffsetPaginator](ctx, PaginationContextKey)
}

const (
	// Default constants
	defaultOffsetAlias               = "offset"
	defaultLimitAlias                = "limit"
	defaultTotalAlias                = "total"
	defaultMaxLimit                  = 100
	defaultMinLimit                  = 10
	defaultLimit                     = 20
	defaultOffset                    = 0
	enableLinkHeaderByDefault        = true
	disablePaginationHeaderByDefault = false
	paginationHeaderPrefix           = "Pagination"

	// Relations constants
	next     = "next"
	previous = "prev"
	first    = "first"
	last     = "last"
)

type PaginationOption Option[*paginationOptions]

func PaginationOptions(opts ...PaginationOption) PaginationOption {
	return func(po *paginationOptions) {
		for _, opt := range opts {
			opt(po)
		}
	}

}

// SetMaxLimit allows to set the maximum quantity of entries per page
func SetMaxLimit(maxLimit int) PaginationOption {
	return func(po *paginationOptions) {
		if maxLimit > 0 {
			po.maxLimit = maxLimit
		}
	}
}

// SetMinLimit allows to set the minimum quantity of entries por page
func SetMinLimit(minLimit int) PaginationOption {
	return func(po *paginationOptions) {
		if minLimit > 0 && minLimit < po.maxLimit {
			po.minLimit = minLimit
		}
	}
}

// SetDefaultLimit allows to set the default value to use if limit is not specified
func SetDefaultLimit(defaultLimit int) PaginationOption {
	return func(po *paginationOptions) {
		if defaultLimit > 0 {
			po.defaultLimit = defaultLimit
		}
	}
}

// UseLimitAlias allows to replace the query param "limit" by other word like "per_page"
func UseLimitAlias(alias string) PaginationOption {
	return func(po *paginationOptions) {
		if alias != "" {
			po.limitAlias = strings.TrimSpace(alias)
		}
	}
}

// UseOffsetAlias allows to replace the query param "page" by other word like "page"
func UseOffsetAlias(alias string) PaginationOption {
	return func(po *paginationOptions) {
		if alias != "" {
			po.offsetAlias = strings.TrimSpace(alias)
		}
	}
}

// UseTotalAlias allows to replace the param "total" by other word like "count"
func UseTotalAlias(alias string) PaginationOption {
	return func(po *paginationOptions) {
		if alias != "" {
			po.totalAlias = alias
		}
	}
}

// IsEnableLinkHeader allows to enable the Link headers following the RFC 8288
// See: https://datatracker.ietf.org/doc/html/rfc8288
func IsEnableLinkHeader(isEnable bool) PaginationOption {
	return func(po *paginationOptions) {
		po.isEnableLinkHeader = isEnable
	}
}

// IsEnablePaginationHeaders allow sto enable the Pagination-* headers
func IsEnablePaginationHeaders(isEnable bool) PaginationOption {
	return func(po *paginationOptions) {
		po.isEnablePaginationHeaders = isEnable
	}
}

func UsePagiationHeaderPrefix(prefix string) PaginationOption {
	return func(po *paginationOptions) {
		if prefix != "" {
			po.paginationHeaderPrefix = prefix
		}
	}
}

// Preset with default options
var defaultOptions = PaginationOptions(
	SetMaxLimit(defaultMaxLimit),                                // 100
	SetMinLimit(defaultMinLimit),                                // 10
	SetDefaultLimit(defaultLimit),                               // 20
	UseLimitAlias(defaultLimitAlias),                            // limit
	UseOffsetAlias(defaultOffsetAlias),                          // offset
	UseTotalAlias(defaultTotalAlias),                            // total
	IsEnableLinkHeader(enableLinkHeaderByDefault),               // yes
	IsEnablePaginationHeaders(disablePaginationHeaderByDefault), // No
	UsePagiationHeaderPrefix(paginationHeaderPrefix),            // Pagination
)

// paginationOptions represents the available options to apply during pagination process
type paginationOptions struct {
	maxLimit                  int
	minLimit                  int
	defaultLimit              int
	limitAlias                string
	offsetAlias               string
	totalAlias                string
	isEnableLinkHeader        bool
	isEnablePaginationHeaders bool
	paginationHeaderPrefix    string
}

// OffsetPaginator represents the state of current pagination
type OffsetPaginator struct {
	Offset int // The current page
	Limit  int // The number of elements to return
	Total  int // The calculated maximum page to reach
}

// UsePagination is a middleware that allows to use the offset pagination. This middleware has customization options
func UsePagination(opts ...PaginationOption) func(huma.Context, func(huma.Context)) {
	// Create a new pagination options
	pagOpts := &paginationOptions{}
	// Apply default configuration
	defaultOptions(pagOpts)
	// Apply user options and overwrite
	for _, opt := range opts {
		opt(pagOpts)
	}

	return func(ctx huma.Context, nextFn func(huma.Context)) {
		// Only allow POST and GET methods for pagination
		if ctx.Method() != http.MethodGet && ctx.Method() != http.MethodPost {
			nextFn(ctx)
			return
		}

		// Generate a base URL to set the "Link" header
		baseUrl := ctx.Host() + ctx.URL().Path

		// By default the offset field has the value 1 and limit has the value specified in options
		offsetPaginator := &OffsetPaginator{
			Limit:  pagOpts.defaultLimit,
			Offset: defaultOffset,
		}

		// Check if limit is not empty and is a number
		if limitStr := ctx.Query(pagOpts.limitAlias); limitStr != "" {
			if limitInt, err := strconv.Atoi(limitStr); err == nil {
				if limitInt >= pagOpts.maxLimit { // the provided limit is greater than the configured max limit
					// use the max limit
					offsetPaginator.Limit = pagOpts.maxLimit
				} else if limitInt <= pagOpts.minLimit { // the provided limit is lower than the configured min limit
					// use the min limit
					offsetPaginator.Limit = pagOpts.minLimit
				} else { // the provided limit is between the configured min and max limits
					// use the provided limit
					offsetPaginator.Limit = limitInt
				}
			}
		}

		// Check if offset is not empty and is a number
		if offsetStr := ctx.Query(pagOpts.offsetAlias); offsetStr != "" {
			if offsetInt, err := strconv.Atoi(offsetStr); err == nil && offsetInt > 0 {
				offsetPaginator.Offset = offsetInt
			}
		}

		// Add pagination to context
		nextFn(huma.WithValue(ctx, PaginationContextKey, offsetPaginator))

		// If link header is enabled, set the Link header with the prev, next, last and first link references
		if pagOpts.isEnableLinkHeader {

			linkHeaders := []string{}

			// If the offset is greater than 1 we have a previous page
			if offsetPaginator.Offset > 1 {
				linkHeaders = append(linkHeaders, generateLinkHeader(baseUrl, pagOpts.offsetAlias, offsetPaginator.Offset-1, pagOpts.limitAlias, offsetPaginator.Limit, previous))
			}

			// If the offset is lower than total we have a next page
			// If total is equals to 0 the number of pages is unknown and add the "next" link
			if offsetPaginator.Total == 0 || offsetPaginator.Offset < offsetPaginator.Total {
				linkHeaders = append(linkHeaders, generateLinkHeader(baseUrl, pagOpts.offsetAlias, offsetPaginator.Offset+1, pagOpts.limitAlias, offsetPaginator.Limit, next))
			}

			// If the offset is lower than total - 1 we have a last page
			// If total is equals to 0 the number of pages is unknown and not add the "last" link
			if offsetPaginator.Offset < offsetPaginator.Total-1 {
				linkHeaders = append(linkHeaders, generateLinkHeader(baseUrl, pagOpts.offsetAlias, offsetPaginator.Total, pagOpts.limitAlias, offsetPaginator.Limit, last))
			}

			// If the offset is greater than 1 we have a first page
			if offsetPaginator.Offset > 1 {
				linkHeaders = append(linkHeaders, generateLinkHeader(baseUrl, pagOpts.offsetAlias, 1, pagOpts.limitAlias, offsetPaginator.Limit, first))
			}

			// Add Link header
			ctx.SetHeader("Link", strings.Join(linkHeaders, ","))
		}

		// If pagination headers is enabled, set the headers for total, offset and limit
		if pagOpts.isEnablePaginationHeaders {
			ctx.SetHeader(pagOpts.paginationHeaderPrefix+"-"+pagOpts.totalAlias, strconv.Itoa(offsetPaginator.Total))
			ctx.SetHeader(pagOpts.paginationHeaderPrefix+"-"+pagOpts.offsetAlias, strconv.Itoa(offsetPaginator.Offset))
			ctx.SetHeader(pagOpts.paginationHeaderPrefix+"-"+pagOpts.limitAlias, strconv.Itoa(offsetPaginator.Limit))
		}
	}
}

func generateLinkHeader(fullUrl string, offsetAlias string, offset int, limitAlias string, limit int, relation string) string {
	return fmt.Sprintf(`<%s?%s=%d&%s=%d>; rel="%s"`, fullUrl, offsetAlias, offset, limitAlias, limit, relation)
}
