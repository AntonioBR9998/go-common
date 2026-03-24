package humamw

import (
	"context"
	"errors"
	"net/url"
	"strings"

	"github.com/AntonioBR9998/go-common/validation"
	"github.com/danielgtaylor/huma/v2"
)

type FilterOperation int
type FilterValueType int

const (
	FILTER_QUERY_PARAM = "filters"
	SORT_QUERY_PARAM   = "sort"
	ORDER_QUERY_PARAM  = "order"

	FilterContextKey string = "filter"

	EQUALS FilterOperation = iota
	NOT_EQUALS
	IN
	LIKE
	GREATER
	GREATER_OR_EQUAL
	LOWER
	LOWER_OR_EQUAL
	UNKNOWN

	STRING FilterValueType = iota
	STRING_LIST
	INT
	FLOAT
	BOOL
)

type FilterDefinition struct {
	Type FilterValueType
}

type FilterGroup struct {
	FilterList []*Filter
	Order      string
	Descending bool
}

type Filter struct {
	Field     string
	Operation FilterOperation
	Value     string
	Type      FilterValueType
}

func GetFilter(ctx context.Context) (*FilterGroup, bool) {
	return ContextValue[string, *FilterGroup](ctx, FilterContextKey)
}

func getOperation(str string) FilterOperation {
	switch str {
	case "eq":
		return EQUALS
	case "ne":
		return NOT_EQUALS
	case "in":
		return IN
	case "like":
		return LIKE
	case "gt":
		return GREATER
	case "ge":
		return GREATER_OR_EQUAL
	case "lt":
		return LOWER
	case "le":
		return LOWER_OR_EQUAL
	}
	return UNKNOWN
}

func isOperationAllowed(op FilterOperation, t FilterValueType) bool {
	switch op {
	case EQUALS:
		return true
	case NOT_EQUALS:
		return true
	case LIKE:
		if t == STRING {
			return true
		}
	case IN:
		if t == STRING {
			return true
		}
	case GREATER:
		fallthrough
	case GREATER_OR_EQUAL:
		fallthrough
	case LOWER:
		fallthrough
	case LOWER_OR_EQUAL:
		if t == INT || t == FLOAT {
			return true
		}
	}
	return false
}

func getFilterList(rawQuery string, filterDefMap map[string]FilterDefinition) ([]*Filter, []error) {
	queries := strings.Split(rawQuery, "&")
	queries = SliceFilter(queries, func(q string) bool {
		return strings.HasPrefix(q, FILTER_QUERY_PARAM+"=")
	})
	filterStrings := SliceMap(queries, func(q string) string {
		parts := strings.SplitN(q, "=", 2)
		if len(parts) < 2 {
			return ""
		}
		return parts[1]
	})

	var errList []error
	filterList := SliceMap(filterStrings, func(f string) *Filter {
		split := strings.Split(f, ":")
		if len(split) != 3 {
			errList = append(errList, errors.New("Malformed filter string: '"+f+"', (correct: 'field:op:value')"))
			return nil
		}
		field := split[0]
		operationStr := split[1]
		value, err := url.QueryUnescape(split[2])
		if err != nil {
			errList = append(errList, errors.New("invalid filter value"))
			return nil
		}

		filterDefinition, ok := filterDefMap[field]
		if !ok {
			errList = append(errList, errors.New("Unknown filter field: '"+field+"', fields: "+getMapKeyString(filterDefMap)))
			return nil
		}

		filter := Filter{
			Field:     field,
			Type:      filterDefinition.Type,
			Operation: getOperation(operationStr),
			Value:     value,
		}

		if filter.Operation == UNKNOWN {
			errList = append(errList, errors.New("Unknown filter operation: '"+operationStr+"', operations: "+operationStr))
		} else if !isOperationAllowed(filter.Operation, filter.Type) {
			println(filter.Operation)
			errList = append(errList, errors.New("Operation: '"+operationStr+"' not allowed for filter type"))
		}

		return &filter
	})

	return filterList, errList
}

func getMapKeyString[T any](fieldMap map[string]T) string {
	var fieldsString string
	first := true
	for key := range fieldMap {
		if first {
			fieldsString = key
			first = false
		} else {
			fieldsString += ", " + key
		}
	}

	return fieldsString
}

func UseFilter(
	api huma.API,
	filterDefMap map[string]FilterDefinition,
	orderDefList []string,
) func(huma.Context, func(huma.Context)) {

	orderSet := make(map[string]struct{})
	for _, orderStr := range orderDefList {
		orderSet[orderStr] = struct{}{}
	}

	return func(ctx huma.Context, next func(huma.Context)) {
		filterList, errList := getFilterList(ctx.URL().RawQuery, filterDefMap)

		orderBy := ctx.Query(SORT_QUERY_PARAM)
		if _, ok := orderSet[orderBy]; !ok && orderBy != "" {
			errList = append(errList, errors.New("Field: '"+orderBy+"' not allowed for ordering. Fields: "+getMapKeyString(orderSet)))
		}

		order := ctx.Query(ORDER_QUERY_PARAM)
		if order != "asc" && order != "desc" && order != "" {
			errList = append(errList, errors.New("order can only be 'asc' or 'desc'"))
		}
		descBool := order == "desc"

		if len(errList) != 0 {
			err := validation.NewErrValidation(errList)
			huma.WriteErr(api, ctx, 400, err.Error(), err)
			return
		}

		filterGroup := FilterGroup{FilterList: filterList, Order: orderBy, Descending: descBool}

		next(huma.WithValue(ctx, FilterContextKey, &filterGroup))
	}
}

func SliceFilter[T any](vs []T, f func(T) bool) []T {
	filtered := make([]T, len(vs))
	var i = 0
	for _, v := range vs {
		if f(v) {
			filtered[i] = v
			i++
		}
	}

	return filtered[:i]
}

func SliceMap[T, U any](ts []T, f func(T) U) []U {
	us := make([]U, len(ts))
	for i := range ts {
		us[i] = f(ts[i])
	}
	return us
}

// ContextValue[T any, K any] is a generic function to extract a value from a context
func ContextValue[K any, V any](ctx context.Context, key any) (V, bool) {
	val, ok := ctx.Value(key).(V)
	return val, ok
}
