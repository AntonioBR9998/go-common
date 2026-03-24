package sql

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"

	"github.com/AntonioBR9998/go-common/humamw"
	"github.com/AntonioBR9998/go-common/validation"
	"github.com/lib/pq"
)

func cleanQuery(str string) string {
	// Replace tabs and newlines with spaces
	str = strings.ReplaceAll(str, "\t", " ")
	str = strings.ReplaceAll(str, "\n", " ")

	// Trim leading and trailing spaces
	str = strings.TrimSpace(str)

	// Remove extra spaces
	str = strings.Join(strings.Fields(str), " ")

	return str
}

func getParams(f *humamw.FilterGroup, params []any) ([]any, []error) {
	var errList []error
	for _, filter := range f.FilterList {
		switch filter.Type {
		case humamw.STRING:
			switch filter.Operation {
			case humamw.IN:
				params = append(params, pq.Array(strings.Split(filter.Value, ",")))
			case humamw.LIKE:
				// escaped wildcards characters
				escaped := strings.ReplaceAll(filter.Value, "\\", "\\\\")
				escaped = strings.ReplaceAll(escaped, "%", "\\%")
				escaped = strings.ReplaceAll(escaped, "_", "\\_")
				params = append(params, escaped)
			default:
				params = append(params, filter.Value)
			}
		case humamw.STRING_LIST:
			params = append(params, strings.Split(filter.Value, ","))
		case humamw.INT:
			intValue, err := strconv.Atoi(filter.Value)
			if err != nil {
				errList = append(errList, errors.New("error parsing int value '"+filter.Value+"'"))
			} else {
				params = append(params, intValue)
			}
		case humamw.FLOAT:
			floatValue, err := strconv.ParseFloat(filter.Value, 64)
			if err != nil {
				errList = append(errList, errors.New("error parsing float value '"+filter.Value+"'"))
			} else {
				params = append(params, floatValue)
			}
		case humamw.BOOL:
			boolValue, err := strconv.ParseBool(filter.Value)
			if err != nil {
				errList = append(errList, errors.New("error parsing bool value '"+filter.Value+"'"))
			} else {
				params = append(params, boolValue)
			}
		default:
			errList = append(errList, errors.New("unknown type"))
		}
	}

	if len(errList) != 0 {
		return nil, errList
	}

	return params, nil
}

func getWhereFilter(f *humamw.FilterGroup, filterToColumnMap map[string]string, lastParam int) string {
	if len(f.FilterList) == 0 {
		return ""
	}

	var sb strings.Builder
	for i, filter := range f.FilterList {
		field, ok := filterToColumnMap[filter.Field]
		if !ok {
			continue
		}
		if i != 0 {
			sb.WriteString(" AND ")
		}
		switch filter.Operation {
		case humamw.EQUALS:
			sb.WriteString(field)
			sb.WriteString("=$")
			sb.WriteString(strconv.Itoa(lastParam + 1 + i))
		case humamw.NOT_EQUALS:
			sb.WriteString("(NOT ")
			sb.WriteString(field)
			sb.WriteString("=$")
			sb.WriteString(strconv.Itoa(lastParam + 1 + i))
			sb.WriteString(fmt.Sprintf(" OR %s IS NULL)", field))
		case humamw.LIKE:
			sb.WriteString(field)
			sb.WriteString(" ILIKE '%' || $")
			sb.WriteString(strconv.Itoa(lastParam + 1 + i))
			sb.WriteString(" || '%' ESCAPE '\\'")
		case humamw.IN:
			sb.WriteString(field)
			sb.WriteString(" = ANY($")
			sb.WriteString(strconv.Itoa(lastParam + 1 + i))
			sb.WriteString(")")
		case humamw.GREATER:
			sb.WriteString(field)
			sb.WriteString(" > $")
			sb.WriteString(strconv.Itoa(lastParam + 1 + i))
		case humamw.GREATER_OR_EQUAL:
			sb.WriteString(field)
			sb.WriteString(" >= $")
			sb.WriteString(strconv.Itoa(lastParam + 1 + i))
		case humamw.LOWER:
			sb.WriteString(field)
			sb.WriteString(" < $")
			sb.WriteString(strconv.Itoa(lastParam + 1 + i))
		case humamw.LOWER_OR_EQUAL:
			sb.WriteString(field)
			sb.WriteString(" <= $")
			sb.WriteString(strconv.Itoa(lastParam + 1 + i))
		}
	}

	return sb.String()
}

func getLastParamIndex(query string) int {
	lastParam := 0
	for i := 0; i < len(query); i++ {
		index := strings.Index(query[i:], "$")
		if index == -1 {
			break
		}
		i += index + 1

		paramIndex := 0
		for ; i < len(query); i++ {
			if !unicode.IsDigit(rune(query[i])) {
				break
			}
			paramIndex *= 10
			paramIndex += int(query[i] - '0')
		}

		if lastParam < paramIndex {
			lastParam = paramIndex
		}
	}

	return lastParam
}

func IndexInMainQuery(query string, substr string) int {
	// Avoid panic when substr is empty
	if substr == "" {
		return -1
	}

	parenthesisCount := 0

	for index, char := range query {
		if parenthesisCount == 0 {
			// Ensure we do not read past the end of query when comparing substr
			if index+len(substr) > len(query) {
				break
			}
			if char == rune(substr[0]) {
				found := true
				for substrIndex, substrChar := range substr {
					if substrChar != rune(query[index+substrIndex]) {
						found = false
						break
					}
				}
				if found {
					return index
				}
			}
		}

		switch char {
		case '(':
			parenthesisCount++
		case ')':
			parenthesisCount--
		}
	}

	return -1
}

func addWhereToQuery(f *humamw.FilterGroup, filterToColumnMap map[string]string, query string, lastParam int) (string, error) {
	if len(f.FilterList) == 0 {
		return query, nil
	}
	whereFilter := getWhereFilter(f, filterToColumnMap, lastParam)

	whereIndex := IndexInMainQuery(query, "WHERE")
	if whereIndex != -1 {
		// WHERE clause, insert just after it, and add 'AND' at the end
		insertPos := whereIndex + 6
		return query[:insertPos] + whereFilter + " AND " + query[insertPos:], nil
	}
	// No WHERE clause, insert just after 'FROM table_name', and add 'WHERE' at the beginning
	fromIndex := IndexInMainQuery(query, "FROM") + 5
	if fromIndex == -1 {
		return "", errors.New("FROM not found in query")
	}
	insertPos := strings.Index(query[fromIndex:], " ") + fromIndex
	if insertPos == -1 {
		return query + " WHERE " + whereFilter, nil
	}
	return query[:insertPos] + " WHERE " + whereFilter + query[insertPos:], nil
}

func addOrderToQuery(f *humamw.FilterGroup, filterToColumnMap map[string]string, query string) string {
	if query == "" {
		return query
	}
	if f.Order == "" {
		return query
	}
	order, ok := filterToColumnMap[f.Order]
	if !ok {
		return query
	}

	var orderStr string
	if f.Descending {
		orderStr = order + " DESC NULLS LAST"
	} else {
		orderStr = order + " ASC NULLS FIRST"
	}

	orderIndex := IndexInMainQuery(query, "ORDER BY")
	if orderIndex != -1 {
		orderIndex += len("ORDER BY") + 1
		// order clause, replace the contents
		startIndex := orderIndex
		dirIndex := IndexInMainQuery(query[orderIndex:], "DESC")
		if dirIndex != -1 {
			startIndex = dirIndex + orderIndex
		}
		dirIndex = IndexInMainQuery(query[orderIndex:], "ASC")
		if dirIndex != -1 {
			startIndex = dirIndex + orderIndex
		}

		orderEnd := strings.Index(query[startIndex:], " ")
		if orderEnd == -1 {
			orderEnd = len(query)
			if query[orderEnd-1] == ';' {
				orderEnd -= 1
			}

		} else {
			orderEnd += startIndex
		}

		return query[:orderIndex] + orderStr + query[orderEnd:]
	}
	// no order clause, LIMIT start or EOS
	splitPosition := IndexInMainQuery(query, "LIMIT") - 1
	if splitPosition == -2 {
		splitPosition = len(query)
		if query[splitPosition-1] == ';' {
			splitPosition -= 1
		}
	}

	return query[:splitPosition] + " ORDER BY " + orderStr + query[splitPosition:]
}

// Injects the filter (WHERE and ORDER BY) to the query.
//
// If the column being filtered by is not present in the filterToColumnMap but is present in the
// filter definition in the middleware, no error will happen. This is because you may want to apply
// specific filters in a query, and other filters in other queries.
//
// Note: May fail if the query has a JOIN, and does not have a WHERE clause. This can be botched by
// adding a WHERE TRUE clause, or, if you feel like it, editing string manipulation code to
// contemplate that case.
func AddFilterToQuery(f *humamw.FilterGroup, whereToColumnMap map[string]string,
	orderToColumnMap map[string]string, query string, params []any) (string, []any, error) {

	query = cleanQuery(query)
	lastParam := getLastParamIndex(query)

	newParams, errList := getParams(f, params)

	newQuery, err := addWhereToQuery(f, whereToColumnMap, query, lastParam)
	if err != nil {
		errList = append(errList, err)
	}

	// Only attempt to add ordering if we still have a non-empty query string.
	// This avoids passing an empty or invalid query to addOrderToQuery, which
	// may assume the query is well-formed.
	if newQuery != "" {
		newQuery = addOrderToQuery(f, orderToColumnMap, newQuery)
	}

	if len(errList) != 0 {
		return "", nil, validation.NewErrValidation(errList)
	}

	return newQuery, newParams, nil
}
