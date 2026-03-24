package errors

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
)

type TrackedVarFile struct {
	file string
	vars map[string]any
}

type TrackedError struct {
	stackTrace string
	err        error
	vars       []TrackedVarFile
}

const red = "\033[31m"
const yellow = "\033[33m"
const green = "\033[32m"
const blue = "\033[34m"
const reset = "\033[0m"
const bold = "\033[1m"

func (e *TrackedError) Error() string {
	var sb strings.Builder

	// Print the main error in red
	sb.WriteString(fmt.Sprintf("%s%v%s\n", red, e.err, reset))

	// Print tracked vars if any
	sb.WriteString(bold)
	sb.WriteString(yellow)
	sb.WriteString("Tracked variables:\n")
	sb.WriteString(reset)
	for _, tv := range e.vars {
		sb.WriteString(bold)
		sb.WriteString(yellow)
		sb.WriteString(fmt.Sprintf("  %s%s%s:\n", green, tv.file, reset))
		for k, v := range tv.vars {
			sb.WriteString(fmt.Sprintf("  - %s%s%s%s: %#v\n", blue, bold, k, reset, v))
		}
	}

	// Print stack trace header + stack trace
	sb.WriteString(bold)
	sb.WriteString(yellow)
	sb.WriteString("Stack trace:\n")
	sb.WriteString(reset)
	sb.WriteString(e.stackTrace)

	return sb.String()
}

func (e *TrackedError) Unwrap() error {
	return e.err
}

func captureStackTrace(skip int) string {
	var pcs [32]uintptr
	n := runtime.Callers(skip+2, pcs[:])
	frames := runtime.CallersFrames(pcs[:n])

	var sb strings.Builder
	for {
		frame, more := frames.Next()
		sb.WriteString(fmt.Sprintf("%s\n\t%s:%d\n", frame.Function, frame.File, frame.Line))
		if !more {
			break
		}
	}
	return sb.String()
}

func captureStackTraceUpToFile(stopFile string, skip int) string {
	const maxDepth = 32
	pcs := make([]uintptr, maxDepth)
	n := runtime.Callers(skip+2, pcs) // +2 to skip captureStackTraceUpToFile and TrackError
	frames := runtime.CallersFrames(pcs[:n])

	var stack []string
	for {
		frame, more := frames.Next()

		fullPath := frame.File
		fileName := filepath.Base(fullPath)

		coloredPath := fmt.Sprintf("%s%s", red, fileName)
		pathWithColoredFile := fmt.Sprintf("%s", fullPath[:len(fullPath)-len(fileName)]) + coloredPath

		stack = append(stack, fmt.Sprintf("%s\n\t%s:%d%s", frame.Function, pathWithColoredFile, frame.Line, reset))

		if strings.HasSuffix(frame.File, stopFile) {
			break
		}
		if !more {
			break
		}
	}

	return strings.Join(stack, "\n")
}

func printCallerLine(skip int) string {
	_, file, line, ok := runtime.Caller(skip)
	if !ok {
		fmt.Println("Unable to get caller info")
		return ""
	}
	return fmt.Sprintf("%s:%d", filepath.Base(file), line)
}

func appendArgs(err *TrackedError, vars map[string]any) {
	file := printCallerLine(3)

	if len(vars) != 0 {
		err.vars = append(err.vars, TrackedVarFile{
			file: file,
			vars: vars,
		})
	}
}

func TrackError(err error) error {
	if err == nil {
		return nil
	}

	var trackedErr *TrackedError
	if errors.As(err, &trackedErr) {
		return err
	}

	stackTrace := captureStackTraceUpToFile("api/api.go", 1)

	trackedErr = &TrackedError{
		stackTrace: stackTrace,
		err:        err,
	}
	return trackedErr
}

func TrackErrorVar(err error, vars map[string]any) error {
	if err == nil {
		return nil
	}

	var trackedErr *TrackedError
	if errors.As(err, &trackedErr) {
		appendArgs(trackedErr, vars)
		return err
	}

	stackTrace := captureStackTraceUpToFile("api/api.go", 1)

	trackedErr = &TrackedError{
		stackTrace: stackTrace,
		err:        err,
	}
	appendArgs(trackedErr, vars)
	return trackedErr
}
