//go:build !windows

package executor

import (
	"context"
	"errors"
)

func ListProcessIDsByExecutable(context.Context, string) ([]int, error) {
	return nil, errors.New("windows executable process query is unavailable on this platform")
}

func TerminateProcessByPID(context.Context, int) error {
	return errors.New("windows process termination is unavailable on this platform")
}
