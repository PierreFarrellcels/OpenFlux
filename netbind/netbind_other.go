//go:build !windows && !linux

package netbind

import "errors"

// BindDefault is only needed (and implemented) for the full tunnel on
// Windows and Linux.
func BindDefault() (uint32, error) {
	return 0, errors.New("привязка к интерфейсу есть только в Windows и Linux")
}
