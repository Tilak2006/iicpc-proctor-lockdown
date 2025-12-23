package linux

import (
	"errors"

	"golang.org/x/sys/unix"
)

// IsUnsupported reports whether the kernel/driver does not support
// the requested network enforcement operation.
func IsUnsupported(err error) bool {
	return errors.Is(err, unix.EOPNOTSUPP)
}
