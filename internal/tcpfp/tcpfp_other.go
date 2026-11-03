//go:build !linux

package tcpfp

import (
	"errors"
	"net"
)

// StartSYNCapture is only supported on Linux.
func StartSYNCapture(ports []int) (*SynTable, error) {
	return nil, errors.New("tcpfp: SYN capture is only supported on Linux")
}

// GetInfo is only supported on Linux.
func GetInfo(c net.Conn) *Info { return nil }
