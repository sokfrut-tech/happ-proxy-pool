//go:build android

package libXray

import (
	"os"
	"strconv"
)

// SetTunFd exposes Xray-core's Android TUN descriptor setting to the Java host.
// Xray-core reads this from the Go process environment when constructing the
// Android TUN inbound. Putting the value in the Xray JSON has no effect.
func SetTunFd(fd int32) error {
	if fd < 0 {
		return os.ErrInvalid
	}
	return os.Setenv("xray.tun.fd", strconv.FormatInt(int64(fd), 10))
}

// ResetTunFd removes the descriptor after Xray has stopped or failed to start.
func ResetTunFd() error {
	return os.Unsetenv("xray.tun.fd")
}
