//go:build linux

package apply

import "syscall"

// NoFollowFlag is the platform-appropriate O_NOFOLLOW bit for os.OpenFile.
// On Linux it is syscall.O_NOFOLLOW; on Windows it is 0 (see
// nofollow_windows.go). The Lstat pre-check in SecureOpenOutput closes the
// same TOCTOU window on platforms that do not expose O_NOFOLLOW.
const NoFollowFlag = syscall.O_NOFOLLOW
