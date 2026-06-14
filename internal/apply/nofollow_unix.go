//go:build !windows

package apply

import "os"

// NoFollowFlag is the platform-appropriate O_NOFOLLOW bit for os.OpenFile.
// On Unix-like systems it is os.O_NOFOLLOW; on Windows it is 0 because the
// Go runtime does not expose O_NOFOLLOW. Callers that need to refuse
// symlink targets on Windows must Lstat the path first; see SecureOpenOutput.
const NoFollowFlag = os.O_NOFOLLOW
