//go:build windows

package apply

// NoFollowFlag is the platform-appropriate O_NOFOLLOW bit for os.OpenFile.
// On Windows it is 0 because Go's os/syscall packages do not expose
// O_NOFOLLOW; the symlink-at-open guard is enforced by SecureOpenOutput's
// os.Lstat pre-check.
const NoFollowFlag = 0
