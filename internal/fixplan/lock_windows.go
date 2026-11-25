//go:build windows

package fixplan

import (
	"os"

	"golang.org/x/sys/windows"
)

func lockFileNonBlocking(f *os.File) error {
	var ol windows.Overlapped
	err := windows.LockFileEx(
		windows.Handle(f.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0,
		^uint32(0),
		^uint32(0),
		&ol,
	)
	if err == windows.ERROR_LOCK_VIOLATION {
		return ErrLocked
	}

	return err
}

func unlockFile(f *os.File) error {
	var ol windows.Overlapped

	return windows.UnlockFileEx(windows.Handle(f.Fd()), 0, ^uint32(0), ^uint32(0), &ol)
}
