package fixplan

import (
	"errors"
	"os"
	"path/filepath"
)

type fileLock struct {
	path string
	f    *os.File
}

func acquireApplyLock(stateDir string) (*fileLock, error) {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return nil, err
	}
	path := filepath.Join(stateDir, "apply.lock")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, err
	}
	if err := lockFileNonBlocking(f); err != nil {
		_ = f.Close()
		if errors.Is(err, ErrLocked) {
			return nil, &ApplyError{Code: CodeLocked, Message: "another fix apply is already running; retry after it exits"}
		}

		return nil, err
	}

	return &fileLock{path: path, f: f}, nil
}

func (l *fileLock) Release() error {
	if l == nil || l.f == nil {
		return nil
	}
	err := unlockFile(l.f)
	closeErr := l.f.Close()
	if err != nil {
		return err
	}

	return closeErr
}
