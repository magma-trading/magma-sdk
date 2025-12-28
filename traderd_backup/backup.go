package backup

import (
  "fmt"
  "io"
  "os"
  "path/filepath"
)

// RotateAndBackupTraderDB looks for ./traderd.db.
// If present, it rotates backups traderd.db_1..traderd.db_5 and then creates traderd.db_1.
func RotateAndBackupTraderDB() error {
	const base = "traderd.db"
	src := filepath.Clean(base)

	// If traderd.db doesn't exist, nothing to do.
	if _, err := os.Stat(src); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("stat %s: %w", src, err)
	}

	// Rotate: _4 -> _5, _3 -> _4, ..., _1 -> _2 (only if exists)
	for i := 4; i >= 1; i-- {
		oldName := fmt.Sprintf("%s_%d", base, i)
		newName := fmt.Sprintf("%s_%d", base, i+1)

		if _, err := os.Stat(oldName); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return fmt.Errorf("stat %s: %w", oldName, err)
		}

		// Remove target if it exists (so rename won't fail on Windows etc.)
		_ = os.Remove(newName)

		if err := os.Rename(oldName, newName); err != nil {
			return fmt.Errorf("rename %s -> %s: %w", oldName, newName, err)
		}
	}

	// Copy traderd.db -> traderd.db_1
	dst := fmt.Sprintf("%s_1", base)
	if err := copyFileAtomic(src, dst); err != nil {
		return fmt.Errorf("copy %s -> %s: %w", src, dst, err)
	}

	return nil
}

// copyFileAtomic copies src to dst via a temp file + rename (best-effort atomic).
func copyFileAtomic(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	dir := filepath.Dir(dst)
	tmp, err := os.CreateTemp(dir, filepath.Base(dst)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()

	// If anything fails, clean up temp file.
	defer func() {
		_ = tmp.Close()
		_ = os.Remove(tmpName)
	}()

	if _, err := io.Copy(tmp, in); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}

	// Ensure dst doesn't exist, then swap in.
	_ = os.Remove(dst)
	return os.Rename(tmpName, dst)
}
