package blobstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"git.ow-ops.eu/ow-ops/apoci/internal/validate"
)

// ErrBlobNotFound is returned by Open when the requested blob does not exist.
var ErrBlobNotFound = errors.New("blob not found")

// BlobStore is the interface for content-addressable blob storage.
type BlobStore interface {
	Put(ctx context.Context, r io.Reader, expectedDigest string) (digest string, size int64, err error)
	// Open returns a seekable reader for the blob and its size. Returns
	// ErrBlobNotFound if the blob does not exist. The returned reader is not safe
	// for concurrent use.
	Open(ctx context.Context, digest string) (io.ReadSeekCloser, int64, error)
	// Exists reports whether the blob is present in the store.
	// Returns an error on storage failure; callers must not treat an error as "not found".
	Exists(ctx context.Context, digest string) (bool, error)
	// Size returns the blob size. ErrBlobNotFound if absent.
	Size(ctx context.Context, digest string) (int64, error)
	// Delete removes the blob. It is not an error if the blob does not exist.
	Delete(ctx context.Context, digest string) error
	// ListDigests returns the digests it could enumerate. Unreadable parts of the
	// store are skipped (and logged) so one bad shard doesn't block GC.
	ListDigests(ctx context.Context) ([]string, error)
	ModTime(ctx context.Context, digest string) (time.Time, error)
	// DeleteIfOlder removes the blob only if it was last modified at or before
	// cutoff, re-checking at delete time so a concurrent re-upload isn't reaped.
	// A zero cutoff deletes unconditionally. Reports whether it was deleted.
	DeleteIfOlder(ctx context.Context, digest string, cutoff time.Time) (bool, error)
	// CleanStaleTemp removes upload staging files untouched for at least maxAge
	// and returns how many it handled (blobs restored from an interrupted
	// DeleteIfOlder count too).
	CleanStaleTemp(ctx context.Context, maxAge time.Duration) (int, error)
}

type Store struct {
	root   string
	logger *slog.Logger
}

func New(dataDir string, logger *slog.Logger) (*Store, error) {
	root := filepath.Join(dataDir, "blobs", "sha256")
	if err := os.MkdirAll(root, 0o750); err != nil {
		return nil, fmt.Errorf("creating blob directory: %w", err)
	}
	s := &Store{root: root, logger: logger}
	s.removeStaleTempFiles()
	return s, nil
}

// removeStaleTempFiles deletes ".upload-*" staging files left in the blob root
// by an interrupted Put. They sit outside the two-char shards, so ListDigests
// (and thus GC) never sees them. Safe at startup: no Put is in flight.
func (s *Store) removeStaleTempFiles() {
	removeTempFiles(s.logger, s.root, 0, ".upload-*")
	s.recoverTrash()
}

// CleanStaleTemp removes staging files from interrupted Puts while the server
// keeps running. In-flight Puts keep touching their file, so only files idle for
// maxAge are removed.
func (s *Store) CleanStaleTemp(_ context.Context, maxAge time.Duration) (int, error) {
	n := removeTempFiles(s.logger, s.root, maxAge, ".upload-*")
	return n + s.recoverTrash(), nil
}

// recoverTrash resolves ".trash-*" files left by a DeleteIfOlder that was
// interrupted between moving a blob aside and deciding its fate. The blob goes
// back unless a newer copy exists; GC re-evaluates it on its next pass. Callers
// must not run it concurrently with DeleteIfOlder.
func (s *Store) recoverTrash() int {
	matches, err := filepath.Glob(filepath.Join(s.root, ".trash-*"))
	if err != nil {
		s.logger.Warn("blobstore: globbing trashed blobs failed", "error", err)
		return 0
	}
	recovered := 0
	for _, m := range matches {
		hash := strings.TrimPrefix(filepath.Base(m), ".trash-")
		if !hexDigestRe.MatchString(hash) {
			continue
		}
		path := filepath.Join(s.root, hash[:2], hash)
		if _, err := os.Stat(path); err == nil {
			_ = os.Remove(m)
			continue
		}
		if err := os.Rename(m, path); err != nil {
			s.logger.Warn("blobstore: restoring trashed blob failed", "path", m, "error", err)
			continue
		}
		s.logger.Info("blobstore: restored blob from interrupted delete", "digest", "sha256:"+hash)
		recovered++
	}
	return recovered
}

// removeTempFiles deletes files in dir matching the glob patterns whose mtime is
// at least maxAge old (maxAge <= 0 removes all matches) and returns the count.
func removeTempFiles(logger *slog.Logger, dir string, maxAge time.Duration, patterns ...string) int {
	cutoff := time.Now().Add(-maxAge)
	removed := 0
	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(dir, pattern))
		if err != nil {
			logger.Warn("blobstore: globbing stale temp files failed", "pattern", pattern, "error", err)
			continue
		}
		for _, m := range matches {
			if maxAge > 0 {
				fi, err := os.Stat(m)
				if err != nil || fi.ModTime().After(cutoff) {
					continue
				}
			}
			if err := os.Remove(m); err != nil {
				logger.Warn("blobstore: removing stale temp file failed", "path", m, "error", err)
				continue
			}
			logger.Info("blobstore: removed stale temp file", "path", m)
			removed++
		}
	}
	return removed
}

func (s *Store) Put(_ context.Context, r io.Reader, expectedDigest string) (digest string, size int64, err error) {
	if expectedDigest != "" {
		if err := validate.Digest(expectedDigest); err != nil {
			return "", 0, fmt.Errorf("invalid expected digest: %w", err)
		}
	}

	tmp, err := os.CreateTemp(s.root, ".upload-*")
	if err != nil {
		return "", 0, fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath := tmp.Name()
	defer func() {
		_ = tmp.Close()
		if err != nil {
			_ = os.Remove(tmpPath)
		}
	}()

	h := sha256.New()
	w := io.MultiWriter(tmp, h)

	size, err = io.Copy(w, r)
	if err != nil {
		return "", 0, fmt.Errorf("writing blob: %w", err)
	}

	if err = tmp.Sync(); err != nil {
		return "", 0, fmt.Errorf("syncing blob: %w", err)
	}

	computed := "sha256:" + hex.EncodeToString(h.Sum(nil))

	if expectedDigest != "" && computed != expectedDigest {
		return "", 0, fmt.Errorf("digest mismatch: expected %s, got %s", expectedDigest, computed)
	}

	finalPath, err := s.pathForDigest(computed) // computed digest is always valid
	if err != nil {
		return "", 0, fmt.Errorf("unexpected invalid computed digest %s: %w", computed, err)
	}
	if err = os.MkdirAll(filepath.Dir(finalPath), 0o750); err != nil {
		return "", 0, fmt.Errorf("creating blob subdirectory: %w", err)
	}

	if err = os.Rename(tmpPath, finalPath); err != nil {
		return "", 0, fmt.Errorf("moving blob to final path: %w", err)
	}

	s.logger.Debug("blob stored", "digest", computed, "size", size)
	return computed, size, nil
}

func (s *Store) Open(_ context.Context, digest string) (io.ReadSeekCloser, int64, error) {
	path, err := s.pathForDigest(digest)
	if err != nil {
		return nil, 0, err
	}
	f, err := os.Open(path) //nolint:gosec // path is constructed from content-addressable digest
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, 0, ErrBlobNotFound
		}
		return nil, 0, fmt.Errorf("opening blob: %w", err)
	}
	fi, err := f.Stat()
	if err != nil {
		_ = f.Close()
		return nil, 0, fmt.Errorf("statting blob: %w", err)
	}
	return f, fi.Size(), nil
}

func (s *Store) Exists(_ context.Context, digest string) (bool, error) {
	path, err := s.pathForDigest(digest)
	if err != nil {
		return false, nil // invalid digest is simply not found
	}
	_, err = os.Stat(path)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	return false, fmt.Errorf("checking blob existence: %w", err)
}

func (s *Store) Size(_ context.Context, digest string) (int64, error) {
	path, err := s.pathForDigest(digest)
	if err != nil {
		return 0, err
	}
	fi, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return 0, ErrBlobNotFound
		}
		return 0, fmt.Errorf("statting blob: %w", err)
	}
	return fi.Size(), nil
}

func (s *Store) ModTime(_ context.Context, digest string) (time.Time, error) {
	path, err := s.pathForDigest(digest)
	if err != nil {
		return time.Time{}, err
	}
	fi, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return time.Time{}, ErrBlobNotFound
		}
		return time.Time{}, fmt.Errorf("statting blob: %w", err)
	}
	return fi.ModTime(), nil
}

func (s *Store) Delete(_ context.Context, digest string) error {
	path, err := s.pathForDigest(digest)
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("deleting blob: %w", err)
	}
	return nil
}

// DeleteIfOlder moves the file aside before inspecting it: a concurrent Put
// renames a new file onto the final path, so inspecting the moved inode tells us
// whether we are holding the old orphan or a fresh upload. A fresh one is put
// back; blobs are content-addressed, so restoring over a racing Put is harmless.
func (s *Store) DeleteIfOlder(ctx context.Context, digest string, cutoff time.Time) (bool, error) {
	if cutoff.IsZero() {
		return true, s.Delete(ctx, digest)
	}
	path, err := s.pathForDigest(digest)
	if err != nil {
		return false, err
	}
	trash := filepath.Join(s.root, ".trash-"+strings.TrimPrefix(digest, "sha256:"))
	if err := os.Rename(path, trash); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return false, nil
		}
		return false, fmt.Errorf("moving blob aside: %w", err)
	}
	fi, err := os.Stat(trash)
	if err != nil {
		return false, fmt.Errorf("statting moved blob: %w", err)
	}
	if fi.ModTime().After(cutoff) {
		if err := os.Rename(trash, path); err != nil {
			return false, fmt.Errorf("restoring recently modified blob: %w", err)
		}
		return false, nil
	}
	if err := os.Remove(trash); err != nil {
		return false, fmt.Errorf("deleting blob: %w", err)
	}
	return true, nil
}

var hexDigestRe = regexp.MustCompile(`^[a-f0-9]{64}$`)

func (s *Store) ListDigests(_ context.Context) ([]string, error) {
	var digests []string

	subdirs, err := os.ReadDir(s.root)
	if err != nil {
		return nil, fmt.Errorf("reading blob root: %w", err)
	}
	for _, subdir := range subdirs {
		if !subdir.IsDir() || len(subdir.Name()) != 2 {
			continue
		}
		entries, err := os.ReadDir(filepath.Join(s.root, subdir.Name()))
		if err != nil {
			s.logger.Warn("blobstore: skipping unreadable blob subdir", "subdir", subdir.Name(), "error", err)
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			if !hexDigestRe.MatchString(entry.Name()) {
				continue
			}
			digests = append(digests, "sha256:"+entry.Name())
		}
	}
	return digests, nil
}

func (s *Store) pathForDigest(digest string) (string, error) {
	if err := validate.Digest(digest); err != nil {
		return "", err
	}
	hash := strings.TrimPrefix(digest, "sha256:")
	return filepath.Join(s.root, hash[:2], hash), nil
}
