package blobstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

var ctx = context.Background()

func testStore(t *testing.T) *Store {
	t.Helper()
	dir := t.TempDir()
	s, err := New(dir, nopLog())
	require.NoError(t, err)
	return s
}

func mustExist(t *testing.T, s BlobStore, digest string) {
	t.Helper()
	ok, err := s.Exists(ctx, digest)
	require.NoError(t, err)
	require.True(t, ok)
}

func mustNotExist(t *testing.T, s BlobStore, digest string) {
	t.Helper()
	ok, err := s.Exists(ctx, digest)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestPutAndOpen(t *testing.T) {
	s := testStore(t)

	data := []byte("hello world")
	digest, size, err := s.Put(ctx, bytes.NewReader(data), "")
	require.NoError(t, err)
	require.Equal(t, int64(len(data)), size)
	require.NotEmpty(t, digest, "expected non-empty digest")

	f, _, err := s.Open(ctx, digest)
	require.NoError(t, err)
	require.NotNil(t, f)
	defer func() { _ = f.Close() }()

	got, err := io.ReadAll(f)
	require.NoError(t, err)
	require.True(t, bytes.Equal(got, data))
}

func TestPutWithExpectedDigest(t *testing.T) {
	s := testStore(t)

	data := []byte("hello world")
	digest, _, err := s.Put(ctx, bytes.NewReader(data), "")
	require.NoError(t, err)

	digest2, _, err := s.Put(ctx, bytes.NewReader(data), digest)
	require.NoError(t, err)
	require.Equal(t, digest, digest2)
}

func TestPutWithWrongDigest(t *testing.T) {
	s := testStore(t)

	data := []byte("hello world")
	_, _, err := s.Put(ctx, bytes.NewReader(data), "sha256:0000000000000000000000000000000000000000000000000000000000000000")
	require.Error(t, err, "expected error for wrong digest")
}

func TestExists(t *testing.T) {
	s := testStore(t)

	mustNotExist(t, s, "sha256:0000000000000000000000000000000000000000000000000000000000000000")

	data := []byte("test data")
	digest, _, _ := s.Put(ctx, bytes.NewReader(data), "")

	mustExist(t, s, digest)
}

func TestDelete(t *testing.T) {
	s := testStore(t)

	data := []byte("delete me")
	digest, _, _ := s.Put(ctx, bytes.NewReader(data), "")

	mustExist(t, s, digest)
	require.NoError(t, s.Delete(ctx, digest))
	mustNotExist(t, s, digest)
}

func TestDeleteNonexistent(t *testing.T) {
	s := testStore(t)
	require.NoError(t, s.Delete(ctx, "sha256:0000000000000000000000000000000000000000000000000000000000000000"))
}

func TestPathTraversalRejected(t *testing.T) {
	s := testStore(t)

	malicious := []string{
		"sha256:../../../etc/passwd",
		"sha256:..%2F..%2Fetc%2Fpasswd",
		"notsha256:abcd",
		"sha256:short",
		"sha256:ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789", // uppercase
		"",
	}

	for _, d := range malicious {
		mustNotExist(t, s, d)
		_, _, err := s.Open(ctx, d)
		require.Error(t, err, "Open should error for malicious digest %q", d)
	}
}

func nopLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestNewRemovesStaleTempFiles(t *testing.T) {
	dir := t.TempDir()
	root := filepath.Join(dir, "blobs", "sha256")
	require.NoError(t, os.MkdirAll(root, 0o750))

	stale := filepath.Join(root, ".upload-abc123")
	require.NoError(t, os.WriteFile(stale, []byte("partial blob"), 0o600))
	// A real committed blob in a shard must survive.
	shard := filepath.Join(root, "ab")
	require.NoError(t, os.MkdirAll(shard, 0o750))
	keep := filepath.Join(shard, "abdeadbeef")
	require.NoError(t, os.WriteFile(keep, []byte("blob"), 0o600))

	_, err := New(dir, nopLog())
	require.NoError(t, err)

	_, err = os.Stat(stale)
	require.True(t, os.IsNotExist(err), "stale temp file should be removed")
	_, err = os.Stat(keep)
	require.NoError(t, err, "committed blob must survive")
}

func TestListDigestsSkipsUnreadableShard(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("permission checks don't apply to root")
	}
	s := testStore(t)

	good, _, err := s.Put(ctx, bytes.NewReader([]byte("good")), "")
	require.NoError(t, err)
	bad, _, err := s.Put(ctx, bytes.NewReader([]byte("bad")), "")
	require.NoError(t, err)

	badShard := filepath.Join(s.root, bad[len("sha256:"):][:2])
	require.NoError(t, os.Chmod(badShard, 0o000))
	t.Cleanup(func() { _ = os.Chmod(badShard, 0o700) }) //nolint:gosec // directory needs the execute bit restored for TempDir cleanup

	digests, err := s.ListDigests(ctx)
	require.NoError(t, err)
	require.Contains(t, digests, good)
	require.NotContains(t, digests, bad)
}

func TestDeleteIfOlder(t *testing.T) {
	s := testStore(t)
	digest, _, err := s.Put(ctx, bytes.NewReader([]byte("orphan")), "")
	require.NoError(t, err)
	path, err := s.pathForDigest(digest)
	require.NoError(t, err)

	t.Run("fresh blob is kept", func(t *testing.T) {
		deleted, err := s.DeleteIfOlder(ctx, digest, time.Now().Add(-time.Hour))
		require.NoError(t, err)
		require.False(t, deleted)
		mustExist(t, s, digest)
		entries, err := filepath.Glob(filepath.Join(s.root, ".trash-*"))
		require.NoError(t, err)
		require.Empty(t, entries, "no trash left behind")
	})

	t.Run("old blob is deleted", func(t *testing.T) {
		old := time.Now().Add(-2 * time.Hour)
		require.NoError(t, os.Chtimes(path, old, old))
		deleted, err := s.DeleteIfOlder(ctx, digest, time.Now().Add(-time.Hour))
		require.NoError(t, err)
		require.True(t, deleted)
		mustNotExist(t, s, digest)
	})

	t.Run("missing blob is not an error", func(t *testing.T) {
		deleted, err := s.DeleteIfOlder(ctx, digest, time.Now())
		require.NoError(t, err)
		require.False(t, deleted)
	})

	t.Run("zero cutoff deletes unconditionally", func(t *testing.T) {
		d, _, err := s.Put(ctx, bytes.NewReader([]byte("fresh")), "")
		require.NoError(t, err)
		deleted, err := s.DeleteIfOlder(ctx, d, time.Time{})
		require.NoError(t, err)
		require.True(t, deleted)
		mustNotExist(t, s, d)
	})
}

func TestCleanStaleTempKeepsInFlightFiles(t *testing.T) {
	s := testStore(t)
	stale := filepath.Join(s.root, ".upload-stale")
	fresh := filepath.Join(s.root, ".upload-fresh")
	require.NoError(t, os.WriteFile(stale, []byte("x"), 0o600))
	require.NoError(t, os.WriteFile(fresh, []byte("x"), 0o600))
	old := time.Now().Add(-2 * time.Hour)
	require.NoError(t, os.Chtimes(stale, old, old))

	n, err := s.CleanStaleTemp(ctx, time.Hour)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	_, err = os.Stat(stale)
	require.True(t, os.IsNotExist(err))
	_, err = os.Stat(fresh)
	require.NoError(t, err, "an in-flight upload must survive")
}

func TestRecoverTrashRestoresInterruptedDelete(t *testing.T) {
	s := testStore(t)
	digest, _, err := s.Put(ctx, bytes.NewReader([]byte("interrupted")), "")
	require.NoError(t, err)
	path, err := s.pathForDigest(digest)
	require.NoError(t, err)
	hash := digest[len("sha256:"):]
	trash := filepath.Join(s.root, ".trash-"+hash)

	// A crash after the move-aside leaves the blob only under its trash name.
	require.NoError(t, os.Rename(path, trash))
	mustNotExist(t, s, digest)

	n, err := s.CleanStaleTemp(ctx, time.Hour)
	require.NoError(t, err)
	require.Equal(t, 1, n)
	mustExist(t, s, digest)
	_, err = os.Stat(trash)
	require.True(t, os.IsNotExist(err))

	// A trash file shadowed by a newer copy is just discarded.
	require.NoError(t, os.WriteFile(trash, []byte("interrupted"), 0o600))
	n, err = s.CleanStaleTemp(ctx, time.Hour)
	require.NoError(t, err)
	require.Zero(t, n)
	mustExist(t, s, digest)
	_, err = os.Stat(trash)
	require.True(t, os.IsNotExist(err))
}

func TestAdoptFileMovesStagedFileIntoStore(t *testing.T) {
	s := testStore(t)
	data := []byte("staged chunked upload")
	digest := "sha256:" + hex.EncodeToString(sha256Sum(data))

	staged := filepath.Join(t.TempDir(), "upload-1")
	require.NoError(t, os.WriteFile(staged, data, 0o600))
	old := time.Now().Add(-3 * time.Hour)
	require.NoError(t, os.Chtimes(staged, old, old))

	size, err := s.AdoptFile(ctx, staged, digest)
	if errors.Is(err, ErrCrossDevice) {
		t.Skip("temp dirs are on different filesystems")
	}
	require.NoError(t, err)
	require.Equal(t, int64(len(data)), size)

	_, err = os.Stat(staged)
	require.True(t, os.IsNotExist(err), "staged file must be consumed")
	mustExist(t, s, digest)

	mtime, err := s.ModTime(ctx, digest)
	require.NoError(t, err)
	require.WithinDuration(t, time.Now(), mtime, time.Minute, "adopted blob needs a fresh mtime so GC's grace period applies")

	_, err = s.AdoptFile(ctx, staged, "not-a-digest")
	require.Error(t, err)
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
