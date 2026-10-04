package blobstore

import (
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/stretchr/testify/require"
)

func TestIsS3NotFound(t *testing.T) {
	require.True(t, isS3NotFound(&types.NoSuchKey{}))
	require.True(t, isS3NotFound(&smithy.GenericAPIError{Code: "NotFound"}))
	require.False(t, isS3NotFound(&smithy.GenericAPIError{Code: "NoSuchBucket"}), "a missing bucket is a storage failure, not a missing blob")
	require.False(t, isS3NotFound(nil))
}

func TestNewS3FailsOnMissingBucket(t *testing.T) {
	var status atomic.Int32
	status.Store(http.StatusNotFound)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(int(status.Load()))
	}))
	t.Cleanup(srv.Close)

	cfg := S3Config{Bucket: "b", Region: "us-east-1", Endpoint: srv.URL, AccessKey: "k", SecretKey: "s", ForcePathStyle: true, TempDir: t.TempDir()}

	_, err := NewS3(cfg, nopLog())
	require.ErrorContains(t, err, `checking S3 bucket "b"`)

	status.Store(http.StatusOK)
	_, err = NewS3(cfg, nopLog())
	require.NoError(t, err)
}

func TestS3ReaderRejectsReadAfterClose(t *testing.T) {
	r := &s3ReadSeekCloser{}
	require.NoError(t, r.Close())
	_, err := r.Read(make([]byte, 1))
	require.ErrorIs(t, err, os.ErrClosed)
}
