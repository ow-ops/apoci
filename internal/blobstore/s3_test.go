package blobstore

import (
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
