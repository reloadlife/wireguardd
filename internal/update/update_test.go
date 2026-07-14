package update

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeVersion(t *testing.T) {
	require.Equal(t, "0.7.1", normalizeVersion("v0.7.1"))
	require.Equal(t, "0.7.1", normalizeVersion("v0.7.1-dirty"))
	require.Equal(t, "0.7.1", normalizeVersion("v0.7.1-5-gdeadbeef"))
	require.Equal(t, "0.7.1", normalizeVersion("0.7.1"))
}

func TestAssetNameFormat(t *testing.T) {
	n := assetName(ComponentDaemon, "v0.7.1")
	require.True(t, strings.HasPrefix(n, "wireguardd_0.7.1_linux_"))
	require.True(t, strings.HasSuffix(n, ".tar.gz"))

	n = assetName(ComponentCtl, "v0.7.1")
	require.True(t, strings.HasPrefix(n, "wireguardctl_0.7.1_"))
	require.True(t, strings.HasSuffix(n, ".tar.gz"))
}

func TestVersionsEqual(t *testing.T) {
	require.True(t, versionsEqual("v0.7.1", "0.7.1"))
	require.True(t, versionsEqual("v0.7.1-dirty", "v0.7.1"))
	require.False(t, versionsEqual("v0.7.0", "v0.7.1"))
}
