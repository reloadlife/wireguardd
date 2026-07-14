package netutil

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestValidateCIDR(t *testing.T) {
	require.NoError(t, ValidateCIDR("10.0.0.1/24"))
	require.NoError(t, ValidateCIDR("fd00::1/64"))
	require.Error(t, ValidateCIDR("10.0.0.1"))
	require.Error(t, ValidateCIDR("not-an-ip/24"))
	require.Error(t, ValidateCIDR(""))
}

func TestValidateEndpoint(t *testing.T) {
	require.NoError(t, ValidateEndpoint(""))
	require.NoError(t, ValidateEndpoint("vpn.example.com:51820"))
	require.NoError(t, ValidateEndpoint("1.2.3.4:51820"))
	require.Error(t, ValidateEndpoint("no-port"))
	require.Error(t, ValidateEndpoint(":51820"))
}

func TestAllocateNextHost(t *testing.T) {
	used := CollectUsedHosts(
		[]string{"10.7.0.1/24"},
		[][]string{{"10.7.0.2"}},
		[][]string{{"10.7.0.3/32"}},
	)
	assigned, allowed, err := AllocateNextHost([]string{"10.7.0.1/24"}, used)
	require.NoError(t, err)
	require.Equal(t, "10.7.0.4", assigned)
	require.Equal(t, "10.7.0.4/32", allowed)
}

func TestAllocateSkipsIfaceIP(t *testing.T) {
	assigned, _, err := AllocateNextHost([]string{"172.20.0.1/24"}, nil)
	require.NoError(t, err)
	require.Equal(t, "172.20.0.2", assigned)
}

func TestIsAutoToken(t *testing.T) {
	require.True(t, IsAutoToken(""))
	require.True(t, IsAutoToken("auto"))
	require.True(t, IsAutoToken(" * "))
	require.False(t, IsAutoToken("10.0.0.2/32"))
}
