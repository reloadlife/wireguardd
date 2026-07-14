package tui

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRenderQR(t *testing.T) {
	s, err := RenderQR("[Interface]\nPrivateKey = abc\n")
	require.NoError(t, err)
	require.True(t, strings.Contains(s, "█") || strings.Contains(s, "▀") || strings.Contains(s, "▄") || len(s) > 20)
}
