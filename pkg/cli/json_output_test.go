package cli

import (
	"bytes"
	"io"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func captureStdout(f func()) string {
	old := os.Stdout
	r, w, _ := os.Pipe()
	os.Stdout = w

	f()

	_ = w.Close()
	os.Stdout = old
	var buf bytes.Buffer
	_, _ = io.Copy(&buf, r)
	return buf.String()
}

func TestRenderJSON_SimpleMap(t *testing.T) {
	output := captureStdout(func() {
		err := RenderJSON(map[string]string{"key": "value"})
		require.NoError(t, err)
	})

	assert.Contains(t, output, `"key": "value"`)
}

func TestRenderJSON_Struct(t *testing.T) {
	type item struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	output := captureStdout(func() {
		err := RenderJSON(item{Name: "test", Count: 42})
		require.NoError(t, err)
	})

	assert.Contains(t, output, `"name": "test"`)
	assert.Contains(t, output, `"count": 42`)
}

func TestRenderJSON_InvalidValue(t *testing.T) {
	err := RenderJSON(make(chan int))
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to marshal JSON")
}
