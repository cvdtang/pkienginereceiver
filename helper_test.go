package pkienginereceiver

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToStringSlice(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    interface{}
		expected []string
	}{
		{
			// When given a interface of slice string check if returns slice of strings.
			name:     "Valid []interface{} containing strings",
			input:    interface{}([]interface{}{"hello", "world"}),
			expected: []string{"hello", "world"},
		},
		{
			name:     "Input is nil",
			input:    nil,
			expected: nil,
		},
		{
			// Test: "if !ok return nil" (e.g., passing an int or a direct []string)
			name:     "Type assertion fails (!ok)",
			input:    "not a slice",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := toStringSlice(tt.input)
			assert.Equal(t, tt.expected, got)
		})
	}
}
