package pkienginereceiver

// Converts a []any value into a []string.
func toStringSlice(i any) []string {
	raw, ok := i.([]any)
	if !ok {
		return nil
	}

	res := make([]string, len(raw))
	for i, v := range raw {
		res[i], _ = v.(string) // Defaults to "" if not a string
	}

	return res
}

// Converts a []string value into a []any.
func toAnySlice(values []string) []any {
	attrs := make([]any, 0, len(values))
	for _, value := range values {
		attrs = append(attrs, value)
	}

	return attrs
}
