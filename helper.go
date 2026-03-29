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
