package pkienginereceiver

// Converts a []interface{} value into a []string.
func toStringSlice(i interface{}) []string {
	raw, ok := i.([]interface{})
	if !ok {
		return nil
	}

	res := make([]string, len(raw))
	for i, v := range raw {
		res[i], _ = v.(string) // Defaults to "" if not a string
	}
	return res
}
