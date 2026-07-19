package evaluator

import "strings"

// Matcher evaluates parsed Sigma rules against normalized events.
type Matcher struct{}

// Match returns true if the rule's condition evaluates true for the given event.
// event is a flat map of canonical field names to values.
func (Matcher) Match(rule *Rule, event map[string]string) bool {
	if rule == nil || rule.Condition == nil {
		return false
	}
	return evalExpr(rule.Condition, rule.Detections, event)
}

func evalExpr(expr Expr, detections map[string]FieldMap, event map[string]string) bool {
	if expr == nil {
		return false
	}
	switch e := expr.(type) {
	case IdentExpr:
		return evalIdent(e.Name, detections, event)
	case AndExpr:
		return evalExpr(e.Left, detections, event) && evalExpr(e.Right, detections, event)
	case OrExpr:
		return evalExpr(e.Left, detections, event) || evalExpr(e.Right, detections, event)
	case NotExpr:
		return !evalExpr(e.Child, detections, event)
	case OneOfExpr:
		return evalOneOf(e, detections, event)
	case AllOfExpr:
		return evalAllOf(e, detections, event)
	}
	return false
}

func evalIdent(name string, detections map[string]FieldMap, event map[string]string) bool {
	fm, ok := detections[name]
	if !ok {
		return false
	}
	// All field entries in the identifier must match (AND)
	for field, entry := range fm {
		val, exists := event[field]
		if !exists {
			return false
		}
		if !matchField(val, entry) {
			return false
		}
	}
	return true
}

func matchField(eventValue string, entry FieldEntry) bool {
	if len(entry.Values) == 0 {
		return false
	}

	hasAll := false
	hasEndsWith := false
	hasStartsWith := false
	hasContains := false
	for _, m := range entry.Modifiers {
		switch m {
		case "all":
			hasAll = true
		case "endswith":
			hasEndsWith = true
		case "startswith":
			hasStartsWith = true
		case "contains":
			hasContains = true
		}
	}

	// Build the matcher function based on modifiers
	matchOne := func(candidate string) bool {
		// Strip leading slash/drive for path matching
		v := strings.ToLower(eventValue)
		c := strings.ToLower(candidate)

		// If candidate contains * wildcards, use glob-like matching
		if strings.Contains(c, "*") {
			return matchWildcard(v, c)
		}

		switch {
		case hasEndsWith:
			return strings.HasSuffix(v, c)
		case hasStartsWith:
			return strings.HasPrefix(v, c)
		case hasContains:
			return strings.Contains(v, c)
		default:
			return v == c
		}
	}

	if hasAll {
		for _, candidate := range entry.Values {
			if !matchOne(candidate) {
				return false
			}
		}
		return true
	}
	// Default: ANY match (OR)
	for _, candidate := range entry.Values {
		if matchOne(candidate) {
			return true
		}
	}
	return false
}

// matchWildcard performs case-insensitive glob matching where * matches any
// sequence of characters.  It splits the pattern on * and matches each literal
// segment in order within the value string.
func matchWildcard(value, pattern string) bool {
	// A single "*" matches everything
	if pattern == "*" {
		return true
	}

	segments := strings.Split(pattern, "*")
	pos := 0
	for _, seg := range segments {
		if seg == "" {
			continue // leading *, trailing *, or consecutive **
		}
		idx := strings.Index(value[pos:], seg)
		if idx < 0 {
			return false
		}
		pos += idx + len(seg)
	}
	return true
}

func evalOneOf(e OneOfExpr, detections map[string]FieldMap, event map[string]string) bool {
	names := e.Names
	if len(names) == 0 {
		// "1 of them" — expand to all search-identifiers
		for k := range detections {
			names = append(names, k)
		}
	}
	matched := 0
	for _, name := range names {
		if evalIdent(name, detections, event) {
			matched++
		}
	}
	return matched >= e.N
}

func evalAllOf(e AllOfExpr, detections map[string]FieldMap, event map[string]string) bool {
	names := e.Names
	if len(names) == 0 {
		// "all of them" — expand to all search-identifiers
		for k := range detections {
			names = append(names, k)
		}
	}
	for _, name := range names {
		if !evalIdent(name, detections, event) {
			return false
		}
	}
	return len(names) > 0 // vacuous truth over empty set → false
}
