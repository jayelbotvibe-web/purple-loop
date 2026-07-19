package evaluator

import (
	"regexp"
	"strconv"
	"strings"
)

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
	// A keyword identifier (bare string list) is a full-text search: any value
	// appearing anywhere in the event's fields matches.
	if kw, ok := fm[keywordField]; ok {
		return matchKeywords(kw.Values, event)
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

// matchKeywords returns true if any keyword appears (case-insensitive) in any
// canonical field value of the event.
func matchKeywords(keywords []string, event map[string]string) bool {
	for _, kw := range keywords {
		needle := strings.ToLower(kw)
		for field, val := range event {
			if field == FidelityKey {
				continue
			}
			if strings.Contains(strings.ToLower(val), needle) {
				return true
			}
		}
	}
	return false
}

// keywordField is the reserved field name under which a keyword (full-text)
// identifier's bare-string list is stored.
const keywordField = "__keywords__"

func matchField(eventValue string, entry FieldEntry) bool {
	if len(entry.Values) == 0 {
		return false
	}

	hasAll := false
	hasEndsWith := false
	hasStartsWith := false
	hasContains := false
	hasRe := false
	numOp := ""
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
		case "re":
			hasRe = true
		case "lt", "lte", "gt", "gte":
			numOp = m
		}
	}

	// Build the matcher function based on modifiers
	matchOne := func(candidate string) bool {
		// Regex: match against the raw value, case-sensitive per Sigma default.
		if hasRe {
			re, err := regexp.Compile(candidate)
			if err != nil {
				return false
			}
			return re.MatchString(eventValue)
		}

		// Numeric comparison: both sides must parse as numbers.
		if numOp != "" {
			return matchNumeric(eventValue, candidate, numOp)
		}

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

// matchNumeric compares two numeric strings under the given operator
// (lt/lte/gt/gte). Returns false if either side is not a number.
func matchNumeric(eventValue, candidate, op string) bool {
	ev, err1 := strconv.ParseFloat(strings.TrimSpace(eventValue), 64)
	cv, err2 := strconv.ParseFloat(strings.TrimSpace(candidate), 64)
	if err1 != nil || err2 != nil {
		return false
	}
	switch op {
	case "lt":
		return ev < cv
	case "lte":
		return ev <= cv
	case "gt":
		return ev > cv
	case "gte":
		return ev >= cv
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
