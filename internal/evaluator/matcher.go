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
		if entry.MatchNull {
			// Sigma `Field: null` matches when the field is absent or empty.
			if exists && val != "" {
				return false
			}
			continue
		}
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

		// Express the modifier (or an explicit-wildcard value) as a Sigma glob,
		// then match as an anchored, case-insensitive regexp. Anchoring pins the
		// literal segments to the ends of the value (so `*\svchost.exe` does not
		// match `…svchost.exe.malware`), `?` matches one character, and regex
		// metacharacters in the value can't leak.
		switch {
		case hasContains:
			return globMatch("*"+candidate+"*", eventValue)
		case hasStartsWith:
			return globMatch(candidate+"*", eventValue)
		case hasEndsWith:
			return globMatch("*"+candidate, eventValue)
		case strings.ContainsAny(candidate, "*?"):
			return globMatch(candidate, eventValue)
		default:
			return strings.EqualFold(eventValue, candidate)
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

// globMatch reports whether value matches a Sigma glob pattern, case-insensitively
// and anchored to the whole value.
func globMatch(pattern, value string) bool {
	re := globToRegexp(pattern)
	return re != nil && re.MatchString(value)
}

// globToRegexp compiles a Sigma wildcard pattern into an anchored,
// case-insensitive regexp: `*` → any run, `?` → one character; every other
// character (including `\`, a literal path separator in this dialect) is
// escaped. Returns nil if compilation fails (treated as no match by globMatch).
func globToRegexp(glob string) *regexp.Regexp {
	var b strings.Builder
	b.WriteString("(?is)^")
	for i := 0; i < len(glob); i++ {
		switch glob[i] {
		case '*':
			b.WriteString(".*")
		case '?':
			b.WriteString(".")
		default:
			b.WriteString(regexp.QuoteMeta(string(glob[i])))
		}
	}
	b.WriteString("$")
	re, err := regexp.Compile(b.String())
	if err != nil {
		return nil
	}
	return re
}

func evalOneOf(e OneOfExpr, detections map[string]FieldMap, event map[string]string) bool {
	names := expandIdentNames(e.Names, detections)
	matched := 0
	for _, name := range names {
		if evalIdent(name, detections, event) {
			matched++
		}
	}
	return matched >= e.N
}

func evalAllOf(e AllOfExpr, detections map[string]FieldMap, event map[string]string) bool {
	names := expandIdentNames(e.Names, detections)
	for _, name := range names {
		if !evalIdent(name, detections, event) {
			return false
		}
	}
	return len(names) > 0 // vacuous truth over empty set → false
}

// expandIdentNames resolves aggregate operands to concrete identifier names.
// Empty input means "of them" → every identifier EXCEPT filter/falsepositive
// selections (which are meant to be referenced explicitly, not folded into an
// OR/AND). A name containing */? is a glob expanded against the identifier keys.
func expandIdentNames(names []string, detections map[string]FieldMap) []string {
	if len(names) == 0 {
		var out []string
		for k := range detections {
			if strings.HasPrefix(k, "filter") || strings.HasPrefix(k, "falsepositive") {
				continue
			}
			out = append(out, k)
		}
		return out
	}
	var out []string
	for _, n := range names {
		if strings.ContainsAny(n, "*?") {
			re := globToRegexp(n)
			if re == nil {
				continue
			}
			for k := range detections {
				if re.MatchString(k) {
					out = append(out, k)
				}
			}
			continue
		}
		out = append(out, n)
	}
	return out
}
