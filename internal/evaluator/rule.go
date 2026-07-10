// Package evaluator implements Sigma rule matching. RuleParser reads YAML
// detection blocks; Matcher evaluates events against parsed rules.
package evaluator

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Rule represents a parsed Sigma rule's detection block.
type Rule struct {
	Path        string
	Title       string
	Detections  map[string]FieldMap   // search-identifier → field conditions
	Condition   Expr                 // parsed condition tree
}

// FieldMap is a search-identifier's field→value mapping with modifiers.
type FieldMap map[string]FieldEntry

// FieldEntry is one field condition with its modifier chain.
type FieldEntry struct {
	Values    []string // list of values to match against
	Modifiers []string // e.g. "contains", "startswith", "endswith", "all"
}

// Expr is a node in the condition expression tree.
type Expr interface{ isExpr() }

// IdentExpr references a search-identifier by name.
type IdentExpr struct{ Name string }

// AndExpr combines sub-expressions with AND.
type AndExpr struct{ Left, Right Expr }

// OrExpr combines sub-expressions with OR.
type OrExpr struct{ Left, Right Expr }

// NotExpr negates a sub-expression.
type NotExpr struct{ Child Expr }

// OneOfExpr matches when N of the given identifiers match.
type OneOfExpr struct {
	N     int
	Names []string
}

// AllOfExpr matches when all given identifiers match.
type AllOfExpr struct{ Names []string }

func (IdentExpr) isExpr()  {}
func (AndExpr) isExpr()    {}
func (OrExpr) isExpr()     {}
func (NotExpr) isExpr()    {}
func (OneOfExpr) isExpr()  {}
func (AllOfExpr) isExpr()  {}

// RuleParser loads a Sigma rule from a YAML file.
type RuleParser struct{}

// Parse reads a Sigma YAML rule file and returns the parsed Rule.
func (RuleParser) Parse(path string) (*Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var raw struct {
		Title     string `yaml:"title"`
		Detection struct {
			Condition string         `yaml:"condition"`
			Fields    map[string]any `yaml:",inline"`
		} `yaml:"detection"`
	}
	if err := yaml.Unmarshal(data, &raw); err != nil {
		return nil, err
	}

	rule := &Rule{Path: path, Title: raw.Title}

	// Parse search-identifiers (all fields except "condition")
	rule.Detections = make(map[string]FieldMap)
	for name, val := range raw.Detection.Fields {
		if name == "condition" {
			continue
		}
		fm, err := parseFieldMap(val)
		if err != nil {
			return nil, err
		}
		rule.Detections[name] = fm
	}

	// Parse condition expression
	cond, err := parseCondition(raw.Detection.Condition)
	if err != nil {
		return nil, err
	}
	rule.Condition = cond
	return rule, nil
}

func parseFieldMap(val any) (FieldMap, error) {
	fm := make(FieldMap)
	m, ok := val.(map[string]any)
	if !ok {
		return fm, nil
	}
	for key, v := range m {
		entry := FieldEntry{}
		// Split key into field name and modifiers
		parts := strings.Split(key, "|")
		fieldName := parts[0]
		entry.Modifiers = parts[1:]
		// Parse value(s)
		switch vv := v.(type) {
		case string:
			entry.Values = []string{vv}
		case []any:
			for _, item := range vv {
				if s, ok := item.(string); ok {
					entry.Values = append(entry.Values, s)
				}
			}
		}
		fm[fieldName] = entry
	}
	return fm, nil
}

// parseCondition parses a Sigma condition string into an expression tree.
// Grammar (recursive descent, no external parser lib):
//   expr     = or_expr
//   or_expr  = and_expr ("or" and_expr)*
//   and_expr = not_expr ("and" not_expr)*
//   not_expr = "not" not_expr | primary
//   primary  = identifier | "(" expr ")" | aggregates
//   aggregates = <int> "of" identifier_list | "all of" identifier_list
func parseCondition(s string) (Expr, error) {
	s = strings.TrimSpace(s)
	p := &condParser{s: s, pos: 0}
	expr, err := p.parseOr()
	if err != nil {
		return nil, err
	}
	if p.pos < len(p.s) {
		// trailing content — try extra paren
	}
	return expr, nil
}

type condParser struct {
	s   string
	pos int
}

func (p *condParser) skip() {
	for p.pos < len(p.s) && (p.s[p.pos] == ' ' || p.s[p.pos] == '\t') {
		p.pos++
	}
}

func (p *condParser) peek() byte {
	p.skip()
	if p.pos >= len(p.s) {
		return 0
	}
	return p.s[p.pos]
}

func (p *condParser) parseOr() (Expr, error) {
	left, err := p.parseAnd()
	if err != nil {
		return nil, err
	}
	for {
		p.skip()
		if strings.HasPrefix(p.s[p.pos:], "or ") || strings.HasPrefix(p.s[p.pos:], "or\t") {
			p.pos += 2
			right, err := p.parseAnd()
			if err != nil {
				return nil, err
			}
			left = OrExpr{Left: left, Right: right}
		} else {
			break
		}
	}
	return left, nil
}

func (p *condParser) parseAnd() (Expr, error) {
	left, err := p.parseNot()
	if err != nil {
		return nil, err
	}
	for {
		p.skip()
		if strings.HasPrefix(p.s[p.pos:], "and ") || strings.HasPrefix(p.s[p.pos:], "and\t") {
			p.pos += 3
			right, err := p.parseNot()
			if err != nil {
				return nil, err
			}
			left = AndExpr{Left: left, Right: right}
		} else {
			break
		}
	}
	return left, nil
}

func (p *condParser) parseNot() (Expr, error) {
	p.skip()
	if strings.HasPrefix(p.s[p.pos:], "not ") {
		p.pos += 4
		child, err := p.parseNot()
		if err != nil {
			return nil, err
		}
		return NotExpr{Child: child}, nil
	}
	return p.parsePrimary()
}

func (p *condParser) parsePrimary() (Expr, error) {
	p.skip()
	if p.pos >= len(p.s) {
		return nil, nil
	}

	// Aggregates: "1 of them" or "all of them" or "1 of id1,id2"
	if ch := p.peek(); ch >= '0' && ch <= '9' {
		return p.parseOneOf()
	}
	if strings.HasPrefix(p.s[p.pos:], "all of ") {
		return p.parseAllOf()
	}

	// Parenthesized expression
	if p.s[p.pos] == '(' {
		p.pos++
		expr, err := p.parseOr()
		if err != nil {
			return nil, err
		}
		p.skip()
		if p.pos < len(p.s) && p.s[p.pos] == ')' {
			p.pos++
		}
		return expr, nil
	}

	// Identifier
	return p.parseIdent()
}

func (p *condParser) parseIdent() (Expr, error) {
	p.skip()
	start := p.pos
	for p.pos < len(p.s) && isIdent(p.s[p.pos]) {
		p.pos++
	}
	if start == p.pos {
		return nil, nil
	}
	name := p.s[start:p.pos]
	return IdentExpr{Name: name}, nil
}

func (p *condParser) parseOneOf() (Expr, error) {
	p.skip()
	// Read the count
	start := p.pos
	for p.pos < len(p.s) && p.s[p.pos] >= '0' && p.s[p.pos] <= '9' {
		p.pos++
	}
	n := 0
	for i := start; i < p.pos; i++ {
		n = n*10 + int(p.s[i]-'0')
	}
	// Skip " of "
	p.skip()
	if strings.HasPrefix(p.s[p.pos:], "of ") || strings.HasPrefix(p.s[p.pos:], "of\t") {
		p.pos += 3
	}
	// Read identifiers
	var names []string
	for {
		p.skip()
		if strings.HasPrefix(p.s[p.pos:], "them") {
			p.pos += 4
			// "1 of them" — we don't know the list, pass through
			break
		}
		if strings.HasPrefix(p.s[p.pos:], "(") {
			// "1 of (a, b, c, ...)"
			p.pos++ // skip (
			for {
				id, err := p.parseIdent()
				if err != nil {
					return nil, err
				}
				if id != nil {
					names = append(names, id.(IdentExpr).Name)
				}
				p.skip()
				if p.pos < len(p.s) && p.s[p.pos] == ',' {
					p.pos++
					continue
				}
				if p.pos < len(p.s) && p.s[p.pos] == ')' {
					p.pos++
					break
				}
				break
			}
			break
		}
		// "1 of them" without parens — just "them"
		if strings.HasPrefix(p.s[p.pos:], "them") {
			p.pos += 4
			break
		}
		break
	}
	return OneOfExpr{N: n, Names: names}, nil
}

func (p *condParser) parseAllOf() (Expr, error) {
	p.pos += 7 // skip "all of "
	p.skip()
	var names []string
	if strings.HasPrefix(p.s[p.pos:], "them") {
		p.pos += 4
		return AllOfExpr{Names: names}, nil
	}
	for {
		id, err := p.parseIdent()
		if err != nil {
			return nil, err
		}
		if id != nil {
			names = append(names, id.(IdentExpr).Name)
		}
		p.skip()
		if p.pos < len(p.s) && p.s[p.pos] == ',' {
			p.pos++
			continue
		}
		break
	}
	return AllOfExpr{Names: names}, nil
}

func isIdent(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_'
}
