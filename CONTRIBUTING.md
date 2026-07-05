# Contributing

## Running tests

```bash
go test ./internal/... -count=1
```

All tests must pass before opening a PR. CI enforces this.

## Detection-as-code

Every Sigma rule must have a `detections/tests/<rule_name>/` directory with:
- `positive_events.jsonl` — events that MUST match the rule (at least 1)
- `negative_events.jsonl` — events that MUST NOT match (at least 1)

CI runs the regression test (`TestRegression_AllRules`) which fails if any positive doesn't match
or any negative does. This is the detection-as-code contract — no rule lands without fixtures.

## Testing a rule manually

```bash
go test ./internal/evaluator/ -v -run TestSigma
```

## Branch and commit conventions

- Branch per feature/fix: `feat/description` or `fix/description`
- Commits use Conventional Commits: `feat(scope):`, `fix(scope):`, `docs:`, `test:`, `chore:`
- Push after each commit — never batch
- PR → green CI → squash-merge to main

## Running the canary

```bash
make canary
# or: go run ./cmd/purpleloop canary
```

The canary is the pipeline positive control — it must fire before trusting campaign results.

## Code style

YAGNI, stdlib-first, delete over add. No unrequested abstractions.
Keep it simple — the best code is the code never written.
