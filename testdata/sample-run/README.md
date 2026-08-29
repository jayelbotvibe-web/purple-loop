# Sample replay dataset

`events.jsonl` is a dataset in the captured-run format, so `purpleloop replay` can be
exercised without a lab:

```bash
go run ./cmd/purpleloop replay testdata/sample-run
```

**This is not lab telemetry.** The events are the same ones the CI fixtures assert, shaped
into the capture format. It demonstrates the replay path and gives a newcomer a real verdict
from the real matcher — it is not evidence about any real detection pipeline. A genuine
dataset is produced by a real run: `reports/runs/<run-id>/events.jsonl`, which the capture
writer refuses to create for a synthetic run.

`T1518` is included deliberately as a **MISSED**: its atomic ran and produced telemetry, but
the events do not satisfy the rule. A sample where everything passes would teach the wrong
thing.
