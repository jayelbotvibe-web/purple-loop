# Pitfalls & fixes

Check here before debugging.

## Wazuh indexer won't start / exits immediately
- **Cause:** `vm.max_map_count` too low. **Fix:** `scripts/host-prep.sh` (sets it to 262144).
- **Cause:** JVM heap too large for the box. **Fix:** heap is pinned to `-Xms4g -Xmx4g` in the
  override; don't raise it on this machine.

## Indexer cluster health not green (yellow/red)
- Single-node → replicas can't allocate. Yellow is often acceptable for a lab; verify-lab treats
  only **green** as pass, so if it stays yellow, set index replicas to 0 in the indexer config and
  retry. Record the change in PROGRESS.md.

## Dashboard shows 503 / "server not ready"
- The dashboard raced the indexer. Wait 60-90s after `lab-up`; it resolves once the indexer is up.
  Not a failure — re-run `make verify`.

## Victim not registered / no telemetry
- **Cause:** wrong network — the victim can't reach `wazuh.manager`. **Fix:** confirm `LAB_NETWORK`
  in `versions.env` matches `docker network ls`; the victim must be on the stack's network.
- **Cause:** enrollment needs the manager's authd password. **Fix:** check `docker logs
  purpleloop-victim` for enrollment errors; enable password enrollment or register manually with
  `agent-auth`.
- **Cause:** archives logging disabled, so the round-trip check finds nothing. **Fix:** enable
  `<logall_json>yes</logall_json>` in the manager config for lab use.

## Certs errors on lab-up
- The generator didn't run or ran against a different ref. **Fix:** delete
  `lab/wazuh-docker/single-node/config/wazuh_indexer_ssl_certs/` and re-run `scripts/lab-fetch.sh`.

## `go build` fails after adding a dep
- Run `go mod tidy` and commit both `go.mod` and `go.sum`.

## Laptop slows mid-campaign
- Thermal throttling on the mobile CPU, not a resource fault. Plug in, ensure airflow, continue.
  Do NOT change host config to "fix" it.
