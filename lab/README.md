# Lab plane

The lab uses Wazuh's **official single-node Docker deployment**, pinned via
`versions.env` (`WAZUH_DOCKER_REF`), rather than a hand-rolled cluster — the
official deployment handles certificate generation and indexer discovery
correctly, which is the fiddliest part of the setup.

## How it fits together
1. `scripts/lab-fetch.sh` clones `wazuh/wazuh-docker` at the pinned tag into
   `lab/wazuh-docker/` (gitignored) and records the Atomic Red Team commit.
2. It copies `lab/docker-compose.override.yml` into the cloned
   `single-node/` directory. Docker Compose **auto-merges** an
   `docker-compose.override.yml` sitting beside the base `docker-compose.yml`,
   so our customisations apply without editing vendored files.
3. Our override does two things:
   - caps the indexer JVM heap (`OPENSEARCH_JAVA_OPTS`) and container memory;
   - adds the `victim` container (built from `lab/victim/`) on the same network.
4. `make lab-up` brings the merged stack up; `make verify` proves it works.

## Reconcile point (first run)
The victim attaches to the stack's default network (`LAB_NETWORK` in
`versions.env`). If `scripts/verify-lab.sh` reports the victim cannot reach
`wazuh.manager`, the network name differs for your pinned version — update
`LAB_NETWORK` and re-run. This is the one version-specific value to confirm.
