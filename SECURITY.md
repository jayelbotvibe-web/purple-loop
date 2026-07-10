# Security Policy

## Scope

Purple Loop is an **adversary-emulation engine** that executes real ATT&CK techniques against lab
victims. It is designed to run **exclusively** inside the isolated `purpleloop-lab` Docker network.
The engine and its atomics must never be pointed at production systems, external targets, or any
host outside the lab.

## Reporting a vulnerability

If you discover a security issue — especially anything that risks breaking lab containment or
causing unintended execution outside the lab — please report it via GitHub issues or email.

Issues touching lab containment, credential handling, or uncontrolled command execution are treated
as high priority.

## What's in scope

- Lab containment boundaries (Docker network isolation, VM networking)
- Credential handling (.env, lab/secrets/ — never committed)
- Command execution paths (docker exec, SSH, Wazuh active response)
- The Sigma rule parser and matcher (crash/panic/DoS)

## Trust model — executor subprocess boundary

The `G204` (subprocess launched with variable) flags reported by gosec in
`internal/executor/ssh.go`, `internal/executor/exec.go`, and
`internal/collector/wazuh.go` are **by design**. These executors:

- Run Atomic Red Team test commands and SIEM queries as their core function
- Assume a **trusted operator** who explicitly chooses what to run
- Target a **disposable lab victim** — never production systems
- Operate inside the isolated `purpleloop-lab` Docker network and/or a dedicated
  evaluation Windows VM

Production deployment of these executors against non-lab targets would be a
misuse of the tool, not a vulnerability in the tool itself. The operator is
responsible for lab containment.

## What's out of scope

- The Wazuh SIEM and Atomic Red Team (upstream projects; report to them directly)
- The lab's evaluation Windows VM (time-limited evaluation build; not production)
- Docker/VMware misconfigurations in the user's environment
