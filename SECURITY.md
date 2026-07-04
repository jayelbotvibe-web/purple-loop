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

## What's out of scope

- The Wazuh SIEM and Atomic Red Team (upstream projects; report to them directly)
- The lab's evaluation Windows VM (time-limited evaluation build; not production)
- Docker/VMware misconfigurations in the user's environment
