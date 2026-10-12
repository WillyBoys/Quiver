# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems in Quiver.

Report them privately through GitHub's private vulnerability reporting: go to the **Security** tab of this repository and choose **Report a vulnerability**. Include the affected version or commit, steps to reproduce, and the impact you expect.

This is a single-maintainer project, so responses are best effort. I aim to acknowledge reports within a week.

## Scope

In scope:
- Ways for an agent, a scanned target, or tool output to bypass the policy gate: running commands, reaching out-of-scope targets, or skipping approvals.
- Authentication or authorization bypass on the API or event stream.
- Exposure of secrets, such as Claude credentials or stored target credentials.
- Prompt injection from target-controlled content that leads to an action the policy gate should have stopped.

Out of scope:
- Findings that require an attacker who already controls the host running Quiver.
- Misuse of Quiver against systems you are not authorized to test. That is the operator's legal responsibility (see the README).

## Supported versions

Quiver v2 is in early development. Only the latest commit on `main` receives fixes. Quiver v1 ([WillyBoys/Quiver-v1](https://github.com/WillyBoys/Quiver-v1)) is archived and unsupported.
