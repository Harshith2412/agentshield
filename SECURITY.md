# Security policy

## Supported versions

The initial `0.1.x` release line receives security fixes. This table must be reviewed for each later release line.

| Version | Supported |
| --- | --- |
| 0.1.x | Yes |
| Earlier development snapshots and release candidates | No |

## Private reporting

Do not disclose suspected vulnerabilities in public issues. Use GitHub private vulnerability reporting when enabled and include the affected version, controlled reproduction, impact, and suggested mitigation. If private reporting is unavailable, maintainers must configure a private security contact before release; this project does not invent or publish an unverified address.

Avoid credentials, personal data, live targets, and exploit material beyond what a safe reproduction requires. Maintainers should acknowledge reports promptly and coordinate disclosure after mitigation.

## Classifying reports

- A vulnerability is an implementation or packaging flaw that violates a documented guarantee, such as bypassing an instrumented protected tool or accepting a tampered verified trace.
- An expected attack simulation is a checked-in, controlled scenario demonstrating modeled unprotected behavior; it is not itself a vulnerability.
- A security-model limitation is behavior explicitly outside [documented guarantees](docs/security-model.md), such as an uninstrumented side-effect path or host compromise. Limitations can still motivate design discussion but should not be represented as undisclosed guarantees.

AgentShield is an alpha research prototype. Use sandboxing, least privilege, allowlisted tools, and human approval for consequential actions.
