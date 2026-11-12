# Security Policy

## Supported versions

Security fixes go into the latest release line (currently `v2.1.1`) and the `main` branch. Older releases are not patched; please upgrade.

## Reporting a vulnerability

**Please do not open a public issue, discussion or pull request for a security problem.**

Report it privately through GitHub: **Security → Advisories → "Report a vulnerability"** on this repository (<https://github.com/SigmaHQ/pySigma-backend-elasticsearch/security/advisories/new>).
If you cannot use GitHub, contact one of the maintainers listed in `pyproject.toml` privately.

Please include:

- the version or commit, and a minimal Sigma rule, pipeline or command that reproduces the problem, with the observed and expected output;
- the impact you see (see the scope below) and, if you have one, a proposed fix.

## What we treat as a vulnerability

This backend turns Sigma rules, which are often third-party or community content, into Elasticsearch (Lucene, EQL, ES|QL) queries and related output formats that run in a detection platform. The following are in scope:

- **Query or output injection:** rule content (values, field names, titles, descriptions, tags or other metadata) that can change the *structure* of a generated query or of any output format this backend produces, instead of being treated as data. For example, breaking out of a quoted value, adding commands, clauses or sub-searches, or altering the fields of a generated configuration or alert definition.
- **Code execution or file access:** converting a rule or loading a pipeline shipped with this backend that leads to code execution, unsafe deserialisation, template evaluation of untrusted input, or file access outside the intended location.
- **Denial of service:** a small crafted rule that makes conversion consume excessive CPU or memory.
- **Release and supply chain:** weaknesses in this repository's CI or release workflows that could let an outsider publish or alter a released package.

**Out of scope (report publicly as bugs):**

- Conversion or mapping errors that make a rule match more or fewer events than intended, without attacker-controlled input changing the structure of the output. These are important, but they are handled as normal issues and pull requests so fixes reach users quickly.
- A systemic and severe detection gap may be reported privately; the maintainers decide whether it becomes an advisory.

Report problems whose root cause is in pySigma itself (rule parsing, modifiers, processing pipeline machinery, conversion base classes) to [SigmaHQ/pySigma](https://github.com/SigmaHQ/pySigma). Report problems specific to this repository here.

## Our process

| Step                                                                          | Target                                        |
| ----------------------------------------------------------------------------- | --------------------------------------------- |
| Acknowledge the report                                                        | within 5 working days                         |
| Initial assessment and severity (CVSS 3.1)                                    | within 14 days                                |
| Fix developed in the advisory's temporary private fork                        | as soon as practical, normally within 90 days |
| Coordinated release, then GitHub Security Advisory published (CVE via GitHub) | at the fix release                            |

- We credit reporters in the advisory unless they ask not to be credited.
- When a fix affects other SigmaHQ projects, we may coordinate their releases.
- We ask reporters to keep details private until the advisory is published or 90 days have passed, whichever comes first, unless agreed otherwise.
