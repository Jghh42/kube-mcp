# ADR 0002: Known-format credential scanner (proof of concept)

- Status: Proposed. This is a proof of concept for evaluation and must not be merged as-is.
- Date: 2026-11-18

## Context

Secret sanitization covers only Kubernetes `Secret` objects. Credentials also show up in env values, ConfigMaps, annotations (including `kubectl.kubernetes.io/last-applied-configuration`), CRD specs such as HelmRelease values, container args, and labels. GET returns all of these to the agent, and therefore to the LLM provider. Three complementary layers are under discussion:

1. Fingerprinting the known leak paths: Secret data, literal container env values, ConfigMap `data`/`binaryData`, and the last-applied annotation (PR #76).
2. **This POC:** a deterministic scanner for credentials in known formats, run on the final safe output. It is the last-resort layer for everything layer 1 does not structurally cover.
3. An optional model-based credential gate (draft PR #48).

The question this POC answers is whether layer 2 is precise, cheap, and useful enough to productionize, and which action it should take on a match.

## What the POC does

`KubernetesReader.ExecuteAsync` scans the final safe `JsonNode` tree of every detailed `k8s_get` GET, after Secret sanitization and before the final output-size guard. LIST summaries and namespace discovery are not scanned: they carry only names, kinds, types, key names, and ages. The scanner reads only JSON **string values** and reports each match as a JSONPath, for example `$.spec.template.spec.containers[0].env[1].value`. A string that is itself a JSON document, such as the last-applied annotation, is parsed and scanned as a tree. Its matches are reported at the outer string's path, redacted inside the parsed tree, and the tree is then re-serialized into the outer string. Embedded documents are parsed with a depth limit of 64. A valid document deeper than that fails closed with `credential_scan_failed`. A document with duplicate property names is scanned as raw text.

Redaction depends on the kind of rule:

- **Exact-format rules** replace only the matched text with `[redacted:<rule-id>]` and keep the rest of the value. For example, `postgres://app:[redacted:url-credentials]@db/app`, or a PEM block from `BEGIN` through `END` inside a larger config file. Every occurrence in a value is redacted. A match with uncertain extent redacts the whole value instead: a PEM block without an `END` line, or a token that runs past its pattern's length bound (GitLab, Slack, Slack webhook, JWT).
- **Generic rules** (`generic-assignment`, `generic-keyed-field`, `bearer-token`) replace the whole value, because their boundaries are approximate. The exception is a generic match whose credential text is already covered by exact-format matches, such as `GITHUB_TOKEN=ghp_…`: only the exact text is redacted. Every generic candidate in a value is checked, so a covered token does not hide a later `DB_PASSWORD=…` in the same file. A regex timeout fails closed: the whole result is withheld with `credential_scan_failed`. The per-match timeout is 250 ms, and the existing Kubernetes request deadline bounds the whole scan.

Configuration, with every rule on by default:

```json
"CredentialScanner": { "Enabled": true, "DisabledRules": [] }
```

`DisabledRules` accepts the rule ids listed below, and startup validation rejects unknown ids. Each redaction logs one warning with the match count and up to 20 `rule-id JSONPath` pairs, for tuning; paths are built only for the logged pairs. Object keys that match an exact-format rule or a fingerprint, or that are over 63 characters or contain control characters, quotes, or backslashes, are logged as `[*]`. Paths are truncated to 256 characters. Values are never logged. A credential used as a key that matches no rule could still reach the log. The request deadline is checked again after redaction. Values kube-mcp generates itself (`hmac-sha256:<32 hex>` fingerprints and redaction markers) are skipped before any rule runs. Without that exclusion a fingerprint under a `token` key would pass the generic filter (see the unit test).

No dependency, tool, middleware, or service was added. All patterns use `[GeneratedRegex]` with a match timeout.

## Decisions (owner, 2026-11-18)

1. Matches are **redacted**; withholding the result is reserved for scan failures. The `Withhold` mode and the `credential_detected` category were removed.
2. The scanner and **all rules, including the generic ones, are enabled by default**, and individual rules can be disabled through configuration.
3. Match paths may be logged for tuning.
4. A held-out run on the owner's homelab cluster was approved (results below).
5. LIST summaries and namespace discovery are not scanned.
6. Exact-format rules redact only the matched text; generic rules redact the whole value.

## Rules and sources

The format rules are a curated port of [Gitleaks](https://github.com/gitleaks/gitleaks) `config/gitleaks.toml` (MIT License, Copyright (c) 2019 Zachary Rice), noted per rule in the source. The local additions handle Kubernetes-specific shapes.

| Rule | Detects | Source |
| --- | --- | --- |
| `private-key` | A PEM/OpenSSH/PGP `PRIVATE KEY` block from the header through the `END` line, at any line width (raw or JSON-escaped newlines), with at least 32 base64 characters of body | Gitleaks `private-key`, tightened |
| `private-key-base64` | Base64 that decodes to a PEM private key (kubeconfig `client-key-data`, CRD fields); certificates and CSRs are rejected by decoding | local |
| `aws-access-key-id` | `AKIA`/`ASIA`/`ABIA`/`ACCA`/`A3T…` key ids, excluding `…EXAMPLE` | Gitleaks `aws-access-token` |
| `aws-secret-access-key` | 40-char secret after an `aws…secret` assignment, or under an `…secret_access_key` field | local heuristic |
| `github-token` | `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` | Gitleaks `github-*` |
| `github-fine-grained-pat` | `github_pat_…` | Gitleaks `github-fine-grained-pat` |
| `gitlab-pat` | `glpat-…` | Gitleaks `gitlab-pat` |
| `slack-token` | `xox[abposr]-…` and `xapp-…` | Gitleaks `slack-*-token` |
| `slack-webhook-url` | `hooks.slack.com/services/…` | Gitleaks `slack-webhook-url` |
| `stripe-secret-key` | `sk_`/`rk_` + `live`/`test`/`prod`; publishable keys are excluded | Gitleaks `stripe-access-token` |
| `google-api-key` | `AIza…` | Gitleaks `gcp-api-key` |
| `jwt` | Three base64url segments whose header decodes to a JSON object with `alg` or `typ`; the payload need not start with `ey` | Gitleaks `jwt` plus header check |
| `url-credentials` | `scheme://user:password@host`; placeholders such as `$(VAR)` and `{{ … }}` are excluded | local |
| `age-secret-key` | `AGE-SECRET-KEY-1…` | Gitleaks `age-secret-key` |
| `bearer-token` | `Bearer <token>` in text (generic filter applies) | local |
| `generic-assignment` | `password=`, `token:`, `"apiKey":"…"`, `--secret=` and similar, where the keyword must end the key token | Gitleaks `generic-api-key`, simplified |
| `generic-keyed-field` | A string under a secret-like key: the property name, the env `name` sibling of `value`, or the preceding `--flag` arg | local |

The generic rules apply one value filter: 8–256 characters, no whitespace, at least two character classes, and Shannon entropy of at least 3.0 bits/char. The filter also rejects placeholders (`$…`, `${…}`, `$(…)`, `{{…}}`, `<…>`, `example`, `xxxx`), paths, credential-less URLs, digests, numbers, booleans, `SCREAMING_SNAKE` env-var references, and Kubernetes-name-shaped values (`grafana-admin`, `cert-manager/webhook-ca`; UUIDs still match). Keyed matching ignores keys containing `checksum`, `hash`, `digest`, or `fingerprint`, so Helm `checksum/secret` is not flagged.

## Evaluation

The corpus lives in `tests/KubeMcp.Tests/SecretScannerCorpus.cs`. All credentials are fakes generated at runtime from a seeded RNG or throwaway key pairs, and provider prefixes are split so the source never contains a complete token. `SecretScannerEvaluationReport` regenerates every table below when `KUBE_MCP_SCANNER_REPORT=<file>` is set; otherwise it does nothing.

- **Positives:** 43 credential samples covering every rule, including a PEM block rewrapped at 16 characters per line and an `.env` file with a GitHub token followed by a password. Each is planted in env values, ConfigMap data, annotations, HelmRelease `spec.values`, container args, labels (where label syntax allows), and a kubectl last-applied annotation, giving 269 cases. Each case must trigger its expected rule at the planted path. After redaction, none of the sample's credential substrings may remain in any string value, including inside re-serialized embedded JSON. Host objects are a realistic Helm-managed Deployment, an app ConfigMap, and a Flux HelmRelease.
- **Negatives:** 25 homelab-shaped objects (568 string values): the Deployment, ConfigMap, and HelmRelease hosts; sanitized Secret GETs whose raw input held real-looking credentials; Secret and Deployment LIST summaries; `kube-root-ca.crt`; a trust-manager PEM bundle with a public key; a webhook `caBundle`; cert-manager Certificate and CertificateRequest objects (base64 CSR and cert); a Flux Kustomization and GitRepository; a CNPG Cluster; a Pod with imageID, containerID and a projected SA-token volume; Events; an Ingress with auth annotations; an ExternalSecret template; recyclarr/homepage configs; Loki/Velero values; a Prometheus config with token files; git SHAs, trace ids and checksums; and SSH public keys, JWKS and binaryData.
- **Evasions:** 15 credentials this layer is not expected to catch.

### Per-rule results (269 positive placements; 25 negative objects, 568 string values)

| Rule | Positives | Expected-rule recall | Any-rule recall | False positives (negative strings) |
| --- | ---: | ---: | ---: | ---: |
| `private-key` | 30 | 30/30 (100%) | 30/30 (100%) | 0 |
| `private-key-base64` | 12 | 12/12 (100%) | 12/12 (100%) | 0 |
| `aws-access-key-id` | 13 | 13/13 (100%) | 13/13 (100%) | 0 |
| `aws-secret-access-key` | 18 | 18/18 (100%) | 18/18 (100%) | 0 |
| `github-token` | 20 | 20/20 (100%) | 20/20 (100%) | 0 |
| `github-fine-grained-pat` | 6 | 6/6 (100%) | 6/6 (100%) | 0 |
| `gitlab-pat` | 7 | 7/7 (100%) | 7/7 (100%) | 0 |
| `slack-token` | 13 | 13/13 (100%) | 13/13 (100%) | 0 |
| `slack-webhook-url` | 6 | 6/6 (100%) | 6/6 (100%) | 0 |
| `stripe-secret-key` | 14 | 14/14 (100%) | 14/14 (100%) | 0 |
| `google-api-key` | 7 | 7/7 (100%) | 7/7 (100%) | 0 |
| `jwt` | 12 | 12/12 (100%) | 12/12 (100%) | 0 |
| `url-credentials` | 18 | 18/18 (100%) | 18/18 (100%) | 0 |
| `age-secret-key` | 12 | 12/12 (100%) | 12/12 (100%) | 0 |
| `bearer-token` | 12 | 12/12 (100%) | 12/12 (100%) | 0 |
| `generic-assignment` | 36 | 36/36 (100%) | 36/36 (100%) | 0 |
| `generic-keyed-field` | 33 | 33/33 (100%) | 33/33 (100%) | 0 |
| **All** | 269 | | 269/269 (100%) | 0 |

Spurious matches elsewhere in the positive host objects: 0.

### Recall by placement (any rule)

| Placement | Cases | Detected | Missed (rule) |
| --- | ---: | ---: | --- |
| env | 43 | 43 (100%) | - |
| configmap-data | 43 | 43 (100%) | - |
| annotation | 43 | 43 (100%) | - |
| crd-spec | 43 | 43 (100%) | - |
| container-arg | 43 | 43 (100%) | - |
| last-applied-json | 43 | 43 (100%) | - |
| label | 11 | 11 (100%) | - |

### Shannon-entropy threshold for generic rules (81 generic positives; 8 extra hard negatives)

| Min entropy (bits/char) | Generic expected-rule recall | Generic FPs (corpus negatives) | Hard-negative FPs |
| ---: | ---: | ---: | ---: |
| 0.0 | 81/81 (100%) | 1 | 5/8 |
| 2.5 | 81/81 (100%) | 1 | 5/8 |
| 3.0 | 81/81 (100%) | 0 | 3/8 |
| 3.5 | 74/81 (91.4%) | 0 | 0/8 |
| 4.0 | 49/81 (60.5%) | 0 | 0/8 |

Hard negatives still flagged at the default 3.0: `$.token` (generic-keyed-field), `$.secret` (generic-keyed-field), `$.accessKey` (generic-keyed-field).

### Redaction: response bytes kept on a true positive (withholding would keep 0%)

| Placement | Cases | Median bytes kept | Min bytes kept |
| --- | ---: | ---: | ---: |
| env | 43 | 99% | 67% |
| configmap-data | 43 | 97% | 31% |
| annotation | 43 | 99% | 67% |
| crd-spec | 43 | 99% | 55% |
| container-arg | 43 | 99% | 67% |
| last-applied-json | 43 | 97% | 36% |
| label | 11 | 100% | 99% |

### Known gaps (evasion corpus)

| Technique | Caught by this layer | Value is an env/ConfigMap data value (layer 1 scope) |
| --- | --- | --- |
| Short low-entropy password under a secret key (DB_PASSWORD=hunter2) | no | yes |
| Single-class passphrase (correcthorsebatterystaple) | no | yes |
| Passphrase containing spaces | no | yes |
| Random password under a non-secret key name | no | yes |
| Random password in a CRD field with no keyword | no | no |
| Known-format token split across two env vars | no | yes |
| Base64-encoded GitHub token | no | yes |
| Hex-encoded AWS secret key | no | no |
| Reversed GitHub token | no | yes |
| Docker config JSON base64-encoded in a ConfigMap | no | yes |
| Gzip+base64 config containing a password | no | yes |
| Credential used as a ConfigMap key (keys are not scanned) | no | no |
| Unsupported vendor format without keyword (sk-proj-…) | no | no |
| Numeric PIN stored as a JSON number | no | no |
| URL-encoded basic-auth credentials in a query string | no | no |

### Latency (median of 9 runs after warm-up; 12 logical CPUs, X64)

| Output | Size | Strings | Serialize (baseline) | Scan | Scan throughput |
| --- | ---: | ---: | ---: | ---: | ---: |
| Typical Deployment GET | 4.3 KiB | 95 | 0.04 ms | 0.32 ms | 13 MiB/s |
| CNPG Cluster GET | 2.5 KiB | 54 | 0.02 ms | 0.20 ms | 12 MiB/s |
| ConfigMap, one ~1 MiB config text | 1032.1 KiB | 2 | 4.22 ms | 16.62 ms | 61 MiB/s |
| ConfigMap, 5,000 small keys | 663.9 KiB | 5001 | 2.65 ms | 19.90 ms | 33 MiB/s |
| HelmRelease, ~1 MiB nested values | 1000.4 KiB | 31021 | 11.38 ms | 34.89 ms | 28 MiB/s |

### Pathological 1 MiB inputs (single string value; per-match timeout 250 ms)

| Input | Time | Outcome |
| --- | ---: | --- |
| 1 MiB of 'a' | 15 ms | no match |
| repeated 'password=' (keyword, no value) | 51 ms | no match |
| repeated 'password=aaaaaaaa ' (rejected values) | 40 ms | no match |
| repeated '-----BEGIN ' (no PRIVATE KEY) | 20 ms | no match |
| repeated PEM header without body | 32 ms | no match |
| repeated 'a://b:' (URL without '@') | 4 ms | no match |
| repeated 'eyAAAAAAAAAAAAAAAAA.' (JWT-like) | 169 ms | no match |
| 'LS0tLS1CRUdJTi' + 1 MiB base64 | 25 ms | no match |
| repeated 'aws_secret' (AWS keyword chain) | 138 ms | no match |
| repeated 'Bearer ' (no token) | 39 ms | no match |
| repeated 'xoxb-1234567890-' (Slack prefix) | 31 ms | 13107 matches: slack-token |

These times are per-string totals across all candidate matches. Every pattern uses bounded quantifiers, and no single match call came near the 250 ms timeout. `RegexTimeoutFailsClosed` injects a catastrophic `^(a+)+$` rule to show that a timeout withholds the result with `credential_scan_failed`. The Slack row matches because the garbage is Slack-shaped.

The latency figures cover only the scan. They exclude the Kubernetes round trip, which dominates real requests.

### How the numbers were reached, and why they are optimistic

The rules and filters were tuned on this same corpus, and the corpus was written by the same author as the rules. The first run showed the realistic failure modes:

- `checksum/secret: <sha256>` (a Helm convention) triggered the keyed rule in every Deployment-hosted case: 134 spurious matches.
- `cert-manager.io/inject-ca-from-secret: ns/name` and `client_secret: AUTHELIA_OIDC_CLIENT_SECRET` were false positives.
- JSON-escaped `\n` inside the last-applied annotation broke `\b` anchors.
- URL passwords with unencoded `@` or `#` were missed. That one was a corpus bug.

The fixes are the digest-key, `namespace/name`, and env-reference exclusions, plus embedded-JSON parsing. The 100%/0 figures therefore show the rules work on the shapes they were designed for. They do not estimate real-cluster precision on their own.

### Held-out run on a real homelab cluster

Tool outputs were fetched from the deployed kube-mcp: every LIST and every listed object's GET, across 13 policy-admitted namespaces and 46 mapped resources. The deployed version fingerprints only Secret data, so env values, ConfigMaps, and last-applied annotations were raw. The outputs were scanned locally with `SecretScannerHeldOutEvaluation` (`KUBE_MCP_SCANNER_CORPUS_DIR=<dir>`) and never committed. Values were inspected only as masked shapes.

| Scope | Outputs | String values | Matches | Scan p50 / p95 / max |
| --- | ---: | ---: | ---: | --- |
| GET only (what is scanned now; re-run after the review fixes) | 526 | 28,352 | **0** | 0.11 / 1.08 / 7.4 ms |
| GET and LIST (first run, before LISTs were skipped) | 994 | 32,383 | **0** | 0.06 / 0.66 / 8.2 ms |

The objects included 154 Events, 54 ConfigMaps, 53 Pods, 38 Secrets, 32 Kustomizations, 16 Deployments, 16 CNPG Backups, 8 HelmReleases, and cert-manager, Gateway API, and Traefik objects.

**No false positives, and no true positives either:** this GitOps-managed cluster keeps its credentials in Secrets. The zero is not the scanner failing to fire. The run contained 9 values under secret-like keys and 4 keyword assignments inside text, and the filters rejected every one for the reasons they were designed for:

- Kubernetes Secret names under `*Secret` keys, in CNPG status (`serverTLSSecret`, …) and CNPG plugin annotations;
- Grafana `$__file{…}` placeholders, in HelmRelease values and `grafana.ini`;
- a resourceVersion under a `…-credentials` key;
- YAML and Python code mentioning `token:`.

Six of those nine clear the 3.0 entropy threshold. The Kubernetes-name and placeholder filters, not entropy, carry precision on real data.

One cluster is a small sample. It confirms that precision is good on this cluster's typical shapes; it says nothing about recall on real leaks.

## Analysis: what this layer cannot catch

This layer recognizes formats; it does not understand meaning. It misses:

- arbitrary and low-entropy passwords (`hunter2`, dictionary passphrases, passphrases with spaces);
- credentials under neutral key names, or in CRD fields with no keyword;
- secrets split across fields;
- anything encoded or obfuscated: base64, hex, gzip, reversed, `.dockerconfigjson` placed in a ConfigMap;
- credentials in property names or non-string JSON values;
- vendor formats without a rule.

The generic rules narrow these gaps only where a keyword is nearby, and they hold most of the false-positive risk: at 3.0 bits/char, 3 of 8 hard negatives are still flagged.

| Gap | This layer | Layer 1: fingerprint env/ConfigMap values | Model gate (PR #48) |
| --- | --- | --- | --- |
| Known formats in CRD specs, annotations, args, labels, last-applied | **Caught** | Not in scope | Likely; unmeasured |
| Arbitrary/low-entropy password in env or ConfigMap | Missed | **Covered**: every value is fingerprinted regardless of format | Possible from context; unmeasured |
| The same outside env/ConfigMap (CRD spec, annotation) | Missed | Not in scope | Possible; unmeasured |
| Encoded, compressed, or obfuscated value | Missed | **Covered** if in env/ConfigMap | Unlikely for encoded data |
| Split across fields | Missed | **Covered** if in env/ConfigMap | Pairwise chunk overlap only |
| Cost per GET | ~0.3 ms typical, ~30 ms at the 1 MiB bound; no network | Negligible; the agent loses value visibility | One remote call per chunk; seconds; external dependency |
| Determinism and auditability | Deterministic; rule id per match | Deterministic | Probabilistic; threshold needs private qualification |

Layer 1 is the stronger control for env and ConfigMap values because it does not depend on recognizing anything. This layer adds value where layer 1 does not reach: known-format credentials in CRD specs, annotations, args, labels, and kubectl last-applied JSON. The two layers compose: fingerprints are skipped by the scanner.

## Redact vs withhold

The decision was to redact. The redaction table above measures the cost: on true positives the median response keeps 98–100% of its bytes per placement. The minimum, 31%, is a large config value redacted whole by a generic rule. Withholding would keep 0%, turning every false positive into an outage of that object for the agent. Its one security advantage is incidental: it also hides *undetected* credentials that happen to share an object with a detected one, which is layer 1's job. Scan errors and timeouts still fail closed and withhold the result.

## Review (GPT-6.2 Sol via Pi, 2026-11-18)

An independent review confirmed eight findings. Seven were fixed with regression tests:

| Finding | Resolution |
| --- | --- |
| A generic match covered by a token hid a later uncovered password in the same value | Every generic candidate is checked |
| Every match built a full JSONPath (memory amplification) | Paths are computed only for the 20 logged pairs |
| Over-depth embedded JSON fell back to raw text; duplicate keys threw | Over-depth fails closed; duplicate keys are scanned as raw text |
| Re-wrapped PEM missed; PEM without END swallowed trailing text; JWT payload `e30` missed; long JWT signature partly survived | Line-width-independent PEM body; incomplete matches redact the whole value; JWT payload relaxed |
| Cancellation not checked after redaction | Checked again after redaction |
| Credential-like map keys logged verbatim in paths | Such keys are logged as `[*]` |
| Corpus test passed on any rule and never checked redaction | It asserts the expected rule and that no credential text survives; the report is opt-in |

Rejected: narrowing `generic-assignment` for URL fragments such as `#/token=MyRouteTab42`. OAuth implicit-flow fragments (`#access_token=…`) are real credentials, and the false-positive cost is one redacted value.

## What production would require

- **More held-out data.** One clean cluster showed no false positives, but a cluster that actually leaks credentials would show recall on real leaks. Run the harness on more clusters before relying on these numbers.
- **Rule governance:** a versioned rule list with per-rule tests, a periodic Gitleaks sync, and a third-party notice for the MIT-licensed patterns.
- **Observability:** a low-cardinality audit field or metric for redaction counts per rule. Redactions currently surface only as a warning log with paths.
- **A dedicated scan budget.** Cancellation by the Kubernetes deadline currently reports `upstream_timeout`. There is no explicit cap on total matches or embedded-document count; both are bounded only by output size and the deadline.
- **Size interplay.** A marker can be longer than the value it replaces. Scanning runs before the size guard, so growth can turn a near-limit response into `response_too_large`.
- **Coordination with layer 1:** if layer 1 introduces another safe-value shape, extend `IsKubeMcpSafeValue`.
- **Documentation and end-to-end coverage:** a kind e2e case with the scanner enabled, and security/configuration documentation beyond this POC's minimal entries.
- **Allowlists only if needed.** Per-rule disabling exists. Add path or key allowlists only if real false positives require them; the simplicity mandate applies.
