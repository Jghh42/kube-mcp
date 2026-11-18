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

`KubernetesReader.ExecuteAsync` scans the final safe `JsonNode` tree of every read (k8s_get GET and LIST, and namespace discovery) after Secret sanitization and LIST summarization, and before the final output-size guard. The scanner reads only JSON **string values** and reports each match as a JSONPath, for example `$.spec.template.spec.containers[0].env[1].value`. A string that is itself a JSON document, such as the last-applied annotation, is parsed and scanned as a tree. Matches inside it are attributed to, and redact, the outer string.

Each matching string value is replaced in full with `[redacted:<rule-id>]`. A regex timeout fails closed: the whole result is withheld with `credential_scan_failed`. The per-match timeout is 250 ms, and the existing Kubernetes request deadline bounds the whole scan.

Configuration, with every rule on by default:

```json
"CredentialScanner": { "Enabled": true, "DisabledRules": [] }
```

`DisabledRules` accepts the rule ids listed below, and startup validation rejects unknown ids. Each redaction logs one warning with the match count and up to 20 `rule-id JSONPath` pairs, for tuning. Paths are truncated to 256 characters and have control characters replaced. Values are never logged. A path can still contain an object key name, so a credential used *as* a key would reach the log. Values kube-mcp generates itself (`hmac-sha256:<32 hex>` fingerprints and redaction markers) are skipped before any rule runs. Without that exclusion a fingerprint under a `token` key would pass the generic filter (see the unit test).

No dependency, tool, middleware, or service was added. All patterns use `[GeneratedRegex]` with a match timeout.

## Decisions (owner, 2026-11-18)

1. Matches are **redacted**; withholding the result is reserved for scan failures. The `Withhold` mode and the `credential_detected` category were removed.
2. The scanner and **all rules, including the generic ones, are enabled by default**, and individual rules can be disabled through configuration.
3. Match paths may be logged for tuning.
4. A held-out run on the owner's homelab cluster was approved (results below).

## Rules and sources

The format rules are a curated port of [Gitleaks](https://github.com/gitleaks/gitleaks) `config/gitleaks.toml` (MIT License, Copyright (c) 2019 Zachary Rice), noted per rule in the source. The local additions handle Kubernetes-specific shapes.

| Rule | Detects | Source |
| --- | --- | --- |
| `private-key` | PEM/OpenSSH/PGP `PRIVATE KEY` header followed by a base64 body (raw or JSON-escaped newlines) | Gitleaks `private-key`, tightened |
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
| `jwt` | Three base64url segments whose header decodes to a JSON object with `alg` or `typ` | Gitleaks `jwt` plus header check |
| `url-credentials` | `scheme://user:password@host`; placeholders such as `$(VAR)` and `{{ … }}` are excluded | local |
| `age-secret-key` | `AGE-SECRET-KEY-1…` | Gitleaks `age-secret-key` |
| `bearer-token` | `Bearer <token>` in text (generic filter applies) | local |
| `generic-assignment` | `password=`, `token:`, `"apiKey":"…"`, `--secret=` and similar, where the keyword must end the key token | Gitleaks `generic-api-key`, simplified |
| `generic-keyed-field` | A string under a secret-like key: the property name, the env `name` sibling of `value`, or the preceding `--flag` arg | local |

The generic rules apply one value filter: 8–256 characters, no whitespace, at least two character classes, and Shannon entropy of at least 3.0 bits/char. The filter also rejects placeholders (`$…`, `${…}`, `$(…)`, `{{…}}`, `<…>`, `example`, `xxxx`), paths, credential-less URLs, digests, numbers, booleans, `SCREAMING_SNAKE` env-var references, and Kubernetes-name-shaped values (`grafana-admin`, `cert-manager/webhook-ca`; UUIDs still match). Keyed matching ignores keys containing `checksum`, `hash`, `digest`, or `fingerprint`, so Helm `checksum/secret` is not flagged.

## Evaluation

The corpus lives in `tests/KubeMcp.Tests/SecretScannerCorpus.cs`. All credentials are fakes generated at runtime from a seeded RNG or throwaway key pairs, and provider prefixes are split so the source never contains a complete token. `SecretScannerEvaluationReport` regenerates every table below; set `KUBE_MCP_SCANNER_REPORT=<file>` to write them to a file.

- **Positives:** 41 credential samples covering every rule. Each is planted in env values, ConfigMap data, annotations, HelmRelease `spec.values`, container args, labels (where label syntax allows), and a kubectl last-applied annotation, giving 257 cases. Host objects are a realistic Helm-managed Deployment, an app ConfigMap, and a Flux HelmRelease.
- **Negatives:** 25 homelab-shaped objects (568 string values): the Deployment, ConfigMap, and HelmRelease hosts; sanitized Secret GETs whose raw input held real-looking credentials; Secret and Deployment LIST summaries; `kube-root-ca.crt`; a trust-manager PEM bundle with a public key; a webhook `caBundle`; cert-manager Certificate and CertificateRequest objects (base64 CSR and cert); a Flux Kustomization and GitRepository; a CNPG Cluster; a Pod with imageID, containerID and a projected SA-token volume; Events; an Ingress with auth annotations; an ExternalSecret template; recyclarr/homepage configs; Loki/Velero values; a Prometheus config with token files; git SHAs, trace ids and checksums; and SSH public keys, JWKS and binaryData.
- **Evasions:** 15 credentials this layer is not expected to catch.

### Per-rule results (257 positive placements; 25 negative objects, 568 string values)

| Rule | Positives | Expected-rule recall | Any-rule recall | False positives (negative strings) |
| --- | ---: | ---: | ---: | ---: |
| `private-key` | 24 | 24/24 (100%) | 24/24 (100%) | 0 |
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
| `generic-assignment` | 30 | 30/30 (100%) | 30/30 (100%) | 0 |
| `generic-keyed-field` | 33 | 33/33 (100%) | 33/33 (100%) | 0 |
| **All** | 257 | | 257/257 (100%) | 0 |

Spurious matches elsewhere in the positive host objects: 0.

### Recall by placement (any rule)

| Placement | Cases | Detected | Missed (rule) |
| --- | ---: | ---: | --- |
| env | 41 | 41 (100%) | - |
| configmap-data | 41 | 41 (100%) | - |
| annotation | 41 | 41 (100%) | - |
| crd-spec | 41 | 41 (100%) | - |
| container-arg | 41 | 41 (100%) | - |
| last-applied-json | 41 | 41 (100%) | - |
| label | 11 | 11 (100%) | - |

### Shannon-entropy threshold for generic rules (75 generic positives; 8 extra hard negatives)

| Min entropy (bits/char) | Generic expected-rule recall | Generic FPs (corpus negatives) | Hard-negative FPs |
| ---: | ---: | ---: | ---: |
| 0.0 | 75/75 (100%) | 1 | 5/8 |
| 2.5 | 75/75 (100%) | 1 | 5/8 |
| 3.0 | 75/75 (100%) | 0 | 3/8 |
| 3.5 | 62/75 (82.7%) | 0 | 0/8 |
| 4.0 | 25/75 (33.3%) | 0 | 0/8 |

Hard negatives still flagged at the default 3.0: `$.token` (generic-keyed-field), `$.secret` (generic-keyed-field), `$.accessKey` (generic-keyed-field).

### Redact vs withhold: response bytes kept on a true positive

| Placement | Cases | Redact: median bytes kept | Redact: min bytes kept | Withhold |
| --- | ---: | ---: | ---: | ---: |
| env | 41 | 99% | 67% | 0% |
| configmap-data | 41 | 96% | 30% | 0% |
| annotation | 41 | 99% | 67% | 0% |
| crd-spec | 41 | 98% | 55% | 0% |
| container-arg | 41 | 99% | 67% | 0% |
| last-applied-json | 41 | 78% | 29% | 0% |
| label | 11 | 100% | 99% | 0% |

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
| Typical Deployment GET | 4.3 KiB | 95 | 0.03 ms | 0.30 ms | 14 MiB/s |
| CNPG Cluster GET | 2.5 KiB | 54 | 0.02 ms | 0.19 ms | 13 MiB/s |
| LIST summary, 100 items | 7.9 KiB | 401 | 0.06 ms | 0.90 ms | 9 MiB/s |
| ConfigMap, one ~1 MiB config text | 1032.1 KiB | 2 | 3.19 ms | 11.72 ms | 86 MiB/s |
| ConfigMap, 5,000 small keys | 663.9 KiB | 5001 | 2.57 ms | 15.59 ms | 42 MiB/s |
| HelmRelease, ~1 MiB nested values | 1000.4 KiB | 31021 | 11.81 ms | 34.03 ms | 29 MiB/s |

### Pathological 1 MiB inputs (single string value; per-match timeout 250 ms)

| Input | Time | Outcome |
| --- | ---: | --- |
| 1 MiB of 'a' | 15 ms | no match |
| repeated 'password=' (keyword, no value) | 56 ms | no match |
| repeated 'password=aaaaaaaa ' (rejected values) | 42 ms | no match |
| repeated '-----BEGIN ' (no PRIVATE KEY) | 17 ms | no match |
| repeated PEM header without body | 29 ms | no match |
| repeated 'a://b:' (URL without '@') | 5 ms | no match |
| repeated 'eyAAAAAAAAAAAAAAAAA.' (JWT-like) | 166 ms | no match |
| 'LS0tLS1CRUdJTi' + 1 MiB base64 | 23 ms | no match |
| repeated 'aws_secret' (AWS keyword chain) | 147 ms | no match |
| repeated 'Bearer ' (no token) | 34 ms | no match |
| repeated 'xoxb-1234567890-' (Slack prefix) | 7 ms | match: slack-token |

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

| Outputs | String values | Matches | Scan p50 / p95 / max | Largest output |
| ---: | ---: | ---: | --- | ---: |
| 994 (526 GETs, 468 LISTs) | 32,383 | **0** | 0.06 / 0.66 / 8.2 ms | 157 KiB |

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

The two modes share the same detector, so neither changes what is detected. They differ in what a match costs:

- **Redact** kept a median of 96–100% of response bytes per placement on true positives. Whole-field replacement of a large config blob or last-applied annotation can drop most of the object: the minimum kept was 29%. A false positive costs one field, and the marker tells the agent why the value is missing.
- **Withhold** keeps 0%. Every false positive becomes an outage of that object for the agent. Its one security advantage is incidental: it also hides *undetected* credentials that happen to share an object with a detected one.

**Decision: redact, and fail closed (withhold) only on scan errors and timeouts.** The scanner is a best-effort backstop behind Secret sanitization, not a boundary. Its false-positive cost should stay small enough that the generic rules can remain enabled, and protecting co-located secrets is layer 1's job, not something to get by coincidence. Replace the whole field rather than a substring, because generic-rule match boundaries are approximate. Substring redaction could be considered later, only for exact-format rules such as PEM blocks and provider tokens, to keep the rest of large config files.

## What production would require

- **More held-out data.** One clean cluster showed no false positives, but a cluster that actually leaks credentials would show recall on real leaks. Run the harness on more clusters before relying on these numbers.
- **Rule governance:** a versioned rule list with per-rule tests, a periodic Gitleaks sync, and a third-party notice for the MIT-licensed patterns.
- **Observability:** a low-cardinality audit field or metric for redaction counts per rule. Redactions currently surface only as a warning log with paths.
- **A dedicated scan budget.** Cancellation by the Kubernetes deadline currently reports `upstream_timeout`. Also bound embedded-JSON parsing explicitly, by depth and count.
- **Size interplay.** A marker can be longer than the value it replaces. Scanning runs before the size guard, so growth can turn a near-limit response into `response_too_large`.
- **Coordination with layer 1:** if layer 1 introduces another safe-value shape, extend `IsKubeMcpSafeValue`.
- **Documentation and end-to-end coverage:** a kind e2e case with the scanner enabled, and security/configuration documentation beyond this POC's minimal entries.
- **Allowlists only if needed.** Per-rule disabling exists. Add path or key allowlists only if real false positives require them; the simplicity mandate applies.

## Open questions

1. Should namespace discovery and summary LISTs skip scanning? Today they are scanned, at negligible cost and with no expected matches.
2. Should exact-format rules redact only the matched substring, so the rest of a large config file survives? Today the whole field is replaced.
