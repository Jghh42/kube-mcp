#!/usr/bin/env python3
"""Verify Helm's opt-in application mappings and RBAC stay exactly aligned."""

import re
import sys
from pathlib import Path

# Independent expectations: a change to a predefined family's access surface
# must be reviewed here, not silently inferred from the chart's preset file.
FAMILIES = {
    "certManager": ("cert-manager.io", "v1", {
        "certificates": "Certificate", "certificaterequests": "CertificateRequest",
        "issuers": "Issuer",
    }),
    "traefik": ("traefik.io", "v1alpha1", {
        "ingressroutes": "IngressRoute", "middlewares": "Middleware",
        "traefikservices": "TraefikService", "tlsoptions": "TLSOption",
        "tlsstores": "TLSStore", "serverstransports": "ServersTransport",
        "ingressroutetcps": "IngressRouteTCP", "middlewaretcps": "MiddlewareTCP",
        "serverstransporttcps": "ServersTransportTCP",
        "ingressrouteudps": "IngressRouteUDP",
    }),
    "rookCeph": ("ceph.rook.io", "v1", {
        "cephclusters": "CephCluster", "cephblockpools": "CephBlockPool",
        "cephfilesystems": "CephFilesystem", "cephobjectstores": "CephObjectStore",
    }),
    "cnpg": ("postgresql.cnpg.io", "v1", {
        "clusters": "Cluster", "backups": "Backup",
        "scheduledbackups": "ScheduledBackup", "poolers": "Pooler",
    }),
    "argoCD": ("argoproj.io", "v1alpha1", {
        "applications": "Application", "applicationsets": "ApplicationSet",
        "appprojects": "AppProject",
    }),
}

manifest = Path(sys.argv[1]).read_text()
enabled = set(filter(None, sys.argv[2].split(",")))
rbac_enabled = sys.argv[3] == "rbac"
assert enabled <= FAMILIES.keys(), enabled

expected_env = {}
expected_rules = {}
for family in enabled:
    group, version, resources = FAMILIES[family]
    if rbac_enabled:
        expected_rules[group] = set(resources)
    for resource, kind in resources.items():
        prefix = f"{resource}.{group}"
        expected_env.update({
            (prefix, "Group"): group, (prefix, "Version"): version,
            (prefix, "Resource"): resource, (prefix, "Kind"): kind,
        })

env_matches = re.findall(
    r'^            - name: "KubeMcp__AllowedResources__([^"\n]+)__(Group|Version|Resource|Kind)"\n'
    r'              value: "([^"\n]*)"$', manifest, re.M,
)
actual_env = {(name, field): value for name, field, value in env_matches}
assert len(actual_env) == len(env_matches), "duplicate CRD environment variables"
assert actual_env == expected_env, (actual_env, expected_env)

rules = re.findall(
    r'^  - apiGroups: \["([^"]+)"\]\n    resources:\n'
    r'((?:      - [a-z]+\n)+)    verbs: \["get", "list"\]$', manifest, re.M,
)
actual_rules = {
    group: set(re.findall(r'^      - ([a-z]+)$', resources, re.M))
    for group, resources in rules
}
assert len(actual_rules) == len(rules), "duplicate CRD API groups"
assert actual_rules == expected_rules, (actual_rules, expected_rules)
assert "clusterissuers.cert-manager.io" not in manifest
