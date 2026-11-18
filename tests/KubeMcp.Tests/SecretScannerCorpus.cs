using System.Globalization;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using System.Text.RegularExpressions;
using KubeMcp.Security;

namespace KubeMcp.Tests;

internal sealed record PlantedSample(string Rule, string Key, string Value);

internal sealed record PositiveCase(string Rule, string Placement, JsonNode Root, string Path);

internal sealed record NegativeCase(string Name, JsonNode Root);

/// <param name="Layer1Placement">The value sits in an env value or ConfigMap data value.</param>
internal sealed record EvasionCase(string Technique, JsonNode Root, bool Layer1Placement);

/// <summary>
/// Synthetic evaluation corpus for <see cref="KnownFormatSecretScanner"/>. Every
/// credential is generated at runtime from a seeded RNG or a throwaway key pair,
/// and provider prefixes are split so source never contains a complete token.
/// Host objects mirror what a homelab cluster returns from kube-mcp GET.
/// </summary>
internal sealed partial class SecretScannerCorpus
{
    private const string Upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    private const string Lower = "abcdefghijklmnopqrstuvwxyz";
    private const string Digits = "0123456789";
    private const string Alnum = Upper + Lower + Digits;
    private const string HexChars = "0123456789abcdef";
    private const string Base32Aws = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    private const string Bech32 = "QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L";

    private static readonly Lazy<SecretScannerCorpus> Shared = new(() => new SecretScannerCorpus());

    private readonly Random random = new(20261118);
    private readonly string caCertificatePem;
    private readonly string intermediateCertificatePem;
    private readonly string csrPem;
    private readonly string rsaPrivateKeyPem;
    private readonly string ecPrivateKeyPem;
    private readonly string encryptedPrivateKeyPem;
    private readonly string publicKeyPem;
    private readonly string commit;

    public static SecretScannerCorpus Instance => Shared.Value;

    public IReadOnlyList<PositiveCase> Positives { get; }

    public IReadOnlyList<NegativeCase> Negatives { get; }

    public IReadOnlyList<EvasionCase> Evasions { get; }

    private SecretScannerCorpus()
    {
        using var rsa = RSA.Create(2048);
        using var ec = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        using var caKey = ECDsa.Create(ECCurve.NamedCurves.nistP256);
        rsaPrivateKeyPem = rsa.ExportRSAPrivateKeyPem();
        ecPrivateKeyPem = ec.ExportPkcs8PrivateKeyPem();
        encryptedPrivateKeyPem = ec.ExportEncryptedPkcs8PrivateKeyPem(
            "corpus-only",
            new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 1000));
        publicKeyPem = rsa.ExportSubjectPublicKeyInfoPem();
        commit = Hex(40);
        caCertificatePem = SelfSigned(caKey, "CN=kubernetes");
        intermediateCertificatePem = SelfSigned(ec, "CN=cert-manager-webhook-ca");
        csrPem = new CertificateRequest("CN=grafana.home.arpa", ec, HashAlgorithmName.SHA256)
            .CreateSigningRequestPem();

        Positives = PlantedSamples().SelectMany(Place).ToArray();
        Negatives = BuildNegatives();
        Evasions = BuildEvasions();
    }

    // ------------------------------------------------------------------
    // Fake credential generators
    // ------------------------------------------------------------------

    private string Chars(string alphabet, int length)
    {
        var chars = new char[length];
        for (var i = 0; i < length; i++)
        {
            chars[i] = alphabet[random.Next(alphabet.Length)];
        }

        return new string(chars);
    }

    private string Hex(int length) => Chars(HexChars, length);

    private string Base64Bytes(int bytes)
    {
        var buffer = new byte[bytes];
        random.NextBytes(buffer);
        return Convert.ToBase64String(buffer);
    }

    private string Uid()
    {
        var buffer = new byte[16];
        random.NextBytes(buffer);
        return new Guid(buffer).ToString();
    }

    private string MixedPassword(int length) => Chars(Alnum + "!#%*+-_@^", length);

    // RFC 3986 unreserved characters only, as required inside URL userinfo.
    private string UrlPassword(int length) => Chars(Alnum + "-._~", length);

    private string AwsSecret() => Chars(Alnum + "/+", 40);

    private string GitHub(string kind) => "gh" + kind + "_" + Chars(Alnum, 36);

    private string Jwt(string alg, object payload)
    {
        static string Encode(string json) =>
            Convert.ToBase64String(Encoding.UTF8.GetBytes(json)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

        var header = Encode(JsonSerializer.Serialize(new { alg, kid = Chars(Alnum + "-_", 43) }));
        var body = Encode(JsonSerializer.Serialize(payload));
        return $"{header}.{body}.{Chars(Alnum + "-_", alg == "HS256" ? 43 : 342)}";
    }

    private string ServiceAccountJwt() => Jwt("RS256", new
    {
        aud = new[] { "https://kubernetes.default.svc.cluster.local" },
        exp = 1795000000,
        iat = 1763464000,
        iss = "https://kubernetes.default.svc.cluster.local",
        kubernetes_io = new { @namespace = "media", serviceaccount = new { name = "sonarr", uid = Uid() } },
        sub = "system:serviceaccount:media:sonarr"
    });

    private string OpenSshPrivateKey() =>
        "-----BEGIN " + "OPENSSH PRIVATE KEY-----\n" +
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n" +
        string.Join('\n', Enumerable.Range(0, 5).Select(_ => Base64Bytes(51))) +
        "\n-----END " + "OPENSSH PRIVATE KEY-----\n";

    private string AgeSecretKey() => "AGE-SECRET-KEY-1" + Chars(Bech32, 58);

    private static string SelfSigned(ECDsa key, string subject)
    {
        var request = new CertificateRequest(subject, key, HashAlgorithmName.SHA256);
        request.CertificateExtensions.Add(new X509BasicConstraintsExtension(true, false, 0, true));
        using var certificate = request.CreateSelfSigned(
            new DateTimeOffset(2026, 1, 1, 0, 0, 0, TimeSpan.Zero),
            new DateTimeOffset(2036, 1, 1, 0, 0, 0, TimeSpan.Zero));
        return certificate.ExportCertificatePem() + "\n";
    }

    private static string B64(string text) => Convert.ToBase64String(Encoding.UTF8.GetBytes(text));

    private static string J(string value) => JsonSerializer.Serialize(value);

    // ------------------------------------------------------------------
    // Positives: each sample is planted in every applicable placement.
    // ------------------------------------------------------------------

    private IEnumerable<PlantedSample> PlantedSamples()
    {
        yield return new("private-key", "tls.key", rsaPrivateKeyPem);
        yield return new("private-key", "id_ed25519", OpenSshPrivateKey());
        yield return new("private-key", "signing.key", ecPrivateKeyPem);
        yield return new("private-key", "key.pem", encryptedPrivateKeyPem);

        yield return new("private-key-base64", "client-key-data", B64(rsaPrivateKeyPem));
        yield return new("private-key-base64", "kubeconfig",
            "apiVersion: v1\nkind: Config\nclusters:\n- name: home\n  cluster:\n    server: https://10.0.0.10:6443\n" +
            "    certificate-authority-data: " + B64(caCertificatePem) + "\nusers:\n- name: admin\n  user:\n" +
            "    client-certificate-data: " + B64(intermediateCertificatePem) + "\n" +
            "    client-key-data: " + B64(ecPrivateKeyPem) + "\n");

        yield return new("aws-access-key-id", "AWS_ACCESS_KEY_ID", "AKIA" + Chars(Base32Aws, 16));
        yield return new("aws-access-key-id", "credentials",
            "[default]\naws_access_key_id = ASIA" + Chars(Base32Aws, 16) + "\nregion = eu-west-1\n");

        yield return new("aws-secret-access-key", "AWS_SECRET_ACCESS_KEY", AwsSecret());
        yield return new("aws-secret-access-key", "credentials",
            "[default]\naws_access_key_id = AKIA" + Chars(Base32Aws, 16) +
            "\naws_secret_access_key = " + AwsSecret() + "\n");
        yield return new("aws-secret-access-key", "secretAccessKey", AwsSecret());

        yield return new("github-token", "GITHUB_TOKEN", GitHub("p"));
        yield return new("github-token", ".npmrc",
            "@home-ops:registry=https://npm.pkg.github.com\n//npm.pkg.github.com/:_authToken=" + GitHub("o") + "\n");
        yield return new("github-token", "GH_APP_TOKEN", GitHub("s"));
        yield return new("github-fine-grained-pat", "GITHUB_PAT",
            "github_" + "pat_" + Chars(Alnum, 22) + "_" + Chars(Alnum, 59));

        yield return new("gitlab-pat", "GITLAB_TOKEN", "gl" + "pat-" + Chars(Alnum + "-_", 20));
        yield return new("slack-token", "SLACK_BOT_TOKEN",
            "xo" + "xb-" + Chars(Digits, 12) + "-" + Chars(Digits, 13) + "-" + Chars(Alnum, 24));
        yield return new("slack-token", "SLACK_APP_TOKEN",
            "xa" + "pp-1-A" + Chars(Upper + Digits, 10) + "-" + Chars(Digits, 13) + "-" + Hex(64));
        yield return new("slack-webhook-url", "SLACK_WEBHOOK_URL",
            "https://hooks.slack.com/services/T" + Chars(Upper + Digits, 8) + "/B" +
            Chars(Upper + Digits, 10) + "/" + Chars(Alnum, 24));
        yield return new("stripe-secret-key", "STRIPE_SECRET_KEY", "sk" + "_live_" + Chars(Alnum, 24));
        yield return new("stripe-secret-key", "STRIPE_RESTRICTED_KEY", "rk" + "_live_" + Chars(Alnum, 24));
        yield return new("google-api-key", "GOOGLE_API_KEY", "AI" + "za" + Chars(Alnum + "-_", 35));

        yield return new("jwt", "token", ServiceAccountJwt());
        yield return new("jwt", "ID_TOKEN", Jwt("HS256", new { sub = "admin", role = "admin", iat = 1763464000 }));

        yield return new("url-credentials", "DATABASE_URL",
            "postgres://app:" + Chars(Alnum, 24) + "@postgres16-rw.database.svc:5432/app?sslmode=require");
        yield return new("url-credentials", "REDIS_URL", "redis://:hunter2@redis-master.cache.svc:6379/0");
        yield return new("url-credentials", "url", "https://flux:" + UrlPassword(20) + "@gitea.home.arpa/infra/fleet.git");

        yield return new("age-secret-key", "SOPS_AGE_KEY", AgeSecretKey());
        yield return new("age-secret-key", "age.agekey",
            "# created: 2026-03-01T10:00:00Z\n# public key: age1" + Chars(Bech32.ToLowerInvariant(), 58) +
            "\n" + AgeSecretKey() + "\n");

        yield return new("bearer-token", "config", "Authorization: Bearer " + Chars(Alnum, 40));
        yield return new("bearer-token", "script",
            "curl -fsS -H 'Authorization: Bearer " + Base64Bytes(24) + "' https://healthchecks.home.arpa/ping");

        yield return new("generic-assignment", "config.yaml",
            "database:\n  host: postgres16-rw.database.svc\n  user: app\n  password: " + MixedPassword(20) + "\n");
        yield return new("generic-assignment", "app.env", "DB_HOST=postgres\nDB_PASSWORD=" + MixedPassword(16) + "\n");
        yield return new("generic-assignment", "connectionString",
            "Server=mssql.database.svc;Database=app;User Id=sa;Password=" + MixedPassword(18) + ";TrustServerCertificate=true");
        yield return new("generic-assignment", "grafana.ini",
            "[security]\nadmin_user = admin\nadmin_password = " + MixedPassword(14) + "\n");
        yield return new("generic-assignment", "prometheus.yml",
            "scrape_configs:\n- job_name: unifi\n  authorization:\n    type: Bearer\n    credentials: " + Hex(32) + "\n");

        yield return new("generic-keyed-field", "API_TOKEN", Chars(Alnum, 24));
        yield return new("generic-keyed-field", "admin-password", MixedPassword(16));
        yield return new("generic-keyed-field", "clientSecret", Base64Bytes(32));
        yield return new("generic-keyed-field", "api-key", Hex(32));
        yield return new("generic-keyed-field", "password", Uid());
    }

    private IEnumerable<PositiveCase> Place(PlantedSample sample)
    {
        var envName = new string(sample.Key.Select(c => char.IsAsciiLetterOrDigit(c) ? char.ToUpperInvariant(c) : '_').ToArray());

        {
            var root = Deployment();
            var planted = JsonValue.Create(sample.Value);
            Container(root)["env"]!.AsArray().Insert(1, new JsonObject { ["name"] = envName, ["value"] = planted });
            yield return new(sample.Rule, "env", root, planted.GetPath());
        }

        {
            var root = AppConfigMap();
            var planted = JsonValue.Create(sample.Value);
            root["data"]![sample.Key] = planted;
            yield return new(sample.Rule, "configmap-data", root, planted.GetPath());
        }

        {
            var root = Deployment();
            var planted = JsonValue.Create(sample.Value);
            root["metadata"]!["annotations"]!["example.com/" + sample.Key] = planted;
            yield return new(sample.Rule, "annotation", root, planted.GetPath());
        }

        {
            var root = GrafanaHelmRelease();
            var planted = JsonValue.Create(sample.Value);
            root["spec"]!["values"]![sample.Key] = planted;
            yield return new(sample.Rule, "crd-spec", root, planted.GetPath());
        }

        {
            var root = Deployment();
            var planted = JsonValue.Create(sample.Value);
            var args = Container(root)["args"]!.AsArray();
            args.Add("--" + sample.Key.ToLowerInvariant().Replace('_', '-'));
            args.Add(planted);
            yield return new(sample.Rule, "container-arg", root, planted.GetPath());
        }

        if (sample.Value.Length <= 63 && LabelValue(sample.Value))
        {
            var root = Deployment();
            var planted = JsonValue.Create(sample.Value);
            root["metadata"]!["labels"]!["example.com/" + sample.Key.ToLowerInvariant()] = planted;
            yield return new(sample.Rule, "label", root, planted.GetPath());
        }

        {
            // kubectl client-side apply stores the applied object as JSON text.
            var applied = new JsonObject
            {
                ["apiVersion"] = "v1",
                ["kind"] = "ConfigMap",
                ["metadata"] = new JsonObject { ["name"] = "legacy-app", ["namespace"] = "default" },
                ["data"] = new JsonObject { [sample.Key] = sample.Value }
            };
            var root = AppConfigMap();
            var planted = JsonValue.Create(applied.ToJsonString() + "\n");
            root["metadata"]!["annotations"] = new JsonObject
            {
                ["kubectl.kubernetes.io/last-applied-configuration"] = planted
            };
            yield return new(sample.Rule, "last-applied-json", root, planted.GetPath());
        }
    }

    private static bool LabelValue(string value) =>
        value.Length > 0 &&
        char.IsAsciiLetterOrDigit(value[0]) &&
        char.IsAsciiLetterOrDigit(value[^1]) &&
        value.All(c => char.IsAsciiLetterOrDigit(c) || c is '-' or '_' or '.');

    private static JsonObject Container(JsonNode deployment) =>
        deployment["spec"]!["template"]!["spec"]!["containers"]![0]!.AsObject();

    // ------------------------------------------------------------------
    // Host objects (also part of the negative corpus)
    // ------------------------------------------------------------------

    private JsonObject Deployment() => Parse($$"""
        {
          "apiVersion": "apps/v1",
          "kind": "Deployment",
          "metadata": {
            "name": "sonarr",
            "namespace": "media",
            "uid": {{J(Uid())}},
            "resourceVersion": "48213377",
            "generation": 7,
            "creationTimestamp": "2026-09-02T18:21:44Z",
            "labels": {
              "app.kubernetes.io/component": "sonarr",
              "app.kubernetes.io/instance": "sonarr",
              "app.kubernetes.io/managed-by": "Helm",
              "app.kubernetes.io/name": "sonarr",
              "app.kubernetes.io/version": "4.0.9.2244",
              "helm.sh/chart": "app-template-3.5.1",
              "helm.toolkit.fluxcd.io/name": "sonarr",
              "helm.toolkit.fluxcd.io/namespace": "media"
            },
            "annotations": {
              "deployment.kubernetes.io/revision": "12",
              "meta.helm.sh/release-name": "sonarr",
              "meta.helm.sh/release-namespace": "media",
              "reloader.stakater.com/auto": "true",
              "secret.reloader.stakater.com/reload": "sonarr-secret"
            },
            "managedFields": [
              {
                "apiVersion": "apps/v1",
                "fieldsType": "FieldsV1",
                "fieldsV1": {
                  "f:metadata": { "f:annotations": { ".": {}, "f:meta.helm.sh/release-name": {} } },
                  "f:spec": { "f:template": { "f:spec": { "f:containers": { "k:{\"name\":\"app\"}": {
                    "f:env": {
                      "k:{\"name\":\"SONARR__AUTH__APIKEY\"}": { ".": {}, "f:name": {}, "f:valueFrom": {} },
                      "k:{\"name\":\"SONARR__POSTGRES__PASSWORD\"}": { ".": {}, "f:name": {}, "f:valueFrom": {} }
                    },
                    "f:image": {}
                  } } } } }
                },
                "manager": "helm-controller",
                "operation": "Update",
                "time": "2026-11-01T02:00:13Z"
              },
              {
                "apiVersion": "apps/v1",
                "fieldsType": "FieldsV1",
                "fieldsV1": { "f:status": { "f:availableReplicas": {}, "f:conditions": {} } },
                "manager": "kube-controller-manager",
                "operation": "Update",
                "subresource": "status",
                "time": "2026-11-01T02:01:02Z"
              }
            ]
          },
          "spec": {
            "replicas": 1,
            "revisionHistoryLimit": 3,
            "selector": { "matchLabels": { "app.kubernetes.io/instance": "sonarr", "app.kubernetes.io/name": "sonarr" } },
            "strategy": { "type": "Recreate" },
            "template": {
              "metadata": {
                "labels": { "app.kubernetes.io/instance": "sonarr", "app.kubernetes.io/name": "sonarr" },
                "annotations": {
                  "checksum/config": {{J(Hex(64))}},
                  "checksum/secret": {{J(Hex(64))}},
                  "kubectl.kubernetes.io/restartedAt": "2026-10-01T03:00:00Z"
                }
              },
              "spec": {
                "automountServiceAccountToken": false,
                "enableServiceLinks": false,
                "serviceAccountName": "default",
                "securityContext": { "runAsUser": 568, "runAsGroup": 568, "fsGroup": 568, "fsGroupChangePolicy": "OnRootMismatch" },
                "containers": [
                  {
                    "name": "app",
                    "image": {{J("ghcr.io/home-operations/sonarr:4.0.9.2244@sha256:" + Hex(64))}},
                    "imagePullPolicy": "IfNotPresent",
                    "args": ["--log-level=info", "--metrics-bind-address=:9707", "--leader-elect", "--token-file=/var/run/secrets/tokens/api-token"],
                    "env": [
                      { "name": "TZ", "value": "Europe/Amsterdam" },
                      { "name": "SONARR__APP__INSTANCENAME", "value": "Sonarr" },
                      { "name": "SONARR__AUTH__METHOD", "value": "External" },
                      { "name": "SONARR__POSTGRES__HOST", "value": "postgres16-rw.database.svc.cluster.local" },
                      { "name": "SONARR__AUTH__APIKEY", "valueFrom": { "secretKeyRef": { "name": "sonarr-secret", "key": "SONARR__AUTH__APIKEY" } } },
                      { "name": "SONARR__POSTGRES__PASSWORD", "valueFrom": { "secretKeyRef": { "name": "sonarr-secret", "key": "SONARR__POSTGRES__PASSWORD" } } },
                      { "name": "POD_NAME", "valueFrom": { "fieldRef": { "fieldPath": "metadata.name" } } },
                      { "name": "DATABASE_URL", "value": "postgres://$(SONARR__POSTGRES__USER):$(SONARR__POSTGRES__PASSWORD)@postgres16-rw.database.svc:5432/sonarr_main" },
                      { "name": "TOKEN_FILE", "value": "/var/run/secrets/kubernetes.io/serviceaccount/token" },
                      { "name": "SESSION_SECRET", "value": "" },
                      { "name": "OTEL_TRACE_ID_RATIO", "value": "0.25" }
                    ],
                    "envFrom": [{ "secretRef": { "name": "sonarr-secret" } }],
                    "ports": [{ "name": "http", "containerPort": 8989, "protocol": "TCP" }],
                    "resources": { "limits": { "memory": "2Gi" }, "requests": { "cpu": "100m", "memory": "512Mi" } },
                    "livenessProbe": { "httpGet": { "path": "/ping", "port": 8989 }, "periodSeconds": 10 },
                    "volumeMounts": [{ "name": "config", "mountPath": "/config" }, { "name": "tmp", "mountPath": "/tmp" }]
                  }
                ],
                "imagePullSecrets": [{ "name": "ghcr-pull" }],
                "volumes": [
                  { "name": "config", "persistentVolumeClaim": { "claimName": "sonarr" } },
                  { "name": "tmp", "emptyDir": {} }
                ]
              }
            }
          },
          "status": {
            "observedGeneration": 7,
            "replicas": 1,
            "readyReplicas": 1,
            "availableReplicas": 1,
            "conditions": [
              { "type": "Available", "status": "True", "reason": "MinimumReplicasAvailable", "message": "Deployment has minimum availability." },
              { "type": "Progressing", "status": "True", "reason": "NewReplicaSetAvailable", "message": "ReplicaSet \"sonarr-6c9d7f5b8d\" has successfully progressed." }
            ]
          }
        }
        """);

    private JsonObject AppConfigMap() => Parse($$"""
        {
          "apiVersion": "v1",
          "kind": "ConfigMap",
          "metadata": {
            "name": "app-config",
            "namespace": "apps",
            "uid": {{J(Uid())}},
            "resourceVersion": "51200931",
            "creationTimestamp": "2026-10-11T08:00:00Z",
            "labels": { "app.kubernetes.io/name": "app", "kustomize.toolkit.fluxcd.io/name": "apps", "kustomize.toolkit.fluxcd.io/namespace": "flux-system" }
          },
          "data": {
            "config.yaml": "server:\n  port: 8080\n  publicUrl: https://app.home.arpa\ndatabase:\n  host: postgres16-rw.database.svc\n  user: app\n  password: ${DB_PASSWORD}\n  passwordFile: /run/secrets/db/password\nauth:\n  method: oidc\n  issuer: https://auth.home.arpa\n  clientId: app\n  clientSecretFile: /run/secrets/oidc/client_secret\n  tokenTTL: 1h\n  secretName: app-oidc\nlog:\n  level: info\n",
            ".env": "LOG_LEVEL=info\nAPI_TOKEN=\nSESSION_SECRET=<changeme>\nPASSWORD_MIN_LENGTH=12\nFEATURE_FLAGS=search,export\n",
            "LOG_LEVEL": "info",
            "TZ": "Europe/Amsterdam"
          }
        }
        """);

    private JsonObject GrafanaHelmRelease() => Parse($$"""
        {
          "apiVersion": "helm.toolkit.fluxcd.io/v2",
          "kind": "HelmRelease",
          "metadata": {
            "name": "grafana",
            "namespace": "observability",
            "uid": {{J(Uid())}},
            "resourceVersion": "50119772",
            "generation": 14,
            "creationTimestamp": "2026-02-14T12:00:00Z",
            "finalizers": ["finalizers.fluxcd.io"],
            "labels": { "kustomize.toolkit.fluxcd.io/name": "observability", "kustomize.toolkit.fluxcd.io/namespace": "flux-system" }
          },
          "spec": {
            "interval": "1h",
            "chart": { "spec": { "chart": "grafana", "version": "8.5.1", "sourceRef": { "kind": "HelmRepository", "name": "grafana", "namespace": "flux-system" } } },
            "install": { "remediation": { "retries": 3 } },
            "upgrade": { "cleanupOnFail": true, "remediation": { "retries": 3, "strategy": "rollback" } },
            "valuesFrom": [{ "kind": "Secret", "name": "grafana-values", "valuesKey": "values.yaml" }],
            "values": {
              "replicas": 1,
              "admin": { "existingSecret": "grafana-admin", "userKey": "admin-user", "passwordKey": "admin-password" },
              "envFromSecret": "grafana-env",
              "grafana.ini": {
                "server": { "root_url": "https://grafana.home.arpa" },
                "auth.generic_oauth": {
                  "enabled": true,
                  "client_id": "grafana",
                  "client_secret": "$__file{/etc/secrets/oauth/client_secret}",
                  "token_url": "https://auth.home.arpa/api/oidc/token",
                  "api_url": "https://auth.home.arpa/api/oidc/userinfo",
                  "scopes": "openid profile email groups"
                },
                "database": { "type": "postgres", "host": "postgres16-rw.database.svc:5432", "password": "$__env{GF_DATABASE_PASSWORD}" },
                "analytics": { "check_for_updates": false, "reporting_enabled": false }
              },
              "persistence": { "enabled": false },
              "serviceMonitor": { "enabled": true }
            }
          },
          "status": {
            "conditions": [
              { "type": "Ready", "status": "True", "reason": "UpgradeSucceeded", "message": "Helm upgrade succeeded for release observability/grafana.v9 with chart grafana@8.5.1", "lastTransitionTime": "2026-11-02T04:00:00Z" },
              { "type": "Released", "status": "True", "reason": "UpgradeSucceeded", "message": "Helm upgrade succeeded for release observability/grafana.v9 with chart grafana@8.5.1", "lastTransitionTime": "2026-11-02T04:00:00Z" }
            ],
            "history": [
              { "chartName": "grafana", "chartVersion": "8.5.1", "appVersion": "11.2.0", "configDigest": {{J("sha256:" + Hex(64))}}, "digest": {{J("sha256:" + Hex(64))}}, "firstDeployed": "2026-02-14T12:00:10Z", "lastDeployed": "2026-11-02T04:00:00Z", "name": "grafana", "namespace": "observability", "status": "deployed", "version": 9 }
            ],
            "lastAttemptedConfigDigest": {{J("sha256:" + Hex(64))}},
            "lastAttemptedGeneration": 14,
            "lastAttemptedReleaseAction": "upgrade",
            "lastAttemptedRevision": "8.5.1",
            "observedGeneration": 14,
            "storageNamespace": "observability"
          }
        }
        """);

    // ------------------------------------------------------------------
    // Negatives: realistic objects that must not trigger any rule.
    // ------------------------------------------------------------------

    private NegativeCase[] BuildNegatives()
    {
        var fingerprinter = new SecretFingerprinter(Enumerable.Range(0, 32).Select(value => (byte)value).ToArray());
        var sanitizer = new SecretSanitizer(fingerprinter);

        // Raw Secrets full of real-looking credentials; only the sanitized output is scanned.
        var rawSecret = JsonSerializer.Serialize(new
        {
            apiVersion = "v1",
            kind = "Secret",
            metadata = new
            {
                name = "sonarr-secret",
                @namespace = "media",
                uid = Uid(),
                resourceVersion = "48213001",
                creationTimestamp = "2026-09-02T18:21:40Z",
                annotations = new Dictionary<string, string>
                {
                    ["kubectl.kubernetes.io/last-applied-configuration"] = "{\"stringData\":{\"token\":\"" + GitHub("p") + "\"}}"
                }
            },
            type = "Opaque",
            data = new Dictionary<string, string>
            {
                ["SONARR__AUTH__APIKEY"] = B64(Hex(32)),
                ["SONARR__POSTGRES__PASSWORD"] = B64(MixedPassword(24)),
                ["tls.key"] = B64(rsaPrivateKeyPem),
                ["token"] = B64(ServiceAccountJwt()),
                ["AWS_SECRET_ACCESS_KEY"] = B64(AwsSecret()),
                [".dockerconfigjson"] = B64("{\"auths\":{\"ghcr.io\":{\"auth\":\"" + B64("bot:" + GitHub("p")) + "\"}}}")
            },
            stringData = new Dictionary<string, string> { ["DATABASE_URL"] = "postgres://app:" + MixedPassword(20) + "@db/app" }
        });
        using var rawSecretDocument = JsonDocument.Parse(rawSecret);
        var helmReleaseSecret = JsonSerializer.Serialize(new
        {
            apiVersion = "v1",
            kind = "Secret",
            metadata = new
            {
                name = "sh.helm.release.v1.grafana.v9",
                @namespace = "observability",
                uid = Uid(),
                resourceVersion = "50119770",
                creationTimestamp = "2026-11-02T04:00:00Z",
                labels = new Dictionary<string, string> { ["name"] = "grafana", ["owner"] = "helm", ["status"] = "deployed", ["version"] = "9" }
            },
            type = "helm.sh/release.v1",
            data = new Dictionary<string, string> { ["release"] = Base64Bytes(4096) }
        });
        using var helmReleaseSecretDocument = JsonDocument.Parse(helmReleaseSecret);

        return
        [
            new("deployment/sonarr (Helm, digests, managedFields, secretKeyRefs)", Deployment()),
            new("configmap/app-config (placeholders, file refs)", AppConfigMap()),
            new("helmrelease/grafana (existingSecret, $__file refs, digests)", GrafanaHelmRelease()),
            new("secret GET sanitized (HMAC fingerprints)", sanitizer.SanitizeGet(rawSecretDocument.RootElement)),
            new("secret GET sanitized (helm.sh/release.v1)", sanitizer.SanitizeGet(helmReleaseSecretDocument.RootElement)),
            new("secret LIST summary", Parse(Fill("""
                {"operation":"LIST","resource":"secrets","canonicalResource":"secrets","namespace":"media","items":[
                  {"name":"sonarr-secret","type":"Opaque","keys":["AWS_SECRET_ACCESS_KEY","DATABASE_URL","SONARR__AUTH__APIKEY","token","tls.key"]},
                  {"name":"ghcr-pull","type":"kubernetes.io/dockerconfigjson","keys":[".dockerconfigjson"]},
                  {"name":"sh.helm.release.v1.sonarr.v12","type":"helm.sh/release.v1","keys":["release"]}
                ],"count":3,"limited":false}
                """))),
            new("deployments LIST summary", Parse("""
                {"operation":"LIST","resource":"deployments","canonicalResource":"apps/deployments","namespace":"media","items":[
                  {"name":"sonarr","namespace":"media","kind":"Deployment","age":"77d"},
                  {"name":"radarr","namespace":"media","kind":"Deployment","age":"77d"}
                ],"count":2,"limited":false}
                """)),
            new("configmap/kube-root-ca.crt", Parse(Fill("""
                {"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"kube-root-ca.crt","namespace":"media","uid":"@UID@","resourceVersion":"311","creationTimestamp":"2026-01-01T00:00:00Z",
                 "annotations":{"kubernetes.io/description":"Contains a CA bundle that can be used to verify the kube-apiserver when using internal endpoints such as the internal service IP or kubernetes.default.svc. No other usage is guaranteed across distributions of Kubernetes clusters."}},
                 "data":{"ca.crt":"@CA_PEM@"}}
                """))),
            new("configmap/trust-bundle (trust-manager, PEM chain + public key)", Parse(Fill("""
                {"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"home-ca-bundle","namespace":"apps","uid":"@UID@","resourceVersion":"9921",
                 "labels":{"trust.cert-manager.io/bundle":"home-ca-bundle"},"annotations":{"trust.cert-manager.io/hash":"@H64@"}},
                 "data":{"ca-certificates.crt":"@CA_PEM@@INT_PEM@","signing.pub":"@PUB_PEM@"}}
                """))),
            new("validatingwebhookconfiguration (base64 caBundle)", Parse(Fill("""
                {"apiVersion":"admissionregistration.k8s.io/v1","kind":"ValidatingWebhookConfiguration","metadata":{"name":"cert-manager-webhook","uid":"@UID@","resourceVersion":"77812",
                 "annotations":{"cert-manager.io/inject-ca-from-secret":"cert-manager/cert-manager-webhook-ca"}},
                 "webhooks":[{"name":"webhook.cert-manager.io","admissionReviewVersions":["v1"],"sideEffects":"None","failurePolicy":"Fail","timeoutSeconds":30,
                   "clientConfig":{"caBundle":"@INT_B64@","service":{"name":"cert-manager-webhook","namespace":"cert-manager","path":"/validate","port":443}},
                   "rules":[{"apiGroups":["cert-manager.io","acme.cert-manager.io"],"apiVersions":["v1"],"operations":["CREATE","UPDATE"],"resources":["*/*"]}]}]}
                """))),
            new("certificate/wildcard (cert-manager)", Parse(Fill("""
                {"apiVersion":"cert-manager.io/v1","kind":"Certificate","metadata":{"name":"wildcard-home-arpa","namespace":"networking","uid":"@UID@","resourceVersion":"40012","generation":2},
                 "spec":{"secretName":"wildcard-home-arpa-tls","commonName":"home.arpa","dnsNames":["home.arpa","*.home.arpa"],
                   "issuerRef":{"group":"cert-manager.io","kind":"ClusterIssuer","name":"letsencrypt-production"},
                   "privateKey":{"algorithm":"ECDSA","size":256,"rotationPolicy":"Always"},
                   "secretTemplate":{"annotations":{"reflector.v1.k8s.emberstack.com/reflection-allowed":"true","reflector.v1.k8s.emberstack.com/reflection-allowed-namespaces":"media,apps"}}},
                 "status":{"conditions":[{"type":"Ready","status":"True","reason":"Ready","message":"Certificate is up to date and has not expired","observedGeneration":2}],
                   "notAfter":"2027-01-30T10:00:00Z","notBefore":"2026-11-01T10:00:00Z","renewalTime":"2026-12-31T10:00:00Z","revision":6}}
                """))),
            new("certificaterequest (base64 CSR, certificate, CA)", Parse(Fill("""
                {"apiVersion":"cert-manager.io/v1","kind":"CertificateRequest","metadata":{"name":"wildcard-home-arpa-6","namespace":"networking","uid":"@UID@",
                 "annotations":{"cert-manager.io/certificate-name":"wildcard-home-arpa","cert-manager.io/certificate-revision":"6","cert-manager.io/private-key-secret-name":"wildcard-home-arpa-tls-x7k2p"}},
                 "spec":{"request":"@CSR_B64@","issuerRef":{"kind":"ClusterIssuer","name":"letsencrypt-production"},"usages":["digital signature","key encipherment"],"username":"system:serviceaccount:cert-manager:cert-manager","uid":"@UID@"},
                 "status":{"certificate":"@INT_B64@","ca":"@CA_B64@"}}
                """))),
            new("kustomization/apps (Flux, sops decryption)", Parse(Fill("""
                {"apiVersion":"kustomize.toolkit.fluxcd.io/v1","kind":"Kustomization","metadata":{"name":"apps","namespace":"flux-system","uid":"@UID@","resourceVersion":"51207711","generation":31,"finalizers":["finalizers.fluxcd.io"]},
                 "spec":{"interval":"30m","path":"./kubernetes/apps","prune":true,"wait":false,"timeout":"5m",
                   "sourceRef":{"kind":"GitRepository","name":"home-ops"},
                   "decryption":{"provider":"sops","secretRef":{"name":"sops-age"}},
                   "postBuild":{"substitute":{"CLUSTER_DOMAIN":"home.arpa","TIMEZONE":"Europe/Amsterdam"},"substituteFrom":[{"kind":"ConfigMap","name":"cluster-settings"},{"kind":"Secret","name":"cluster-secrets"}]}},
                 "status":{"conditions":[{"type":"Ready","status":"True","reason":"ReconciliationSucceeded","message":"Applied revision: main@sha1:@COMMIT@"}],
                   "inventory":{"entries":[{"id":"media_sonarr_apps_Deployment","v":"v1"},{"id":"media_sonarr__Service","v":"v1"},{"id":"observability_grafana_helm.toolkit.fluxcd.io_HelmRelease","v":"v2"}]},
                   "lastAppliedRevision":"main@sha1:@COMMIT@","lastAttemptedRevision":"main@sha1:@COMMIT@","lastHandledReconcileAt":"2026-11-17T21:04:33.1234+01:00","observedGeneration":31}}
                """))),
            new("gitrepository/home-ops (Flux, ssh url, artifact digest)", Parse(Fill("""
                {"apiVersion":"source.toolkit.fluxcd.io/v1","kind":"GitRepository","metadata":{"name":"home-ops","namespace":"flux-system","uid":"@UID@","resourceVersion":"51207600"},
                 "spec":{"interval":"30m","url":"ssh://git@github.com/example-org/home-ops","ref":{"branch":"main"},"secretRef":{"name":"github-deploy-key"},"ignore":"/*\n!/kubernetes\n"},
                 "status":{"artifact":{"digest":"sha256:@H64@","lastUpdateTime":"2026-11-17T20:04:33Z","path":"gitrepository/flux-system/home-ops/@COMMIT@.tar.gz",
                   "revision":"main@sha1:@COMMIT@","size":182733,"url":"http://source-controller.flux-system.svc.cluster.local./gitrepository/flux-system/home-ops/@COMMIT@.tar.gz"},
                   "conditions":[{"type":"Ready","status":"True","reason":"Succeeded","message":"stored artifact for revision 'main@sha1:@COMMIT@'"}]}}
                """))),
            new("cluster/postgres16 (CNPG)", Parse(Fill("""
                {"apiVersion":"postgresql.cnpg.io/v1","kind":"Cluster","metadata":{"name":"postgres16","namespace":"database","uid":"@UID@","resourceVersion":"51200077","generation":4},
                 "spec":{"instances":3,"imageName":"ghcr.io/cloudnative-pg/postgresql:16.4@sha256:@H64@","primaryUpdateStrategy":"unsupervised","enableSuperuserAccess":true,
                   "superuserSecret":{"name":"cloudnative-pg-secret"},
                   "bootstrap":{"initdb":{"database":"app","owner":"app","secret":{"name":"app-db-credentials"}}},
                   "storage":{"size":"20Gi","storageClass":"ceph-block"},
                   "postgresql":{"parameters":{"max_connections":"400","shared_buffers":"256MB"}},
                   "monitoring":{"enablePodMonitor":true},
                   "backup":{"retentionPolicy":"30d","barmanObjectStore":{"destinationPath":"s3://cnpg-backups/postgres16","endpointURL":"http://minio.storage.svc.cluster.local:9000","serverName":"postgres16-v2",
                     "data":{"compression":"bzip2"},"wal":{"compression":"bzip2","maxParallel":8},
                     "s3Credentials":{"accessKeyId":{"name":"cloudnative-pg-secret","key":"aws-access-key-id"},"secretAccessKey":{"name":"cloudnative-pg-secret","key":"aws-secret-access-key"}}}}},
                 "status":{"phase":"Cluster in healthy state","instances":3,"readyInstances":3,"currentPrimary":"postgres16-1","targetPrimary":"postgres16-1","timelineID":3,
                   "writeService":"postgres16-rw","readService":"postgres16-r",
                   "cloudNativePGCommitHash":"@H8@","cloudNativePGOperatorHash":"@H64@",
                   "certificates":{"clientCASecret":"postgres16-ca","serverCASecret":"postgres16-ca","serverTLSSecret":"postgres16-server","replicationTLSSecret":"postgres16-replication",
                     "serverAltDNSNames":["postgres16-rw","postgres16-rw.database","postgres16-rw.database.svc"],
                     "expirations":{"postgres16-ca":"2027-02-01 10:00:00 +0000 UTC","postgres16-replication":"2027-02-01 10:00:00 +0000 UTC","postgres16-server":"2027-02-01 10:00:00 +0000 UTC"}},
                   "secretsResourceVersion":{"applicationSecretVersion":"40011","clientCaSecretVersion":"40002","replicationSecretVersion":"40003","serverCaSecretVersion":"40002","serverSecretVersion":"40004","superuserSecretVersion":"40010"},
                   "configMapResourceVersion":{"metrics":{"cnpg-default-monitoring":"39990"}},
                   "instancesStatus":{"healthy":["postgres16-1","postgres16-2","postgres16-3"]},
                   "pgDataImageInfo":{"image":"ghcr.io/cloudnative-pg/postgresql:16.4@sha256:@H64@","majorVersion":16}}}
                """))),
            new("pod/sonarr (imageID, containerID, projected SA token volume)", Parse(Fill("""
                {"apiVersion":"v1","kind":"Pod","metadata":{"name":"sonarr-6c9d7f5b8d-x2v7q","generateName":"sonarr-6c9d7f5b8d-","namespace":"media","uid":"@UID@","resourceVersion":"51204410",
                   "labels":{"app.kubernetes.io/name":"sonarr","pod-template-hash":"6c9d7f5b8d"},
                   "annotations":{"kubectl.kubernetes.io/restartedAt":"2026-10-01T03:00:00Z","checksum/config":"@H64@"},
                   "ownerReferences":[{"apiVersion":"apps/v1","kind":"ReplicaSet","name":"sonarr-6c9d7f5b8d","uid":"@UID@","controller":true,"blockOwnerDeletion":true}]},
                 "spec":{"nodeName":"k8s-2","serviceAccountName":"default","containers":[{"name":"app","image":"ghcr.io/home-operations/sonarr:4.0.9.2244",
                     "volumeMounts":[{"name":"kube-api-access-7xk2p","mountPath":"/var/run/secrets/kubernetes.io/serviceaccount","readOnly":true}]}],
                   "volumes":[{"name":"kube-api-access-7xk2p","projected":{"defaultMode":420,"sources":[{"serviceAccountToken":{"expirationSeconds":3607,"path":"token"}},{"configMap":{"name":"kube-root-ca.crt","items":[{"key":"ca.crt","path":"ca.crt"}]}},{"downwardAPI":{"items":[{"fieldRef":{"apiVersion":"v1","fieldPath":"metadata.namespace"},"path":"namespace"}]}}]}}]},
                 "status":{"phase":"Running","hostIP":"10.0.0.12","podIP":"10.42.2.117","qosClass":"Burstable","startTime":"2026-11-01T02:00:20Z",
                   "containerStatuses":[{"name":"app","ready":true,"restartCount":0,"image":"ghcr.io/home-operations/sonarr:4.0.9.2244",
                     "imageID":"ghcr.io/home-operations/sonarr@sha256:@H64@","containerID":"containerd://@H64@","started":true}]}}
                """))),
            new("events (image pull, missing secret)", Parse(Fill("""
                {"operation":"GET","items":[
                 {"apiVersion":"v1","kind":"Event","metadata":{"name":"sonarr-6c9d7f5b8d-x2v7q.18f2a7c3b1d5e9a0","namespace":"media"},"reason":"Pulled","type":"Normal",
                  "message":"Successfully pulled image \"ghcr.io/home-operations/sonarr:4.0.9.2244@sha256:@H64@\" in 2.512s (2.512s including waiting). Image size: 123456789 bytes."},
                 {"apiVersion":"v1","kind":"Event","metadata":{"name":"grafana-7d4b9.18f2a7c3b1d5e9a1","namespace":"observability"},"reason":"FailedMount","type":"Warning",
                  "message":"MountVolume.SetUp failed for volume \"secret-volume\" : secret \"grafana-admin\" not found"},
                 {"apiVersion":"v1","kind":"Event","metadata":{"name":"app.18f2a7c3b1d5e9a2","namespace":"apps"},"reason":"Failed","type":"Warning",
                  "message":"Failed to pull image \"ghcr.io/example/private:1.0\": failed to authorize: failed to fetch anonymous token: unexpected status from GET request to https://ghcr.io/token?scope=repository%3Aexample%2Fprivate%3Apull: 401 Unauthorized"}]}
                """))),
            new("ingress/grafana (auth annotations)", Parse(Fill("""
                {"apiVersion":"networking.k8s.io/v1","kind":"Ingress","metadata":{"name":"grafana","namespace":"observability","uid":"@UID@",
                   "annotations":{"nginx.ingress.kubernetes.io/auth-url":"http://authelia.security.svc.cluster.local/api/authz/auth-request","nginx.ingress.kubernetes.io/auth-signin":"https://auth.home.arpa?rm=$request_method",
                     "nginx.ingress.kubernetes.io/auth-response-headers":"Remote-User,Remote-Name,Remote-Groups,Remote-Email","nginx.ingress.kubernetes.io/auth-secret":"basic-auth",
                     "traefik.ingress.kubernetes.io/router.middlewares":"networking-authelia@kubernetescrd","external-dns.alpha.kubernetes.io/target":"external.home.arpa","gethomepage.dev/widget.key":"{{HOMEPAGE_VAR_GRAFANA_TOKEN}}"}},
                 "spec":{"ingressClassName":"internal","tls":[{"hosts":["grafana.home.arpa"],"secretName":"wildcard-home-arpa-tls"}],
                   "rules":[{"host":"grafana.home.arpa","http":{"paths":[{"path":"/","pathType":"Prefix","backend":{"service":{"name":"grafana","port":{"number":80}}}}]}}]}}
                """))),
            new("externalsecret (templated credentials)", Parse(Fill("""
                {"apiVersion":"external-secrets.io/v1beta1","kind":"ExternalSecret","metadata":{"name":"app","namespace":"apps","uid":"@UID@"},
                 "spec":{"refreshInterval":"1h","secretStoreRef":{"kind":"ClusterSecretStore","name":"onepassword"},
                   "target":{"name":"app-secret","template":{"engineVersion":"v2","data":{"DATABASE_URL":"postgres://{{ .username }}:{{ .password }}@postgres16-rw.database.svc:5432/app","API_TOKEN":"{{ .api_token }}"}}},
                   "data":[{"secretKey":"password","remoteRef":{"key":"app","property":"password"}}],"dataFrom":[{"extract":{"key":"app"}}]},
                 "status":{"binding":{"name":"app-secret"},"refreshTime":"2026-11-18T08:00:00Z","syncedResourceVersion":"1-@H32@"}}
                """))),
            new("configmap/recyclarr + homepage (env refs, hard negatives)", Parse(Fill("""
                {"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"recyclarr","namespace":"media"},
                 "data":{"recyclarr.yml":"sonarr:\n  main:\n    base_url: http://sonarr.media.svc:8989\n    api_key: !env_var SONARR_API_KEY\n    delete_old_custom_formats: true\n",
                   "services.yaml":"- Media:\n    - Sonarr:\n        href: https://sonarr.home.arpa\n        widget:\n          type: sonarr\n          url: http://sonarr.media.svc:8989\n          key: {{HOMEPAGE_VAR_SONARR_TOKEN}}\n",
                   "settings.json":"{\"auth\":{\"method\":\"forms\",\"token_ttl\":3600,\"secretName\":\"app-oidc\",\"passwordPolicy\":\"strong\",\"apiKeyHeader\":\"X-Api-Key\"}}"}}
                """))),
            new("helmrelease/loki (S3 env placeholders, existingSecret)", Parse(Fill("""
                {"apiVersion":"helm.toolkit.fluxcd.io/v2","kind":"HelmRelease","metadata":{"name":"loki","namespace":"observability","uid":"@UID@"},
                 "spec":{"values":{"loki":{"storage":{"type":"s3","bucketNames":{"chunks":"loki-chunks"},"s3":{"endpoint":"minio.storage.svc:9000","accessKeyId":"${S3_ACCESS_KEY_ID}","secretAccessKey":"${S3_SECRET_ACCESS_KEY}","s3ForcePathStyle":true,"insecure":true}},
                   "auth_enabled":false},"global":{"extraArgs":["-config.expand-env=true"],"extraEnvFrom":[{"secretRef":{"name":"loki-s3"}}]},
                   "gateway":{"basicAuth":{"enabled":true,"existingSecret":"loki-gateway-auth"}},
                   "velero":{"credentials":{"existingSecret":"velero-s3","useSecret":true},"secretKey":"cloud","token":"kubernetes-dashboard-token","client_secret":"AUTHELIA_OIDC_CLIENT_SECRET","jwt_secret":"file:///run/secrets/jwt"}}}}
                """))),
            new("configmap/prometheus (token files, credential files)", Parse(Fill("""
                {"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"prometheus-additional","namespace":"observability"},
                 "data":{"prometheus.yml":"scrape_configs:\n- job_name: kubernetes-apiservers\n  scheme: https\n  bearer_token_file: /var/run/secrets/kubernetes.io/serviceaccount/token\n  tls_config:\n    ca_file: /var/run/secrets/kubernetes.io/serviceaccount/ca.crt\n- job_name: node\n  basic_auth:\n    username: prometheus\n    password_file: /etc/prometheus/secrets/node-auth/password\n  authorization:\n    credentials_file: /etc/prometheus/secrets/token\n",
                   "nginx.conf":"location / {\n  proxy_set_header Authorization $http_authorization;\n  auth_basic_user_file /etc/nginx/htpasswd;\n}\n"}}
                """))),
            new("configmap/build-info (git SHAs, trace ids, checksums)", Parse(Fill("""
                {"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"build-info","namespace":"apps","annotations":{"kustomize.toolkit.fluxcd.io/checksum":"@H40@"}},
                 "data":{"build.json":"{\"commit\":\"@H40@\",\"tree\":\"@H40@\",\"traceId\":\"@H32@\",\"spanId\":\"@H16@\",\"buildId\":\"@UID@\"}",
                   "SHA256SUMS":"@H64@  app-linux-amd64\n@H64@  app-linux-arm64\n",
                   "GIT_COMMIT":"@H40@","CONTROLLER_REVISION_HASH":"postgres16-7f9c8d6b5","IMAGE_DIGEST":"sha256:@H64@"}}
                """))),
            new("configmap/binary + ssh public keys + JWKS", Parse(Fill("""
                {"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"assets","namespace":"apps"},
                 "data":{"authorized_keys":"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI@ALNUM43@ admin@workstation\n",
                   "known_hosts":"github.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI@ALNUM43@\n",
                   "jwks.json":"{\"keys\":[{\"kty\":\"RSA\",\"use\":\"sig\",\"alg\":\"RS256\",\"kid\":\"@ALNUM43@\",\"n\":\"@B64URL342@\",\"e\":\"AQAB\"}]}"},
                 "binaryData":{"logo.png":"@RANDB64_3000@","dashboards.tar.gz":"@RANDB64_2000@"}}
                """))),
            new("serviceaccount + namespaces LIST", Parse(Fill("""
                {"items":[{"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"sonarr","namespace":"media","uid":"@UID@",
                  "annotations":{"eks.amazonaws.com/role-arn":"arn:aws:iam::123456789012:role/sonarr"}},"secrets":[{"name":"sonarr-token-7xk2p"}],"imagePullSecrets":[{"name":"ghcr-pull"}],"automountServiceAccountToken":false},
                 {"operation":"LIST","resource":"namespaces","items":[{"name":"media","age":"300d"},{"name":"flux-system","age":"300d"}],"count":2,"limited":false}]}
                """))),
        ];
    }

    // ------------------------------------------------------------------
    // Evasions: credentials this layer is not expected to catch.
    // ------------------------------------------------------------------

    private EvasionCase[] BuildEvasions()
    {
        var token = GitHub("p");
        var awsSecret = AwsSecret();
        var dockerConfig = "{\"auths\":{\"ghcr.io\":{\"auth\":\"" + B64("bot:" + MixedPassword(20)) + "\"}}}";

        JsonObject Env(string name, string value)
        {
            var root = Deployment();
            Container(root)["env"]!.AsArray().Add(new JsonObject { ["name"] = name, ["value"] = value });
            return root;
        }

        JsonObject Data(string key, string value)
        {
            var root = AppConfigMap();
            root["data"]![key] = value;
            return root;
        }

        JsonObject Values(string key, JsonNode value)
        {
            var root = GrafanaHelmRelease();
            root["spec"]!["values"]![key] = value;
            return root;
        }

        using var gzipped = new MemoryStream();
        using (var gzip = new GZipStream(gzipped, CompressionLevel.Fastest, leaveOpen: true))
        {
            gzip.Write(Encoding.UTF8.GetBytes("database:\n  password: " + MixedPassword(20) + "\n"));
        }

        var splitEnv = Deployment();
        Container(splitEnv)["env"]!.AsArray().Add(new JsonObject { ["name"] = "GH_TOKEN_PART1", ["value"] = token[..20] });
        Container(splitEnv)["env"]!.AsArray().Add(new JsonObject { ["name"] = "GH_TOKEN_PART2", ["value"] = token[20..] });

        return
        [
            new("Short low-entropy password under a secret key (DB_PASSWORD=hunter2)", Env("DB_PASSWORD", "hunter2"), true),
            new("Single-class passphrase (correcthorsebatterystaple)", Env("ADMIN_PASSWORD", "correcthorsebatterystaple"), true),
            new("Passphrase containing spaces", Data("admin-password", "correct horse battery staple"), true),
            new("Random password under a non-secret key name", Data("connection-info", MixedPassword(18)), true),
            new("Random password in a CRD field with no keyword", Values("adminUser", new JsonObject { ["name"] = "admin", ["pass"] = MixedPassword(18) }), false),
            new("Known-format token split across two env vars", splitEnv, true),
            new("Base64-encoded GitHub token", Data("gh", B64(token)), true),
            new("Hex-encoded AWS secret key", Values("blob", Convert.ToHexString(Encoding.UTF8.GetBytes(awsSecret))), false),
            new("Reversed GitHub token", Env("WEBHOOK_SEED", new string(token.Reverse().ToArray())), true),
            new("Docker config JSON base64-encoded in a ConfigMap", Data(".dockerconfigjson", B64(dockerConfig)), true),
            new("Gzip+base64 config containing a password", Data("config.yaml.gz", Convert.ToBase64String(gzipped.ToArray())), true),
            new("Credential used as a ConfigMap key (keys are not scanned)", Data(token, "enabled"), false),
            new("Unsupported vendor format without keyword (sk-proj-…)", Values("endpointConfig", "sk-" + "proj-" + Chars(Alnum + "-_", 48)), false),
            new("Numeric PIN stored as a JSON number", Values("pinCode", JsonValue.Create(84726153)), false),
            new("URL-encoded basic-auth credentials in a query string", Values("callback", "https://hooks.home.arpa/notify?auth=" + Uri.EscapeDataString("admin:" + MixedPassword(16))), false),
        ];
    }

    private static JsonObject Parse(string json) => JsonNode.Parse(json)!.AsObject();

    /// <summary>Replaces each <c>@TOKEN@</c> occurrence with a fresh JSON-escaped value.</summary>
    private string Fill(string template) => TokenRegex().Replace(template, match =>
    {
        var token = match.Groups[1].Value;
        var value = token switch
        {
            "UID" => Uid(),
            "COMMIT" => commit,
            "ALNUM43" => Chars(Alnum, 43),
            "B64URL342" => Chars(Alnum + "-_", 342),
            "CA_PEM" => caCertificatePem,
            "INT_PEM" => intermediateCertificatePem,
            "PUB_PEM" => publicKeyPem,
            "CA_B64" => B64(caCertificatePem),
            "INT_B64" => B64(intermediateCertificatePem),
            "CSR_B64" => B64(csrPem),
            _ when token.StartsWith("RANDB64_", StringComparison.Ordinal) => Base64Bytes(int.Parse(token[8..], CultureInfo.InvariantCulture)),
            _ when token[0] == 'H' => Hex(int.Parse(token[1..], CultureInfo.InvariantCulture)),
            _ => throw new InvalidOperationException($"Unknown corpus token {token}.")
        };
        return JsonEncodedText.Encode(value).ToString();
    });

    [GeneratedRegex("@([A-Z][A-Z0-9_]*)@")]
    private static partial Regex TokenRegex();
}
