# OWASP Kubernetes Top 10

Load this reference when reviewing Kubernetes manifests, Helm charts,
cluster configuration, RBAC, NetworkPolicies, or anything under a
`kubectl apply`.

**Source & edition.** Content below is pinned to the **2022 edition**
of the OWASP Kubernetes Top 10, which remains the canonical project
page: <https://owasp.org/www-project-kubernetes-top-ten/> (2022 index
at `/2022/en/src/`). OWASP has published a 2025 edition that renumbers
several items (secrets → K03, network segmentation → K05, auth → K09);
if you review a cluster against 2025 requirements, verify each mapping
against the 2025 per-item pages before citing codes [?].

## How to use

Match the manifest you're reviewing against the detection signals,
propose the minimal hardening that addresses the issue, and cite both
the code (`K01`) and the title. Many K8s issues are absent controls —
the finding is "no NetworkPolicy", not a vulnerable line. Treat the
absence as the evidence.

---

## K01: Insecure Workload Configurations

Source: <https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/K01-insecure-workload-configurations>

Pod specs shipped with container-breakout levers enabled: privileged
mode, root user, writable root FS, no resource limits, missing
probes. These defaults are safe in development and dangerous in
production.

**Detection signals**
- `securityContext.privileged: true`, `runAsUser: 0`, or missing
  `runAsNonRoot: true`.
- `allowPrivilegeEscalation: true` (default is true — must be set to
  false).
- `capabilities.add: [...]` without corresponding `drop: [ALL]`.
- No `resources.limits` — pod can exhaust node.
- `image: myapp:latest` — tag floats; signatures and scans won't bind.
- `hostNetwork: true`, `hostPID: true`, `hostIPC: true` outside an
  explicit reason.
- `readOnlyRootFilesystem` missing or false.

**Mitigation**
```yaml
apiVersion: v1
kind: Pod
metadata:
  name: secure-app
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    fsGroup: 1000
    seccompProfile: { type: RuntimeDefault }
  containers:
  - name: app
    image: registry.example.com/app@sha256:3b6eae...   # pin by digest
    imagePullPolicy: IfNotPresent
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities: { drop: [ALL] }
    resources:
      requests: { memory: "128Mi", cpu: "250m" }
      limits:   { memory: "256Mi", cpu: "500m" }
    livenessProbe: { httpGet: { path: /healthz, port: 8080 } }
  volumes:
  - name: tmp
    emptyDir: {}
```
- Apply Pod Security Admission `restricted` profile per namespace
  (`pod-security.kubernetes.io/enforce: restricted` label).
- Pin images by digest, not tag.

**Checklist**
- [ ] `runAsNonRoot: true`, `allowPrivilegeEscalation: false`,
      `readOnlyRootFilesystem: true`, `capabilities.drop: [ALL]`.
- [ ] Resource `requests` and `limits` set.
- [ ] Image pinned by digest.
- [ ] Namespace enforces Pod Security `restricted`.

---

## K02: Supply Chain Vulnerabilities

Source: <https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/K02-supply-chain-vulnerabilities>

Note: in some editions K02 is titled "RBAC misconfiguration". The
2022 page canonically lists K02 as **Supply Chain Vulnerabilities**
and K03 as **Overly Permissive RBAC**; verify against the current
project index before quoting a specific code. The detection signals
for **RBAC misuse** are captured under K03 below.

**Detection signals (supply chain)**
- Images pulled from public registries without scanning.
- `FROM ubuntu:latest` or similar unpinned base images.
- No SBOM produced at build.
- Manifests fetched at runtime (`kubectl apply -f https://...`)
  without signature verification.

**Mitigation**
- Image admission policy (Sigstore policy-controller, Kyverno,
  Gatekeeper) requiring signed images from approved registries.
- Pin images by digest; generate SBOM at build; store with the
  release artifact.
- Scan images on push; block criticals from promotion.

**Checklist**
- [ ] All production images signed + pinned by digest.
- [ ] Admission policy enforces signature verification.
- [ ] SBOM generated and retained.
- [ ] No runtime fetch of unsigned manifests.

---

## K03: Overly Permissive RBAC

Source: <https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/K03-overly-permissive-rbac>

ClusterRoles / Roles granting far more than any workload needs.
Wildcard verbs, `*` resources, and bindings to `system:authenticated`
are the canonical patterns.

**Detection signals**
- `verbs: ["*"]` or `resources: ["*"]` in Role/ClusterRole rules.
- Bindings to `system:authenticated` or `system:unauthenticated`.
- A single ServiceAccount used across many unrelated workloads.
- `ClusterRoleBinding` to the default `cluster-admin` role for
  workloads (should be rare, human-only, and time-boxed).
- `resourceNames` never used — role grants verbs on all objects of a
  kind.

**Mitigation**
```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata: { namespace: payments, name: read-db-creds }
rules:
- apiGroups: [""]
  resources: [secrets]
  resourceNames: [db-creds]           # single object, not wildcard
  verbs: [get]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata: { namespace: payments, name: read-db-creds }
roleRef: { apiGroup: rbac.authorization.k8s.io, kind: Role, name: read-db-creds }
subjects:
- kind: ServiceAccount
  name: payments-api
  namespace: payments
```
- Write least-privilege roles per workload; use `resourceNames` to
  scope to individual objects.
- Audit existing bindings with `kubectl auth can-i --list` or
  `rakkess` / `rbac-lookup`.
- Reject wildcard RBAC at PR review or via an admission policy.

**Checklist**
- [ ] No `*` verbs or resources in Role/ClusterRole rules.
- [ ] No bindings to `system:authenticated` or default SAs.
- [ ] Each workload uses its own ServiceAccount.
- [ ] `resourceNames` scoped for access to named objects.

---

## K04: Lack of Centralized Policy Enforcement

Source: <https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/K04-policy-enforcement>

Without an admission controller enforcing policy, guardrails rely on
developers remembering rules. At scale, rules drift.

**Detection signals**
- No Pod Security Admission labels on namespaces.
- No Kyverno / Gatekeeper / OPA installed.
- Image allowlists enforced in documentation, not code.
- Constraints referenced in README but no matching `Constraint` /
  `Policy` resource in the cluster.

**Mitigation**
```yaml
apiVersion: v1
kind: Namespace
metadata:
  name: payments
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: latest
    pod-security.kubernetes.io/audit: restricted
    pod-security.kubernetes.io/warn: restricted
```
- Start with Pod Security Admission (built-in). Layer Kyverno or
  Gatekeeper for cross-cutting rules (image registry allowlist,
  required labels, no `:latest`, `NetworkPolicy` presence).
- Ship policy as code in the same repo as manifests.

**Checklist**
- [ ] Every namespace has Pod Security Admission labels.
- [ ] A policy engine (Kyverno/Gatekeeper) enforces custom rules.
- [ ] Policies versioned with the rest of the cluster config.

---

## K05: Inadequate Logging and Monitoring

Source: <https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/K05-inadequate-logging>

Audit gaps make detection and forensics impossible. Without
kube-apiserver audit, control-plane events, and workload logs shipped
off-cluster, compromise goes unnoticed.

**Detection signals**
- `kube-apiserver` started without `--audit-log-path` /
  `--audit-policy-file`.
- Logs stored on nodes only; no aggregation to a SIEM / log service.
- Falco, Tetragon, or equivalent runtime security not installed.
- No alerts on high-signal events (service account token exfiltration,
  exec into pod, privilege escalation attempts, unauthenticated API
  server requests).

**Mitigation**
- Enable API server audit with a targeted policy (at minimum: `Metadata`
  for reads, `Request` for mutating verbs on sensitive resources).
- Ship audit + pod logs off-cluster (Loki, Elastic, Datadog, Splunk).
- Deploy a runtime-security agent (Falco, Tracee, Tetragon).
- Alert on: `exec` into pod, changes to ClusterRoleBindings, anonymous
  API calls, serviceaccount token reads by non-legitimate subjects.

**Checklist**
- [ ] API server audit enabled and shipped off-cluster.
- [ ] Pod logs shipped to a log service.
- [ ] Runtime-security tool deployed and alerting.
- [ ] Top 5 alert rules documented and tested.

---

## K06: Broken Authentication Mechanisms

Source: <https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/K06-broken-authentication>

Kubernetes accepts many authentication mechanisms (client certs, static
tokens, OIDC, ServiceAccount tokens, cloud IAM). Any weak or
unrevokable credential in that mix undermines the whole cluster.

**Detection signals**
- `--anonymous-auth=true` on `kube-apiserver` or `kubelet` (see K09).
- Client-certificate auth for human users — certs can't be revoked
  through the API, only by rotating the CA.
- Long-lived `ServiceAccount` tokens as `Secret` of type
  `kubernetes.io/service-account-token` instead of projected/bound.
- `automountServiceAccountToken: true` (default) on Pods that don't
  call the API.
- kubeconfig files committed to git (grep for `client-certificate-data`).
- No `--oidc-issuer-url` / `--oidc-client-id` on the API server in
  environments that claim SSO.

**Mitigations**

Disable token automount by default; opt in explicitly:

```yaml
apiVersion: v1
kind: ServiceAccount
metadata: { name: app, namespace: payments }
automountServiceAccountToken: false
---
apiVersion: v1
kind: Pod
spec:
  serviceAccountName: app
  automountServiceAccountToken: true   # only on pods that call the API
```

Use short-lived, audience-bound projected tokens instead of Secret-backed:

```yaml
spec:
  volumes:
  - name: vault-token
    projected:
      sources:
      - serviceAccountToken:
          path: vault-token
          expirationSeconds: 3600
          audience: vault
```

Require OIDC + MFA for human access (`--oidc-issuer-url`,
`--oidc-client-id`, `--oidc-username-claim`); use
`kubectl create token <sa> --duration=15m` for break-glass.

**Checklist**
- [ ] No `*.kubeconfig` or client certs in version control.
- [ ] Human auth via OIDC with MFA; certs break-glass only.
- [ ] `automountServiceAccountToken` defaults to `false` on new SAs.
- [ ] No `Secret` of type `service-account-token` unless legacy demands.
- [ ] Tokens issued via `TokenRequest` with `--duration` and audience.

---

## K07: Missing Network Segmentation Controls

Source: <https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/K07-network-segmentation>

Pod networking is flat by default. Without NetworkPolicies (or a
service-mesh equivalent), one compromised container can sweep the
cluster, hit internal databases, and reach the cloud metadata endpoint.

**Detection signals**
- `kubectl get networkpolicies --all-namespaces` returns nothing (or
  only a handful on a multi-tenant cluster).
- CNI in use doesn't enforce NetworkPolicy (plain Flannel without a
  policy plugin) [?] — verify against the CNI's docs.
- Namespaces with databases or secrets operators have no ingress
  restrictions.
- Pods can `curl http://169.254.169.254/` with no legitimate need.
- Ingress without TLS; `Service` of type `LoadBalancer` for
  internal-only workloads.

**Mitigations**

Default-deny per namespace:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: default-deny-all, namespace: payments }
spec:
  podSelector: {}
  policyTypes: [Ingress, Egress]
```

Block cloud-metadata egress from workloads that don't need it:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: block-metadata, namespace: payments }
spec:
  podSelector: {}
  policyTypes: [Egress]
  egress:
  - to:
    - ipBlock:
        cidr: 0.0.0.0/0
        except:
        - 169.254.169.254/32   # AWS/GCP/Azure IMDS
        - 169.254.170.2/32     # ECS task metadata
```

Allow only named callers into sensitive services:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: { name: redis-allow-api, namespace: payments }
spec:
  podSelector: { matchLabels: { app: redis } }
  policyTypes: [Ingress]
  ingress:
  - from:
    - podSelector: { matchLabels: { app: api } }
    ports:
    - { protocol: TCP, port: 6379 }
```

Use a service mesh (Istio, Linkerd, Consul) for identity-based
segmentation when L4 selectors aren't enough.

**Checklist**
- [ ] Every namespace has a default-deny NetworkPolicy.
- [ ] Metadata endpoints blocked cluster-wide by egress policy.
- [ ] Sensitive backends (DB, cache, queue) accept only labeled
      caller pods.
- [ ] CNI in use actually enforces NetworkPolicy — verified with a
      deny-test pod.
- [ ] mTLS on for east-west traffic where identity matters.

---

## K08: Secrets Management Failures

Source: <https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/K08-secrets-management>

`Secret` values are base64-encoded, not encrypted, and sit in etcd.
Without at-rest encryption, tight RBAC, and audit, any backup, etcd
reader, or over-privileged pod turns secrets into plaintext.

**Detection signals**
- `Secret` manifests committed to git (grep `kind: Secret` + `data:`).
- No `EncryptionConfiguration` referenced by `kube-apiserver`
  (`--encryption-provider-config` flag missing).
- `ClusterRole` / `Role` bindings granting `get`/`list` on `secrets`
  to broad subjects (`system:authenticated`, default SAs, CI SAs).
- Pods mounting `/var/run/secrets/kubernetes.io/serviceaccount` when
  they never call the API.
- Third-party controllers with cluster-wide `secrets` access that only
  need one namespace.

**Mitigations**

Enable at-rest encryption in etcd with a KMS provider:

```yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
- resources: [secrets]
  providers:
  - kms:
      name: cloud-kms
      endpoint: unix:///var/run/kmsplugin/socket.sock
      cachesize: 1000
      timeout: 3s
  - identity: {}
```

Source secrets from an external store via the Secrets Store CSI driver
so values never live in etcd:

```yaml
apiVersion: secrets-store.csi.x-k8s.io/v1
kind: SecretProviderClass
metadata: { name: db-creds, namespace: payments }
spec:
  provider: vault
  parameters:
    roleName: payments-db
    objects: |
      - objectName: db-password
        secretPath: secret/data/payments/db
        secretKey: password
```

Least-privilege RBAC on secrets — name them explicitly (see K03
example).

Enable audit logging for `secrets` at `Metadata` level minimum so
anomalous reads reach the SIEM.

**Checklist**
- [ ] `EncryptionConfiguration` loaded; `secrets` in `resources`;
      legacy data re-written to trigger encryption.
- [ ] No `Secret` manifests in git; gitleaks/trufflehog in CI.
- [ ] RBAC on `secrets` uses `resourceNames`.
- [ ] Audit policy logs `get`/`list` on `secrets`.
- [ ] External store (Vault, cloud SM) + CSI for rotating secrets.

---

## K09: Misconfigured Cluster Components

Source: <https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/K09-misconfigured-cluster-components>

`kube-apiserver`, `kubelet`, `etcd`, and the controller-manager ship
with flags safe in dev and dangerous in prod. OWASP cites large-scale
internet exposure as the motivating risk (the project page references
"over 900,000 Kubernetes instances found exposed online").

**Detection signals**
- `kubelet` with `--anonymous-auth=true` or
  `--authorization-mode=AlwaysAllow`.
- `kube-apiserver` reachable from the public internet (check LB /
  security group, not just flags).
- `etcd` peer or client ports (2379, 2380) reachable without mTLS, or
  `--client-cert-auth=false`.
- No `--audit-log-path` / `--audit-policy-file` on API server.
- Admission chain missing `NodeRestriction`, `PodSecurity`, or policy
  engine equivalent.
- CIS Benchmark (kube-bench) failures in Master/Worker sections.

**Mitigations**

Harden the kubelet config (prefer config file over flags):

```yaml
apiVersion: kubelet.config.k8s.io/v1beta1
kind: KubeletConfiguration
authentication:
  anonymous: { enabled: false }
  webhook:   { enabled: true }
  x509:      { clientCAFile: /etc/kubernetes/pki/ca.crt }
authorization:
  mode: Webhook
readOnlyPort: 0
protectKernelDefaults: true
```

Restrict API server exposure and enable audit:

```yaml
# kube-apiserver static pod (illustrative excerpt)
- command:
  - kube-apiserver
  - --anonymous-auth=false
  - --authorization-mode=Node,RBAC
  - --enable-admission-plugins=NodeRestriction,PodSecurity
  - --audit-log-path=/var/log/kube-apiserver-audit.log
  - --audit-policy-file=/etc/kubernetes/audit-policy.yaml
  - --encryption-provider-config=/etc/kubernetes/encryption.yaml
```

Keep the load balancer private; expose the API only via bastion / VPN
/ cloud-private endpoint. Enforce Pod Security Standards per
namespace (see K04). Run CIS benchmarks (kube-bench CronJob pattern
[?]) on a schedule and gate infra PRs on the result.

**Checklist**
- [ ] kube-bench runs in CI against control-plane nodes.
- [ ] API server unreachable from `0.0.0.0/0`.
- [ ] Audit logs shipped off-cluster.
- [ ] `NodeRestriction` + `PodSecurity` admission plugins enabled.
- [ ] etcd uses mTLS and is reachable only from control-plane nodes.

---

## K10: Vulnerable Components

Source: <https://owasp.org/www-project-kubernetes-top-ten/2022/en/src/K10-vulnerable-components>

Kubernetes is an ecosystem, not a single binary. Every ingress
controller, GitOps tool, service mesh, CNI, CSI, and operator is
third-party code running with high privilege. OWASP cites three
historical cases: **CVE-2022-24348** (Argo CD Helm chart parsing),
the **ingress-nginx** custom-snippet disclosure (October 2021), and
**CVE-2020-8595** (Istio auth bypass via `?` / `#`). Don't invent
others.

**Detection signals**
- No image scanner in registry or admission pipeline.
- Images built `FROM ubuntu:latest` / `node:latest` without pinned
  digest.
- Cluster add-ons (ingress controller, cert-manager, Argo CD, Istio)
  more than one minor version behind upstream.
- `ClusterRole` granting `*` on `*` to a third-party operator.
- No SBOM at build; no provenance attestation on images.
- `HostPath` mounts or `hostNetwork: true` in third-party charts
  without justification.

**Mitigations**

Gate admission on image signatures and scan results:

```yaml
apiVersion: policy.sigstore.dev/v1beta1
kind: ClusterImagePolicy
metadata: { name: require-signed-prod }
spec:
  images:
  - glob: "registry.example.com/prod/**"
  authorities:
  - keyless:
      url: https://fulcio.sigstore.dev
      identities:
      - issuer: https://token.actions.githubusercontent.com
        subject: https://github.com/example/app/.github/workflows/release.yml@refs/heads/main
```

Pin images by digest:

```yaml
image: registry.example.com/app@sha256:3b6eae...e1d
```

Constrain third-party components with Gatekeeper/Kyverno policies
(e.g., reject `hostNetwork: true` outside an allowlisted namespace).
Subscribe to CVE feeds for every component you run; fold them into
SBOM review.

**Checklist**
- [ ] Every production image pinned by digest.
- [ ] Registry scanner blocks criticals from promotion.
- [ ] Admission controller enforces signature + policy at deploy time.
- [ ] Quarterly review of third-party RBAC grants; wildcards revoked.
- [ ] SBOM generated at build; stored with release artifact.

---

## Appendix: 2022 → 2025 cross-reference

If you migrate this skill to the 2025 list, the rough mapping is [?]:

- 2022 K06 Broken Authentication ≈ 2025 K09 Broken Authentication
  Mechanisms.
- 2022 K07 Network Segmentation ≈ 2025 K05 Missing Network
  Segmentation Controls.
- 2022 K08 Secrets Management ≈ 2025 K03 Secrets Management Failures.
- 2022 K09 Misconfigured Cluster Components ≈ 2025 K07 Misconfigured
  and Vulnerable Cluster Components (merged with old K10).
- 2022 K10 Vulnerable Components ≈ folded into 2025 K07 [?].

Confirm against individual 2025 per-item pages before quoting codes.
