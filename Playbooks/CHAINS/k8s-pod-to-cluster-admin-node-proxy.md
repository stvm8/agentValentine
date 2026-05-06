# Chain: K8s Pod Shell → ORAS OCI Recon → CoreDNS Discovery → Kubelet Injection → SA Token Minting → Cluster-Admin
Tags: kubernetes, k8s, oras, oci, coredns, kubelet, service-account, token-minting, node-proxy, cluster-admin, pod-escape, rbac
Chain Severity: Critical
Entry Condition: Shell in a Kubernetes pod (staging namespace); ORAS and coredns-enum tools installed; pod has a service account with RBAC permissions

## Node 1 — ORAS OCI Registry Recon
Technique: [[Cloud/Kubernetes#ORAS OCI Registry Recon]]
Strike Vector: "ORAS OCI artifact discovery"
Condition: `oras` binary available in pod; internal or external OCI registry accessible from pod network; credentials or anonymous access to registry
Standalone Severity: Low
Branches:
  - `oras discover` / `oras pull` retrieves OCI artifacts (configs, scripts, internal tooling) with embedded cluster info → Node 2
  - Registry requires auth → check mounted SA token for registry auth; check env vars for registry credentials
  - No artifacts found → enumerate registry repos (`oras repo ls <registry>`); try common names (staging, prod, internal, tools)

## Node 2 — CoreDNS Service Discovery
Technique: [[Cloud/Kubernetes#CoreDNS Service Discovery]]
Strike Vector: "CoreDNS enumeration for internal cluster services"
Condition: `coredns-enum` or equivalent DNS brute-force tool available; pod has DNS resolution via cluster DNS; internal service names discoverable
Standalone Severity: Low
Branches:
  - CoreDNS enumeration reveals internal services (Kubelet API endpoint, internal registries, management planes) → Node 3
  - DNS enumeration blocked → check `/etc/resolv.conf` for cluster DNS IP; query directly with `dig axfr` or `nmap --script dns-brute`
  - Services discovered but Kubelet endpoint not found → probe standard Kubelet ports (10250, 10255) on node IPs from `kubectl get nodes -o wide` (if RBAC allows)

## Node 3 — Kubelet URL Injection
Technique: [[Cloud/Kubernetes#Kubelet URL Injection]]
Strike Vector: "Kubelet API URL injection via discovered endpoint"
Condition: Kubelet API endpoint discovered (port 10250); pod's service account has `nodes/proxy` subresource access or Kubelet allows anonymous reads
Standalone Severity: High
Branches:
  - Kubelet `/pods` endpoint accessible → enumerate pod specs and SA token paths → Node 4
  - Kubelet requires client cert (mutual TLS) → check if pod SA token accepted as bearer; check for `--anonymous-auth=true` on Kubelet config
  - RBAC denies `nodes/proxy` → inject Kubelet URL through a different vector (e.g., `kubectl exec --target-node` if exec perms available)

## Node 4 — Service Account Token Theft from Pod Spec
Technique: [[Cloud/Kubernetes#SA Token Theft via Kubelet]]
Strike Vector: "SA token extraction from Kubelet pod spec"
Condition: Kubelet `/pods` response includes mounted SA token paths or Kubelet `/run` / `/exec` API enables command execution in other pods
Standalone Severity: High
Branches:
  - Kubelet exec API reads token from `/var/run/secrets/kubernetes.io/serviceaccount/token` in target pod → Node 5
  - Token path not in pod spec → check projected volume mounts; try reading token via Kubelet `/run/<namespace>/<pod>/<container>` exec
  - Target pod has no elevated SA → enumerate all pods across namespaces via Kubelet; find pod with higher-privilege SA

## Node 5 — SA Token Minting (TokenRequest API)
Technique: [[Cloud/Kubernetes#SA Token Minting via TokenRequest API]]
Strike Vector: "TokenRequest API to mint long-lived SA token"
Condition: Stolen SA token has `serviceaccounts/token` create permission; target SA identified
Standalone Severity: High
Branches:
  - `kubectl create token <sa-name> --duration=8760h` (or TokenRequest API call) mints long-lived token → Node 6
  - SA lacks `serviceaccounts/token` create perm → use stolen token directly (short TTL — proceed quickly)
  - TokenRequest disabled in cluster → extract token from projected volume (default 1h TTL); automate refresh loop

## Node 6 — Node Proxy API Loopback to API Server
Technique: [[Cloud/Kubernetes#Node Proxy Loopback to API Server]]
Strike Vector: "node/proxy subresource loopback to API server"
Condition: Minted/stolen SA token with `nodes/proxy` subresource RBAC; knowledge of API server internal address; node proxy route passes SA token to loopback target
Standalone Severity: Critical
Branches:
  - Request via `nodes/<node>/proxy/` to API server loopback returns response authenticated as target SA → Node 7
  - Proxy request blocked by NetworkPolicy → attempt direct API server access if SA token works on external API server address
  - API server internal address unknown → check `KUBERNETES_SERVICE_HOST` env var in pod; check `kubectl cluster-info`

## Node 7 — Cluster-Admin Secret Access
Technique: [[Cloud/Kubernetes#Cluster-Admin Secret Read]]
Strike Vector: "cluster-admin secrets enumeration"
Condition: Effective cluster-admin privileges via proxied SA token; `kubectl get secrets -A` or API call to `/api/v1/namespaces/<ns>/secrets`
Standalone Severity: Critical
Branches:
  - `kubectl get secret -n <namespace> <secret-name> -o jsonpath='{.data.<key>}' | base64 -d` returns flag → [TERMINAL] Chain Complete (Critical)
  - Secrets found but flag not in expected namespace → enumerate all namespaces (`kubectl get ns`); look for `flag`, `ctf`, `prod`, `admin` namespaces
  - RBAC limits secret read even with cluster-admin SA → SA may not actually have cluster-admin — verify with `kubectl auth can-i get secrets --all-namespaces`
