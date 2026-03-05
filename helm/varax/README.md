# Varax Helm Chart

Installs the Varax compliance operator into a Kubernetes cluster.

## Prerequisites

- Kubernetes 1.26+
- Helm 3.8+

## Installation

```bash
# Install from OCI registry (recommended)
helm install varax oci://ghcr.io/varaxlabs/charts/varax \
  --namespace varax-system \
  --create-namespace

# Install a specific version
helm install varax oci://ghcr.io/varaxlabs/charts/varax \
  --version 1.0.0 \
  --namespace varax-system \
  --create-namespace

# Install with audit logging enabled (EKS)
helm install varax oci://ghcr.io/varaxlabs/charts/varax \
  --namespace varax-system \
  --create-namespace \
  --set config.auditLogging.autoEnable=true \
  --set cloudProvider.aws.enabled=true \
  --set cloudProvider.aws.serviceAccount.annotations."eks\.amazonaws\.com/role-arn"="arn:aws:iam::ACCOUNT:role/varax"

# Install with custom scan interval
helm install varax oci://ghcr.io/varaxlabs/charts/varax \
  --namespace varax-system \
  --create-namespace \
  --set config.scanInterval=30m
```

### Install from source

```bash
helm install varax ./helm/varax \
  --namespace varax-system \
  --create-namespace
```

## Upgrade

```bash
helm upgrade varax oci://ghcr.io/varaxlabs/charts/varax \
  --namespace varax-system
```

## Uninstall

```bash
helm uninstall varax --namespace varax-system
```

Note: CRDs are not removed on uninstall. To remove them:

```bash
kubectl delete crd complianceconfigs.compliance.varax.io
```

## Values Reference

### Image

| Key | Default | Description |
|-----|---------|-------------|
| `image.repository` | `ghcr.io/varaxlabs/varax` | Container image repository |
| `image.tag` | `latest` | Image tag |
| `image.pullPolicy` | `IfNotPresent` | Image pull policy |

### Operator Configuration

| Key | Default | Description |
|-----|---------|-------------|
| `replicaCount` | `1` | Number of operator replicas (only 1 recommended) |
| `config.scanInterval` | `1h` | Time between compliance scans (Go duration) |
| `config.framework` | `SOC2` | Compliance framework |
| `config.auditLogging.autoEnable` | `false` | Auto-enable cloud provider audit logging |
| `config.remediation.enabled` | `false` | Enable auto-remediation (future) |
| `config.remediation.dryRun` | `true` | Dry-run mode for remediation |

### Cloud Provider

| Key | Default | Description |
|-----|---------|-------------|
| `cloudProvider.aws.enabled` | `false` | Enable AWS/EKS integration |
| `cloudProvider.aws.serviceAccount.annotations` | `{}` | SA annotations (e.g., IRSA role ARN) |

### Storage

| Key | Default | Description |
|-----|---------|-------------|
| `persistence.enabled` | `true` | Enable persistent storage for scan history |
| `persistence.size` | `1Gi` | PVC size |
| `persistence.storageClass` | `""` | StorageClass (empty = cluster default) |

### Prometheus

| Key | Default | Description |
|-----|---------|-------------|
| `prometheus.enabled` | `true` | Create metrics Service |
| `prometheus.serviceMonitor.enabled` | `false` | Create Prometheus ServiceMonitor |
| `prometheus.serviceMonitor.interval` | `30s` | Scrape interval |

### Resources

| Key | Default | Description |
|-----|---------|-------------|
| `resources.limits.cpu` | `200m` | CPU limit |
| `resources.limits.memory` | `256Mi` | Memory limit |
| `resources.requests.cpu` | `100m` | CPU request |
| `resources.requests.memory` | `128Mi` | Memory request |

### Service Account

| Key | Default | Description |
|-----|---------|-------------|
| `serviceAccount.create` | `true` | Create ServiceAccount |
| `serviceAccount.name` | `varax-operator` | ServiceAccount name |
| `serviceAccount.annotations` | `{}` | Additional ServiceAccount annotations |

### Scheduling

| Key | Default | Description |
|-----|---------|-------------|
| `nodeSelector` | `{}` | Node selector labels |
| `tolerations` | `[]` | Pod tolerations |
| `affinity` | `{}` | Pod affinity rules |

## What Gets Installed

- **Namespace** (if `--create-namespace`)
- **CRD**: `complianceconfigs.compliance.varax.io`
- **ServiceAccount**: `varax-operator`
- **ClusterRole**: Read-only access to pods, services, configmaps, secrets, namespaces, nodes, RBAC resources, network policies, deployments; full access to ComplianceConfig CRD
- **ClusterRoleBinding**: Binds the ClusterRole to the ServiceAccount
- **Deployment**: Operator pod running `varax operator`
- **Service**: ClusterIP for Prometheus metrics scraping (port 8080)
- **PersistentVolumeClaim**: 1Gi for BoltDB scan history (if persistence enabled)
- **ComplianceConfig**: Default SOC2 configuration
- **ServiceMonitor**: Prometheus scrape config (if enabled)

## Security

The operator runs with minimal privileges:

- Runs as non-root user (UID 65532)
- Read-only root filesystem
- No privilege escalation
- All capabilities dropped
- Seccomp profile: RuntimeDefault
- Read-only access to cluster resources (no cluster-admin)
- Distroless container base image

## Post-Install Verification

```bash
# Check the operator is running
kubectl get pods -n varax-system

# Check the ComplianceConfig status
kubectl get complianceconfigs -n varax-system

# Run an on-demand scan
kubectl exec -n varax-system deploy/varax -- varax scan

# Check metrics
kubectl port-forward -n varax-system svc/varax 8080:8080
curl -s http://localhost:8080/metrics | grep varax
```
