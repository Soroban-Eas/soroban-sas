# SAS Helm Chart

Production-ready Helm chart for deploying the SAS service on Kubernetes.

## Prerequisites

- Kubernetes 1.20 +
- Helm 3.8 +

## Installing

```sh
helm install my-sas ./charts/sas --namespace sas --create-namespace
```

To install with a custom values file:

```sh
helm install my-sas ./charts/sas -f my-values.yaml
```

## Uninstalling

```sh
helm uninstall my-sas
```

## Configuration

The following table lists the configurable parameters of the chart and their default values.

| Parameter | Description | Default |
|---------|------------|--------|
| `replicaCount` | Number of replicas to deploy | `2` |
| `image.repository` | Container image repository | `ghcr.io/streamingfast/substreams-sas` |
| `image.tag` | Container image tag (overrides appVersion) | `Chart.AppVersion` |
| `image.pullPolicy` | Image pull policy | `IfNotPresent` |
| `imagePullSecrets` | Image pull secrets list | `[]` |
| `service.type` | Kubernetes service type | `ClusterIP` |
| `service.port` | Service port | `8080` |
| `sas.logLevel` | SAS log level | `info` |
| `sas.port` | SAS container port | `8080` |
| `sas.env` | Additional environment variables (name/value pairs) | `[]` |
| `resources` | CPU/memory resources for the container | see `values.yaml` |
| `livenessProbe` | Liveness probe configuration | see `values.yaml` |
| `readinessProbe` | Readiness probe configuration | see `values.yaml` |
| `podSecurityContext` | Pod level security context | see `values.yaml` |
| `securityContext` | Container level security context | see `values.yaml` |
| `serviceAccount.create` | Create a ServiceAccount | `true` |
| `nodeSelector` | Node selector labels | `{}` |
| `tolerations` | Tolerations for the pod | `[]` |
| `affinity` | Affinity rules for the pod | `{}` |
| `updateStrategy` | Deployment update strategy | `RollingUpdate` |

## Security

By default the chart runs the container as a non-root user (UID 1000), with a read-only root filesystem and all capabilities dropped. Override `podSecurityContext` and `securityContext` if your image requires different settings.

## Testing

Validate the chart with:

```sh
helm lint ./charts/sas
helm template my-sas ./charts/sas
```
