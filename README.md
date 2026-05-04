# Platform Buckets Api

## S3/SeaweedFS/MinIO Configuration

This service supports multiple S3-compatible storage backends:
- **MinIO** (for local development, testing)
- **SeaweedFS** (recommended for production, staging, or feature testing)
- **AWS S3** (optional, standard S3 API)

### Selecting backend
- The backend is selected via `values.yaml` (`bucketProvider` section) or environment variables (see deployment templates).
- SeaweedFS S3 is the default for production environments.

### Example values.yaml
See the `charts/platform-buckets/values.yaml` for configuration examples.

### Required Kubernetes Secret for SeaweedFS
See your deployment's Kubernetes manifests for the required secret structure.

### Testing SeaweedFS S3 via aws-cli or mc
1. Port-forward SeaweedFS S3 if running in cluster.
2. Try listing buckets using AWS CLI or MinIO client (mc).

### Notes
- For readonly use cases, configure the deployment to use `read_access_key_id`.
- Switch between MinIO and SeaweedFS by changing the `type` field.
- All configuration and secrets are managed via Helm values/templates and Kubernetes Secrets.

## Local Development

1. Install minikube (https://github.com/kubernetes/minikube#installation)
2. Authenticate local docker (see AWS ECR documentation for details)
3. Launch minikube
4. Make sure the kubectl tool uses the minikube k8s cluster
5. Apply minikube configuration and some k8s fixture services
6. Create a new virtual environment with Python 3.8
7. Install testing dependencies
8. Install minio client (mc) to run tests. Refer to the MinIO documentation
9. Run the unit test suite
10. Run the integration test suite
11. Shutdown minikube

## How to release

Push new tag of form `vXX.XX.XX` where `XX.XX.XX` is semver version (please just use the date, like 20.12.31 for 31 December 2020). You can do this by using github "Create release" UI.
