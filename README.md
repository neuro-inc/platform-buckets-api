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
```yaml
bucketProvider:
  # --- MinIO S3 config example (commented, inactive):
  # type: "minio"
  # minio:
  #   url: http://minio.platform:9000
  #   publicUrl: http://minio.platform:9000
  #   regionName: "us-east-1"
  #   accessKeyId:
  #     valueFrom:
  #       secretKeyRef:
  #         name: minio-secret
  #         key: access_key_id
  #   secretAccessKey:
  #     valueFrom:
  #       secretKeyRef:
  #         name: minio-secret
  #         key: secret_access_key

  # --- SeaweedFS S3 provider (active) ---
  type: "seaweedfs"
  seaweedfs:
	url: http://seaweedfs-s3:9000
	publicUrl: http://seaweedfs-s3:9000
	regionName: "us-east-1"
	accessKeyId:
	  valueFrom:
		secretKeyRef:
		  name: seaweedfs-s3-secret
		  key: admin_access_key_id
	secretAccessKey:
	  valueFrom:
		secretKeyRef:
		  name: seaweedfs-s3-secret
		  key: admin_secret_access_key
	# For readonly mode: use read_access_key_id/read_secret_access_key from the same secret.
```

### Required Kubernetes Secret for SeaweedFS
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: seaweedfs-s3-secret
  namespace: <your-namespace>
type: Opaque
data:
  admin_access_key_id: <base64-encoded>
  admin_secret_access_key: <base64-encoded>
  read_access_key_id: <base64-encoded>
  read_secret_access_key: <base64-encoded>
```

### Testing SeaweedFS S3 via aws-cli or mc
1. Port-forward SeaweedFS S3 if running in cluster:
   ```shell
   kubectl port-forward svc/seaweedfs-s3 9000:9000 -n <namespace>
   ```
2. Try listing buckets:
   ```shell
   AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... aws --endpoint-url http://localhost:9000 s3 ls
   ```
   or with MinIO client (mc):
   ```shell
   mc alias set seaweed http://localhost:9000 <admin_access_key_id> <admin_secret_access_key>
   mc ls seaweed
   ```

### Notes
- For readonly use cases, configure the deployment to use `read_access_key_id`.
- Switch between MinIO and SeaweedFS by changing the `type` field.
- All configuration and secrets are managed via Helm values/templates and Kubernetes Secrets.

## Local Development

1. Install minikube (https://github.com/kubernetes/minikube#installation);
2. Authenticate local docker:
   ```shell
   aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 771188043543.dkr.ecr.us-east-1.amazonaws.com
   ```
   (If values are outdated, ask someone for recent on slack and then update this file)
3. Launch minikube:
   ```shell
   make start_k8s
   ```
4. Make sure the kubectl tool uses the minikube k8s cluster:
   ```shell
   minikube status
   kubectl config use-context minikube
   ```
5. Apply minikube configuration and some k8s fixture services:
   ```shell
   make apply_configuration_k8s
   ```
6. Create a new virtual environment with Python 3.8:
   ```shell
   python -m venv venv
   source venv/bin/activate
   ```
7. Install testing dependencies:
   ```shell
   make setup
   ```
8. Install minio client (mc) to run tests. Refer to (https://docs.min.io/docs/minio-client-quickstart-guide.html)
9. Run the unit test suite:
   ```shell
   make test_unit
   ```
10. Run the integration test suite:
   ```shell
   make test_integration
   ```
11. Shutdown minikube:
   ```shell
   minikube stop
   ```

## How to release

Push new tag of form `vXX.XX.XX` where `XX.XX.XX` is semver version
(please just use the date, like 20.12.31 for 31 December 2020).
You can do this by using github "Create release" UI.
