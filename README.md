# Platform Buckets Api

## Local Development

1. Install minikube (https://github.com/kubernetes/minikube#installation);
2. Authenticate local docker:
```shell
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 771188043543.dkr.ecr.us-east-1.amazonaws.com
```
(If values is outdated, ask someone for recent on slack and then update this file)
3. Launch minikube:
```shell
make start_k8s
```
4. Make sure the kubectl tool uses the minikube k8s cluster:
```shell
minikube status
kubectl config use-context minikube
```
6. Apply minikube configuration and some k8s fixture services:
```shell
make apply_configuration_k8s
```
5. Create a new virtual environment with Python 3.8:
```shell
python -m venv venv
source venv/bin/activate
```
6. Install testing dependencies:
```shell
make setup
```
7. Install minio client (mc) to run tests. Refer to (https://docs.min.io/docs/minio-client-quickstart-guide.html)
8. Run the unit test suite:
```shell
make test_unit
```
9. Run the integration test suite:
```shell
make test_integration
```
10. Shutdown minikube:
```shell
minikube stop
```
