# k run -it migration --image=python --restart=Never --command -- bash
#
# apt-get update && apt-get install -y vim & \
# pip install 'apolo-kube-client==25.7.0' neuro-logging
#
# example usage:
#
# python \
#   migration.py
#   --dry-run \
#   --delete-old \
#   kube \
#   --endpoint-url=http://cluster-url \
#   --auth-type=token \
#   --token-path=/path/to/token \
#   --ca-path=/path/to/ca

# a --delete-old flag can be omitted if we want first to verify,
# that resources were migrated into a new namespaces

from __future__ import annotations

import argparse
import asyncio
import logging
from argparse import ArgumentParser
from pathlib import Path
from typing import Any

from apolo_kube_client.apolo import (
    NO_ORG,
    create_namespace,
    generate_namespace_name,
    normalize_name,
)
from apolo_kube_client.client import KubeClient, kube_client_from_config
from apolo_kube_client.config import KubeClientAuthType, KubeConfig
from apolo_kube_client.errors import ResourceExists
from neuro_logging import (
    init_logging,
)

logger = logging.getLogger(__name__)

BUCKETS_ID_LABEL = "platform.neuromation.io/id"
BUCKETS_OWNER_LABEL = "platform.neuromation.io/owner"
BUCKETS_CREDENTIALS_NAME_LABEL = "platform.neuromation.io/credentials_name"
BUCKETS_BUCKET_NAME_LABEL = "platform.neuromation.io/bucket_name"
ORG_NAME_LABEL = "platform.neuromation.io/org_name"
PROJECT_LABEL = "platform.neuromation.io/project"
NEW_ORG_NAME_LABEL = "platform.apolo.us/org"

DEFAULT_NAMESPACE = "platform-jobs"


def to_new_label_name(old_label_name: str) -> str | None:
    if "platform.neuromation.io" not in old_label_name:
        return None
    if old_label_name.endswith("org_name"):
        return NEW_ORG_NAME_LABEL
    return old_label_name.replace("platform.neuromation.io", "platform.apolo.us")


def gen_labels_from_original_labels(labels: dict[str, str]) -> dict[str, str]:
    for label_name in list(labels):
        new_label_name = to_new_label_name(label_name)
        if not new_label_name:
            continue
        labels[new_label_name] = labels[label_name]
    return labels


async def migrate(
    args: argparse.Namespace,
    targets: list[str],
    dry_run: bool = True,
    delete_old: bool = False,
) -> None:
    """
    Migration entrypoint
    """
    ca_data = Path(args.ca_path).read_text()
    token = Path(args.token_path).read_text()

    kube_config = KubeConfig(
        endpoint_url=args.endpoint_url,
        cert_authority_data_pem=ca_data,
        auth_type=KubeClientAuthType.TOKEN,
        token=token,
        token_path=args.token_path,
    )

    async with kube_client_from_config(kube_config) as kube_client:
        if delete_old:
            if "buckets" in targets:
                await delete_old_buckets(kube_client, dry_run=dry_run)
            if "secrets" in targets:
                await delete_old_secrets(kube_client, dry_run=dry_run)
        else:
            if "buckets" in targets:
                await migrate_buckets(kube_client, dry_run=dry_run)
            if "secrets" in targets:
                await migrate_secrets(kube_client, dry_run=dry_run)


async def migrate_buckets(
    kube_client: KubeClient,
    dry_run: bool = True,
) -> None:
    # creds are not linked directly to org and proj, so we need this mapping
    bucket_id_to_namespace = await _ensure_credentials_namespaces_are_known(kube_client)

    url = user_buckets_url(kube_client)
    response = await kube_client.get(url)
    for old_bucket in response["items"]:
        await create_bucket(
            kube_client=kube_client,
            old_bucket=old_bucket,
            bucket_id_to_namespace=bucket_id_to_namespace,
            dry_run=dry_run,
        )

    url = persistent_bucket_credentials_url(kube_client)
    response = await kube_client.get(url)
    for old_credentials in response["items"]:
        await create_credentials(
            kube_client=kube_client,
            old_credentials=old_credentials,
            bucket_id_to_namespace=bucket_id_to_namespace,
            dry_run=dry_run,
        )


async def create_bucket(
    kube_client: KubeClient,
    old_bucket: dict[str, Any],
    bucket_id_to_namespace: dict[str, str],
    *,
    dry_run: bool,
) -> None:
    metadata = old_bucket["metadata"]
    spec = old_bucket["spec"]
    labels = metadata["labels"]

    project_name = labels.get(PROJECT_LABEL) or labels[BUCKETS_OWNER_LABEL]
    org_name = labels.get(ORG_NAME_LABEL)
    if not org_name or normalize_name(org_name) == normalize_name(NO_ORG):
        org_name = normalize_name(NO_ORG)

    labels[ORG_NAME_LABEL] = org_name
    labels[PROJECT_LABEL] = project_name

    bucket_id = labels[BUCKETS_ID_LABEL]
    labels = gen_labels_from_original_labels(labels)

    if dry_run:
        namespace_name = bucket_id_to_namespace[bucket_id]
        logger.info(f"dry_run: will create namespace {namespace_name}")
    else:
        created_namespace = await create_namespace(kube_client, org_name, project_name)
        namespace_name = created_namespace.name

    payload = {
        "kind": "UserBucket",
        "apiVersion": "neuromation.io/v1",
        "metadata": {
            "name": metadata["name"],
            "labels": labels,
        },
        "spec": spec,
    }

    bucket_creation_url = generate_user_buckets_url(kube_client, namespace_name)

    if dry_run:
        logger.info(f"dry_run: POST {bucket_creation_url}. {payload}")
    else:
        await kube_client.post(
            bucket_creation_url,
            json=payload,
        )


async def create_credentials(
    kube_client: KubeClient,
    old_credentials: dict[str, Any],
    bucket_id_to_namespace: dict[str, str],
    *,
    dry_run: bool,
):
    metadata = old_credentials["metadata"]
    name = metadata["name"]

    namespace = None

    for bucket_id in old_credentials["spec"]["bucket_ids"]:
        namespace = bucket_id_to_namespace[bucket_id]
        if namespace:
            break

    if not namespace:
        raise RuntimeError()

    labels = gen_labels_from_original_labels(labels=metadata["labels"])
    payload = {
        "kind": "PersistentBucketCredential",
        "apiVersion": "neuromation.io/v1",
        "metadata": {"name": name, "labels": labels},
        "spec": old_credentials["spec"],
    }
    credentials_creation_url = generate_persistent_bucket_credential_url(
        kube_client, namespace
    )
    if dry_run:
        logger.info(f"dry_run: POST {credentials_creation_url}. {payload}")
    else:
        await kube_client.post(credentials_creation_url, json=payload)


async def migrate_secrets(
    kube_client: KubeClient,
    dry_run: bool = True,
) -> None:
    url = generate_secrets_url(kube_client, namespace=DEFAULT_NAMESPACE)
    response = await kube_client.get(url)

    scope = []

    # let's gather a scope of work
    for item in response["items"]:
        secret_name = item["metadata"]["name"]
        if not secret_name.startswith("project"):
            continue

        parts = secret_name.split("--")

        # we need to ensure that all secret names are parseable,
        # and we can extract an org and project names
        if len(parts) == 3:
            org_name = normalize_name(NO_ORG)
            project_name = parts[1]
        elif len(parts) == 4:
            org_name, project_name = parts[1], parts[2]
        else:
            org_name = project_name = None

        scope.append((item, org_name, project_name))

    # a sanity-check to ensure that all secrets are migratable
    failed_secrets = []
    for item, org_name, project_name in scope:
        if not org_name or not project_name:
            failed_secrets.append(item)
    if failed_secrets:
        raise RuntimeError(
            f"unable to extract proper org/project names from secrets: "
            f"{', '.join([x['metadata']['name'] for x in failed_secrets])}"
        )

    # create secrets in a new namespaces
    for old_secret, org_name, project_name in scope:
        await create_secret(
            kube_client=kube_client,
            old_secret=old_secret,
            org_name=org_name,
            project_name=project_name,
            dry_run=dry_run,
        )


async def create_secret(
    kube_client: KubeClient,
    old_secret: dict[str, Any],
    org_name: str,
    project_name: str,
    *,
    dry_run: bool,
):
    metadata = old_secret["metadata"]
    secret_name = metadata["name"]

    labels = metadata.get("labels", {}) or {}
    labels[ORG_NAME_LABEL] = org_name
    labels[PROJECT_LABEL] = project_name

    labels = gen_labels_from_original_labels(labels)

    payload = {
        "kind": "Secret",
        "apiVersion": "v1",
        "type": old_secret["type"],
        "data": old_secret["data"],
        "metadata": {
            "name": secret_name,
            "labels": labels,
        },
    }
    if "spec" in old_secret:
        payload["spec"] = old_secret["spec"]
    if dry_run:
        org_name = normalize_name(org_name)
        project_name = normalize_name(project_name)
        namespace_name = generate_namespace_name(org_name, project_name)
        logger.info(f"dry_run: will create namespace {namespace_name}")
    else:
        created_namespace = await create_namespace(kube_client, org_name, project_name)
        namespace_name = created_namespace.name

    secret_creation_url = generate_secrets_url(kube_client, namespace_name)
    if dry_run:
        logger.info(f"dry_run: POST {secret_creation_url}. {payload}")
    else:
        try:
            await kube_client.post(
                secret_creation_url,
                json=payload,
            )
        except ResourceExists:
            pass


def apis_url(kube_client: KubeClient) -> str:
    return f"{kube_client._base_url}/apis"


def neuromation_url(kube_client: KubeClient) -> str:
    return f"{apis_url(kube_client)}/neuromation.io/v1"


def user_buckets_url(kube_client: KubeClient) -> str:
    return f"{apis_url(kube_client)}/neuromation.io/v1/userbuckets"


def generate_user_buckets_url(
    kube_client: KubeClient, namespace: str, name: str | None = None
) -> str:
    url = f"{neuromation_url(kube_client)}/namespaces/{namespace}/userbuckets"
    if name:
        url = f"{url}/{name}"
    return url


def persistent_bucket_credentials_url(kube_client: KubeClient) -> str:
    return f"{neuromation_url(kube_client)}/persistentbucketcredentials"


def generate_secrets_url(
    kube_client: KubeClient,
    namespace: str,
    name: str | None = None,
) -> str:
    url = f"{kube_client._base_url}/api/v1/namespaces/{namespace}/secrets"
    if name:
        url = f"{url}/{name}"
    return url


def generate_persistent_bucket_credential_url(
    kube_client: KubeClient,
    namespace: str | None,
    name: str | None = None,
) -> str:
    if not namespace:
        url = persistent_bucket_credentials_url(kube_client)
    else:
        url = (
            f"{neuromation_url(kube_client)}/namespaces/{namespace}"
            f"/persistentbucketcredentials"
        )
    if name:
        url = f"{url}/{name}"
    return url


async def _ensure_credentials_namespaces_are_known(
    kube_client: KubeClient,
) -> dict[str, str]:
    """
    A sanity-check which should be called before the migration.
    Credentials don't explicitly define a project/org pair,
    therefore, we don't know to which namespace they belong to.
    But we can understand the target namespace based on a credential bucket IDs.
    Here we check that a credential has a one and only one possible namespace in which
    it can be later created.
    """
    bucket_id_to_namespace = {}

    url = user_buckets_url(kube_client)
    response = await kube_client.get(url)
    for item in response["items"]:
        labels = item["metadata"]["labels"]

        project_name = labels.get(PROJECT_LABEL) or labels[BUCKETS_OWNER_LABEL]
        org_name = labels.get(ORG_NAME_LABEL)
        if not org_name or org_name.upper() == NO_ORG:
            org_name = normalize_name(NO_ORG)

        bucket_id = labels[BUCKETS_ID_LABEL]

        org_name = normalize_name(org_name)
        project_name = normalize_name(project_name)

        namespace_name = generate_namespace_name(org_name, project_name)
        bucket_id_to_namespace[bucket_id] = namespace_name

    url = persistent_bucket_credentials_url(kube_client)
    response = await kube_client.get(url)
    for item in response["items"]:
        namespaces = set()
        for bucket_id in item["spec"]["bucket_ids"]:
            namespace = bucket_id_to_namespace.get(bucket_id)
            if not namespace:
                raise RuntimeError(f"Bucket ID {bucket_id} is unknown")
            namespaces.add(namespace)

        if len(namespaces) > 1:
            raise RuntimeError(f"Credentials are related to multiple namespaces")

    return bucket_id_to_namespace


async def delete_old_buckets(
    kube_client: KubeClient,
    dry_run: bool = True,
) -> None:
    """
    Delete buckets/credentials in a default namespace
    """
    url = generate_user_buckets_url(kube_client, namespace=DEFAULT_NAMESPACE)
    response = await kube_client.get(url)
    for item in response["items"]:
        deletion_url = generate_user_buckets_url(
            kube_client,
            namespace=DEFAULT_NAMESPACE,
            name=item["metadata"]["name"],
        )
        if dry_run:
            logger.info(f"dry_run: DELETE {deletion_url}")
        else:
            await kube_client.delete(deletion_url)

    url = generate_persistent_bucket_credential_url(
        kube_client, namespace=DEFAULT_NAMESPACE
    )
    response = await kube_client.get(url)
    for item in response["items"]:
        deletion_url = generate_persistent_bucket_credential_url(
            kube_client,
            namespace=DEFAULT_NAMESPACE,
            name=item["metadata"]["name"],
        )
        if dry_run:
            logger.info(f"dry_run: DELETE {deletion_url}")
        else:
            await kube_client.delete(deletion_url)


async def delete_old_secrets(
    kube_client: KubeClient,
    dry_run: bool = True,
) -> None:
    """
    Delete secrets in a default namespace
    """
    url = generate_secrets_url(kube_client, namespace=DEFAULT_NAMESPACE)
    response = await kube_client.get(url)
    for item in response["items"]:
        deletion_url = generate_secrets_url(
            kube_client, DEFAULT_NAMESPACE, item["metadata"]["name"]
        )
        if dry_run:
            logger.info(f"dry_run: DELETE {deletion_url}")
        else:
            await kube_client.delete(deletion_url)


def main() -> None:
    init_logging()

    parser = ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", default=False)
    parser.add_argument("--delete-old", action="store_true", default=False)

    subparsers = parser.add_subparsers(dest="kube")
    kube_parser = subparsers.add_parser("kube", help="Kubernetes arguments")

    kube_parser.add_argument("--endpoint-url", type=str, required=True)
    kube_parser.add_argument("--auth-type", type=str, required=True, default="token")
    kube_parser.add_argument("--ca-path", type=str, required=True)
    kube_parser.add_argument("--token-path", type=str, required=True)
    kube_parser.add_argument(
        "--targets", type=str, required=False, default="secrets,buckets"
    )

    args = parser.parse_args()

    asyncio.run(
        migrate(
            args,
            targets=args.targets.split(","),
            dry_run=args.dry_run,
            delete_old=args.delete_old,
        )
    )


if __name__ == "__main__":
    main()
