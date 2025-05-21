from __future__ import annotations

import argparse
import asyncio
import logging
from argparse import ArgumentParser
from pathlib import Path

from apolo_kube_client.apolo import (
    NO_ORG,
    create_namespace,
    generate_namespace_name,
    normalize_name,
)
from apolo_kube_client.client import KubeClient, kube_client_from_config
from apolo_kube_client.config import KubeClientAuthType, KubeConfig
from neuro_logging import (
    init_logging,
)

BUCKETS_ID_LABEL = "platform.neuromation.io/id"
BUCKETS_OWNER_LABEL = "platform.neuromation.io/owner"
BUCKETS_CREDENTIALS_NAME_LABEL = "platform.neuromation.io/credentials_name"
BUCKETS_BUCKET_NAME_LABEL = "platform.neuromation.io/bucket_name"

ORG_NAME_LABEL = "platform.neuromation.io/org_name"
PROJECT_LABEL = "platform.neuromation.io/project"


logger = logging.getLogger(__name__)

DEFAULT_NAMESPACE = "platform-jobs"


async def migrate(
    args: argparse.Namespace,
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
        await migrate_buckets(kube_client, dry_run=dry_run, delete_old=delete_old)
        await migrate_secrets(kube_client, dry_run=dry_run, delete_old=delete_old)


async def migrate_buckets(
    kube_client: KubeClient,
    dry_run: bool = True,
    delete_old: bool = False,
) -> None:
    bucket_id_to_namespace = await _ensure_credentials_namespaces_are_known(kube_client)

    url = user_buckets_url(kube_client)
    response = await kube_client.get(url)
    for item in response["items"]:
        metadata = item["metadata"]
        spec = item["spec"]
        labels = metadata["labels"]

        project_name = labels.get(PROJECT_LABEL) or labels[BUCKETS_OWNER_LABEL]
        org_name = labels.get(ORG_NAME_LABEL)
        if not org_name or org_name.upper() == NO_ORG:
            org_name = normalize_name(NO_ORG)

        labels[ORG_NAME_LABEL] = org_name
        labels[PROJECT_LABEL] = project_name

        bucket_id = labels[BUCKETS_ID_LABEL]

        if dry_run:
            namespace_name = bucket_id_to_namespace[bucket_id]
            logger.info(f"dry_run: will create namespace {namespace_name}")
        else:
            created_namespace = await create_namespace(
                kube_client, org_name, project_name
            )
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

    url = persistent_bucket_credentials_url(kube_client)
    response = await kube_client.get(url)
    for item in response["items"]:
        name = item["metadata"]["name"]

        namespace = None

        for bucket_id in item["spec"]["bucket_ids"]:
            namespace = bucket_id_to_namespace[bucket_id]
            if namespace:
                break

        if not namespace:
            raise RuntimeError()

        payload = {
            "kind": "PersistentBucketCredential",
            "apiVersion": "neuromation.io/v1",
            "metadata": {"name": name, "labels": item["metadata"]["labels"]},
            "spec": item["spec"],
        }
        credentials_creation_url = generate_persistent_bucket_credential_url(
            kube_client, namespace
        )
        if dry_run:
            logger.info(f"dry_run: POST {credentials_creation_url}. {payload}")
        else:
            await kube_client.post(credentials_creation_url, json=payload)

    if delete_old:
        await delete_old_buckets(kube_client, dry_run=dry_run)


async def migrate_secrets(
    kube_client: KubeClient,
    dry_run: bool = True,
    delete_old: bool = False,
) -> None:
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
    Delete old resources in a default namespace
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


def main() -> None:
    init_logging()

    parser = ArgumentParser()
    parser.add_argument("--dry-run", action="store_true", default=True)
    parser.add_argument("--delete-old", action="store_true", default=False)

    subparsers = parser.add_subparsers(dest="kube")
    kube_parser = subparsers.add_parser("kube", help="Kubernetes arguments")

    kube_parser.add_argument("--endpoint-url", type=str, required=True)
    kube_parser.add_argument("--auth-type", type=str, required=True, default="token")
    kube_parser.add_argument("--ca-path", type=str, required=True)
    kube_parser.add_argument("--token-path", type=str, required=True)

    args = parser.parse_args()

    asyncio.run(migrate(args, dry_run=args.dry_run, delete_old=args.delete_old))


if __name__ == "__main__":
    main()
