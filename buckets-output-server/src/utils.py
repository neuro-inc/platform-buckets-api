from typing import Any, TypedDict

import apolo_sdk
from apolo_app_types.protocols.common.buckets import (
    Bucket as BucketType,
    BucketProvider,
    CredentialsType,
    GCPBucketCredentials,
    MinioBucketCredentials,
    S3BucketCredentials,
)


class AwsS3Credentials(TypedDict):
    bucket_name: str
    endpoint_url: str
    region_name: str
    access_key_id: str
    secret_access_key: str


class MinioCredentials(AwsS3Credentials):
    pass


class GCPCredentials(TypedDict):
    bucket_name: str
    key_data: str


CredType = S3BucketCredentials | MinioBucketCredentials | GCPBucketCredentials


def bucket_credentials_map(
    buckets: list[apolo_sdk.Bucket],
    credentials: list[apolo_sdk.PersistentBucketCredentials],
) -> list[dict[str, Any]]:
    mapping: dict[str, list[apolo_sdk.PersistentBucketCredentials]] = {}
    for c in credentials:
        bucket_creds = c.credentials
        for bucket in bucket_creds:
            mapping.setdefault(bucket.bucket_id, [])
            mapping[bucket.bucket_id].append(c)
    return [
        {"bucket": bucket, "credentials": mapping.get(bucket.id, [])}
        for bucket in buckets
    ]


def parse_provider(provider: apolo_sdk.Bucket.Provider) -> BucketProvider:
    try:
        return BucketProvider(provider.value.upper())
    except ValueError as e:
        err = (
            f"Unknown provider: {provider.value}. "
            f"Supported providers are: {', '.join(p.value for p in BucketProvider)}"
        )
        raise ValueError(err) from e


def parse_creds(
    pers_credentials: list[apolo_sdk.PersistentBucketCredentials],
) -> list[CredType]:
    output: list[CredType] = []
    for credentials in pers_credentials:
        for c in credentials.credentials:
            provider = parse_provider(c.provider)
            match provider:
                case BucketProvider.AWS:
                    aws_creds: AwsS3Credentials = c.credentials  # type: ignore
                    output.append(
                        S3BucketCredentials(
                            type=(
                                CredentialsType.READ_ONLY
                                if credentials.read_only
                                else CredentialsType.READ_WRITE
                            ),
                            name=aws_creds["bucket_name"],
                            access_key_id=aws_creds["access_key_id"],
                            secret_access_key=aws_creds["secret_access_key"],
                            region_name=aws_creds["region_name"],
                            endpoint_url=aws_creds["endpoint_url"],
                        )
                    )
                case BucketProvider.MINIO:
                    minio_creds: MinioCredentials = c.credentials  # type: ignore
                    output.append(
                        MinioBucketCredentials(
                            type=(
                                CredentialsType.READ_ONLY
                                if credentials.read_only
                                else CredentialsType.READ_WRITE
                            ),
                            name=minio_creds["bucket_name"],
                            access_key_id=minio_creds["access_key_id"],
                            secret_access_key=minio_creds["secret_access_key"],
                            region_name=minio_creds["region_name"],
                            endpoint_url=minio_creds["endpoint_url"],
                        )
                    )
                case BucketProvider.GCP:
                    gcp_creds: GCPCredentials = c.credentials  # type: ignore
                    output.append(
                        GCPBucketCredentials(
                            type=(
                                CredentialsType.READ_ONLY
                                if credentials.read_only
                                else CredentialsType.READ_WRITE
                            ),
                            name=gcp_creds["bucket_name"],
                            key_data=gcp_creds["key_data"],
                        )
                    )
                case _:
                    err = f"Unsupported provider: {provider}"
                    raise ValueError(err)
    return output


def get_buckets_info(
    buckets: list[apolo_sdk.Bucket],
    credentials: list[apolo_sdk.PersistentBucketCredentials],
) -> list[BucketType]:
    bucket_credentials_mapping = bucket_credentials_map(buckets, credentials)
    output = []
    for bc in bucket_credentials_mapping:
        bucket_credentials: list[apolo_sdk.PersistentBucketCredentials] = bc[
            "credentials"
        ]
        bucket: apolo_sdk.Bucket = bc["bucket"]
        provider = parse_provider(bucket.provider)
        bucket_info = BucketType(
            id=bucket.id,
            owner=bucket.owner,
            bucket_provider=provider,
            credentials=parse_creds(bucket_credentials),
        )
        output.append(bucket_info)
    return output


async def get_buckets(client: apolo_sdk.Client) -> list[BucketType]:
    buckets = [b async for b in client.buckets.list()]
    credentials = [c async for c in client.buckets.persistent_credentials_list()]
    return get_buckets_info(buckets, credentials)


async def get_bucket(bucket_id: str) -> BucketType | None:
    async with apolo_sdk.get() as client:
        buckets = [await client.buckets.get(bucket_id_or_name=bucket_id)]
        credentials = [c async for c in client.buckets.persistent_credentials_list()]
    return get_buckets_info(buckets, credentials)[0] if buckets else None


def filter_bucket_name(query: str, items: list[CredType]) -> bool:
    if not query:
        return True
    query = query.lower()
    return any(query in str(getattr(item, "name", "")).lower() for item in items)


def filter_buckets(buckets: list[BucketType], query: str | None) -> list[BucketType]:
    fields = ["id", "owner"]
    if query:
        filtered_buckets = []
        for bucket in buckets:
            query = query.lower()
            if any(
                query in str(getattr(bucket, field)).lower() for field in fields
            ) or filter_bucket_name(query, bucket.credentials):
                filtered_buckets.append(bucket)
    else:
        filtered_buckets = buckets
    return filtered_buckets
