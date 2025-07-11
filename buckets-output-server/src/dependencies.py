import tempfile
from collections.abc import AsyncGenerator
from pathlib import Path
from typing import Annotated

import apolo_sdk
from fastapi import Depends, HTTPException
from src.auth.dependencies import Token
from starlette.requests import Request
from yarl import URL


async def dep_get_apolo_client(
    token: Token,
    request: Request,
    cluster_name: str,
    org_name: str,
    project_name: str,
) -> AsyncGenerator[apolo_sdk.Client]:
    with tempfile.TemporaryDirectory() as tmp_dir:
        config_path = Path(tmp_dir)
        api_url = URL(request.app.config.api_url) / "api/v1"
        try:
            await apolo_sdk.login_with_token(
                token,
                url=api_url,
                path=config_path,
            )
            async with apolo_sdk.get(path=config_path) as apolo_client:
                await apolo_client.config.switch_cluster(cluster_name)
                await apolo_client.config.switch_org(org_name)
                await apolo_client.config.switch_project(project_name)
                yield apolo_client
        except apolo_sdk.AuthError as err:
            raise HTTPException(status_code=401, detail=str(err)) from err


DepApoloClient = Annotated[apolo_sdk.Client, Depends(dep_get_apolo_client)]
