from dataclasses import dataclass


@dataclass(frozen=True)
class Config:
    cluster_name: str
    api_url: str
    env: str = "dev"
