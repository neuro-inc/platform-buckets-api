pytest_plugins = [
    "tests.integration.docker",
    "tests.integration.auth",
    "tests.integration.moto_server",
    "tests.integration.minio",
    "tests.integration.kube",
]
