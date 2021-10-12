from setuptools import find_packages, setup


setup_requires = ("setuptools_scm",)


install_requires = (
    "aiohttp==3.7.4.post0",
    "neuro_auth_client==21.9.13.1",
    "neuro-logging==21.9",
    "aiohttp-cors==0.7.0",
    "aiozipkin==1.1.0",
    "sentry-sdk==1.4.3",
    "marshmallow==3.13.0",
    "aiohttp-apispec==2.2.1",
    "aiobotocore==1.4.1",
    "bmc==0.0.3",
    "azure-storage-blob==12.8.1",
    "google-cloud-storage==1.42.3",
    "google-cloud-iam==2.3.2",
    "google-api-python-client==2.25.0",
)

setup(
    name="platform-buckets-api",
    use_scm_version={
        "git_describe_command": "git describe --dirty --tags --long --match v*.*.*",
    },
    url="https://github.com/neuro-inc/platform-buckets-api",
    packages=find_packages(),
    install_requires=install_requires,
    setup_requires=setup_requires,
    python_requires=">=3.7",
    entry_points={
        "console_scripts": ["platform-buckets-api=platform_buckets_api.api:main"]
    },
    zip_safe=False,
)
