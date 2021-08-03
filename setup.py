from setuptools import find_packages, setup


setup_requires = ("setuptools_scm",)


install_requires = (
    "aiohttp==3.7.4.post0",
    "neuro_auth_client==21.7.27",
    "neuro-logging==21.8.2.2",
    "aiohttp-cors==0.7.0",
    "aiozipkin==1.1.0",
    "sentry-sdk==1.3.0",
    "marshmallow==3.13.0",
    "aiohttp-apispec==2.2.1",
    "aiobotocore==1.3.3",
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
