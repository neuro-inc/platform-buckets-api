ARG PY_VERSION=3.14.10

FROM python:${PY_VERSION}-slim-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --no-cache-dir --upgrade "pip @ https://files.pythonhosted.org/packages/3f/06/3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/pip-26.2.2-py3-none-any.whl#sha256=fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70" \
    && python -m pip install --no-cache-dir --upgrade "certifi==2026.10.23" \
    && python -c "import pip, certifi; assert pip.__version__ == '26.2.2'; assert certifi.__version__ == '2026.10.23'"

ENV PATH=/root/.local/bin:$PATH

WORKDIR /tmp
COPY requirements.txt /tmp/

RUN pip install --user --no-cache-dir -r requirements.txt

COPY dist /tmp/dist/
RUN pip install --user --no-cache-dir --find-links /tmp/dist platform-buckets-api \
    && rm -rf /tmp/dist

RUN apt-get -q update && apt-get -q install -y wget \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
ARG MC_RELEASE=RELEASE.2023-02-28T00-12-59Z
ARG MC_SHA256=d07cee8ecb085f3e1d932b054bed6998e89b640821aaae480a7f09f3b56d6d48
RUN wget -O mc "https://github.com/minio/mc/releases/download/${MC_RELEASE}/mc.linux-amd64.${MC_RELEASE}" \
    && echo "${MC_SHA256}  mc" | sha256sum -c - \
    && chmod +x mc

FROM python:${PY_VERSION}-slim-bookworm AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --no-cache-dir --upgrade "pip @ https://files.pythonhosted.org/packages/3f/06/3e4420302363fbb71be3c7f35ce042f54bfca330e3e66b3a2e3c4cca579f/pip-26.2.2-py3-none-any.whl#sha256=fd7f4dfa8190e014013b9f08f3e973f4e4c26ffd179a204895533a7254813a70" \
    && python -m pip install --no-cache-dir --upgrade "certifi==2026.10.23" \
    && python -c "import pip, certifi; assert pip.__version__ == '26.2.2'; assert certifi.__version__ == '2026.10.23'"
LABEL org.opencontainers.image.source="https://github.com/neuro-inc/platform-buckets-api"
# Name of your service (folder under /home)
ARG SERVICE_NAME="platform-buckets-api"
ARG SERVICE_UID=1001
ARG SERVICE_GID=1001

RUN addgroup --gid $SERVICE_GID $SERVICE_NAME && \
    adduser --uid $SERVICE_UID --gid $SERVICE_GID \
    --home /home/$SERVICE_NAME --shell /bin/false \
    --disabled-password --gecos "" $SERVICE_NAME


# Tell Python where the "user" site is
ENV HOME=/home/${SERVICE_NAME}
ENV PYTHONUSERBASE=/home/${SERVICE_NAME}/.local
ENV PATH=/home/${SERVICE_NAME}/.local/bin:$PATH

# Copy everything from the builder’s user‐site into your service’s user‐site
COPY --from=builder --chown=$SERVICE_NAME:$SERVICE_GID /root/.local /home/$SERVICE_NAME/.local
COPY --from=builder /tmp/mc /usr/bin/mc

WORKDIR /app

ENV NP_BUCKETS_API_PORT=8080
EXPOSE $NP_BUCKETS_API_PORT

CMD ["platform-buckets-api"]
