ARG PY_VERSION=3.13.3

FROM python:${PY_VERSION}-slim-bookworm AS builder

ENV PATH=/root/.local/bin:$PATH

WORKDIR /tmp
COPY requirements.txt /tmp/

RUN pip install --user --no-cache-dir -r requirements.txt

COPY dist /tmp/dist/
RUN pip install --user --no-cache-dir --find-links /tmp/dist platform-buckets-api \
    && rm -rf /tmp/dist

RUN apt-get -q update && apt-get -q install -y wget \
    && apt-get clean && rm -rf /var/lib/apt/lists/*
RUN wget -O mc https://dl.min.io/client/mc/release/linux-amd64/archive/mc.RELEASE.2023-02-28T00-12-59Z
RUN chmod +x mc

FROM python:${PY_VERSION}-slim-bookworm AS runtime
LABEL org.opencontainers.image.source="https://github.com/neuro-inc/platform-buckets-api"

WORKDIR /app

# Name of your service (folder under /home)
ARG SERVICE_NAME="platform-buckets-api"

# Tell Python where the "user" site is
ENV HOME=/home/${SERVICE_NAME}
ENV PYTHONUSERBASE=/home/${SERVICE_NAME}/.local
ENV PATH=/home/${SERVICE_NAME}/.local/bin:$PATH

# Copy everything from the builder’s user‐site into your service’s user‐site
COPY --from=builder /root/.local /home/${SERVICE_NAME}/.local
COPY --from=builder /tmp/mc /usr/bin/mc

ENV NP_BUCKETS_API_PORT=8080
EXPOSE $NP_BUCKETS_API_PORT

CMD ["platform-buckets-api"]
