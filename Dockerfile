FROM python:3.13.1-slim-bookworm AS installer

ENV PATH=/root/.local/bin:$PATH

# Copy to tmp folder to don't pollute home dir
RUN mkdir -p /tmp/dist
COPY dist /tmp/dist

RUN ls /tmp/dist
RUN pip install --user --find-links /tmp/dist platform-buckets-api

RUN apt-get -q update && apt-get -q install -y wget
RUN wget -O mc https://dl.min.io/client/mc/release/linux-amd64/archive/mc.RELEASE.2023-02-28T00-12-59Z
RUN chmod +x mc

FROM python:3.13.1-slim-bookworm as service

LABEL org.opencontainers.image.source = "https://github.com/neuro-inc/platform-buckets-api"

WORKDIR /app

COPY --from=installer /root/.local/ /root/.local/
COPY --from=installer /mc /usr/bin/mc

ENV PATH=/root/.local/bin:$PATH

ENV NP_BUCKETS_API_PORT=8080
EXPOSE $NP_BUCKETS_API_PORT

CMD platform-buckets-api
