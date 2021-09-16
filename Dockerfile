FROM python:3.8.10-buster AS installer

# Separate step for requirements to speed up docker builds
COPY platform_buckets_api.egg-info/requires.txt requires.txt
RUN python -c 'from pkg_resources import Distribution, PathMetadata;\
dist = Distribution(metadata=PathMetadata(".", "."));\
print("\n".join(str(r) for r in dist.requires()));\
' > requirements.txt
RUN pip install --user -r requirements.txt

RUN apt-get -q update && apt-get -q install -y wget
RUN wget https://dl.min.io/client/mc/release/linux-amd64/mc
RUN chmod +x mc

ARG DIST_FILENAME

# Install service itself
COPY dist/${DIST_FILENAME} ${DIST_FILENAME}
RUN pip install --user $DIST_FILENAME

FROM python:3.8.10-buster as service

LABEL org.opencontainers.image.source = "https://github.com/neuro-inc/platform-buckets-api"

WORKDIR /app

COPY --from=installer /root/.local/ /root/.local/
COPY --from=installer /mc /usr/bin/mc

ENV PATH=/root/.local/bin:$PATH

ENV NP_BUCKETS_API_PORT=8080
EXPOSE $NP_BUCKETS_API_PORT

CMD platform-buckets-api
