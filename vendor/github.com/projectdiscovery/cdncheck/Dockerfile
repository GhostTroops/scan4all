FROM alpine:latest

LABEL org.opencontainers.image.authors="ProjectDiscovery"
LABEL org.opencontainers.image.description="cdncheck is a tool for identifying the technology associated with dns / ip network addresses."
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.title="cdncheck"
LABEL org.opencontainers.image.url="https://github.com/projectdiscovery/cdncheck"

RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/cdncheck /usr/local/bin/

ENTRYPOINT ["cdncheck"]
