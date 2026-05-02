FROM ubuntu:latest

RUN apt-get update \
    && apt-get install --no-install-recommends -y \
        ca-certificates \
        curl \
        gnupg \
        python3 \
        python3-pip \
    && curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg \
    | gpg --dearmor -o /usr/share/keyrings/cloud.google.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" \
    > /etc/apt/sources.list.d/google-cloud-sdk.list \
    && apt-get update \
    && apt-get install --no-install-recommends -y google-cloud-cli \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/gcpwn

COPY . .
ARG GCPWN_EXTRAS=""
RUN if [ -n "$GCPWN_EXTRAS" ]; then \
      python3 -m pip install ".[${GCPWN_EXTRAS}]"; \
    else \
      python3 -m pip install .; \
    fi

ENTRYPOINT ["gcpwn"]
