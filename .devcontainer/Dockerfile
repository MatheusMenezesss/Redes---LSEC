# syntax=docker/dockerfile:1
FROM mcr.microsoft.com/devcontainers/python:3.11

# Install network tooling and automation dependencies used in labs.
RUN apt-get update \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        tshark \
        ansible \
        iproute2 \
        iputils-ping \
        net-tools \
        tcpdump \
        traceroute \
        dnsutils \
        curl \
        make \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Python-based linters in the image for consistent local + CI behavior.
RUN pip install --no-cache-dir ruff yamllint
