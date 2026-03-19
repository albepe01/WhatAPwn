FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    clang-14 \
    clang++-14 \
    git \
    build-essential \
    python3 \
    python3-pip \
    python3-venv \
    pkg-config \
    libglib2.0-dev \
    libpixman-1-dev \
    ninja-build \
    && rm -rf /var/lib/apt/lists/*

# Symlink per compatibilità
RUN ln -s /usr/bin/python3 /usr/bin/python

WORKDIR /opt
RUN git clone --recursive https://github.com/andreafioraldi/qasan.git

WORKDIR /opt/qasan

# Compila QASAN con clang-14
RUN python3 build.py --arch x86_64 --cc=clang-14 --cxx=clang++-14

ENV QASAN_PATH=/opt/qasan
ENV PATH="$QASAN_PATH:${PATH}"

WORKDIR /workspace
CMD ["/bin/bash"]
