
FROM ubuntu:22.04

# 安装第三方依赖
RUN sed -i 's|archive.ubuntu.com|mirrors.cloud.tencent.com|g; s|security.ubuntu.com|mirrors.cloud.tencent.com|g' /etc/apt/sources.list \
    && apt-get update \
    && apt-get install -y build-essential python2 libtool-bin wget bison flex libglib2.0-dev libcapstone-dev libpixman-1-dev \
    && ln -s /usr/bin/python2 /usr/bin/python \
    && rm -rf /var/lib/apt/lists/*

COPY . /workspace

# 编译 AFL 以及 qemu_mode
WORKDIR /workspace
RUN make clean all \
    && cd /workspace/qemu_mode \
    && sh build_qemu_support.sh \
    && cd /workspace \
    && make install \
    && rm -rf /workspace/*

# 创建一个最小的实例
RUN cd /workspace \
    && mkdir input/ output/ \
    && echo "import os\nimport math" > input/seed_001.txt \
    && echo "# !/bin/env bash\n\nafl-fuzz-refactor -i input -o output -Q -- python2 @@\n" > run.sh \
    && chmod +x run.sh
