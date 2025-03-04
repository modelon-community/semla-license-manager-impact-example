# syntax = docker/dockerfile:1
FROM rockylinux/rockylinux:8.10-minimal as base

USER root

RUN \
    # Installing epel-release also installs dnf-3
    microdnf -y install epel-release \
    # Enable EPEL ('powertools' will need to be updated to 'crb' for Rocky Linux 9, double-check this, see note in LIC-785)
    && dnf-3 config-manager --set-enabled powertools \
    && dnf-3 install -y epel-release \
    # Install packages
    && dnf-3 install -y \
    bash-completion \
    binutils \
    redhat-lsb \
    bc \
    zlib-devel \
    boost-devel \
    vim \
    cmake \
    patch \
    pkgconfig \
    subversion \
    git \
    curl \
    gcc \
    gcc-c++ \
    gdb \
    dos2unix \
    check-devel \
    libstdc++-static \
    # https://github.com/openssl/openssl/blob/openssl-3.0.8/NOTES-PERL.md says how to install perl for different RPM/DEB-based linux distributions.
    # It says that you also need the 'perl-core' package on RPM-based systems.
    perl \
    perl-core \
    sudo \
    tar \
    tree \
    # 'pax-utils' provides 'lddtree' which is like 'ldd' but it gives a tree view.
    # 'lddtree' can be used for visualizing the shared libraries that a shared library/executable depends on.
    pax-utils \
    zip \
    unzip \
    wget \
    jq \
    which \
    make \
    && dnf-3 clean all


########################################
# SEMLA License Manager Impact Example specific code below
########################################
USER root


# Do this after package installations since we do not necessarily have 'useradd/groupadd' installed
RUN useradd -ms /bin/bash baseuser && groupadd docker && usermod -aG docker baseuser

########################################
# END of SEMLA License Manager Impact Example specific code
########################################

# assert that non-root user 'baseuser' has uid 1000 (same uid as host user, necessary for keeping permissions of mounted-in files)
RUN test $(id -u baseuser) = 1000

FROM base as devcontainer

# enable sudo for existing user from base image
USER root
RUN : \
    && echo "baseuser     ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# set default user when running containers from this image
USER baseuser

FROM base as production

# set default user when running containers from this image
USER baseuser
