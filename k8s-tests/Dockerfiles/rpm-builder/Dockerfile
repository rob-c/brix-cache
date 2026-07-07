# RPM Builder - builds the BriX RPM set in a selectable EL9 target image.
# AlmaLinux 9 remains the default.  The centos9-stream target enables the
# CentOS Storage SIG Ceph repo so brix-tools is built against current SIG Ceph.
ARG BRIX_BASE_IMAGE=almalinux:9
ARG BRIX_RUNTIME_IMAGE=almalinux:9-minimal
FROM ${BRIX_BASE_IMAGE} AS builder

SHELL ["/bin/bash", "-o", "pipefail", "-c"]

ARG BRIX_OS_TARGET=alma9
ARG BRIX_ENABLE_CEPH_SIG=0
ARG BRIX_CEPH_SIG_RELEASE=tentacle
COPY k8s-tests/lib/el-target.sh /tmp/el-target.sh

RUN bash /tmp/el-target.sh && \
    dnf install -y --allowerasing \
        gcc make rpm-build rpmdevtools redhat-rpm-config \
        gcc-c++ pkgconfig nginx-mod-devel openssl-devel pcre2-devel zlib-devel \
        libxml2-devel jansson-devel libcurl-devel krb5-devel libcom_err-devel \
        libxcrypt-devel fuse3-devel sqlite-devel \
        librados-devel libradospp-devel libradosstriper-devel libcephfs-devel \
    && dnf clean all

ARG VERSION=0.1.0
WORKDIR /build/src

# Copy the entire repository - spec file and source tree are both needed.
COPY . .

RUN set -euo pipefail && \
    rpmdev-setuptree && \
    source_name="nginx-xrootd-${VERSION}" && \
    tar \
        --exclude-vcs \
        --exclude='./.rpmbuild' \
        --exclude='./.tmp' \
        --exclude='./.venv*' \
        --exclude='./__pycache__' \
        --exclude='./*.pyc' \
        --exclude='./davs:*' \
        --exclude='./tests/davs:*' \
        --transform "s,^\.,${source_name}," \
        -czf ~/rpmbuild/SOURCES/"${source_name}.tar.gz" \
        -C /build/src . && \
    rpmbuild -ba \
        --define "version_override ${VERSION}" \
        /build/src/packaging/rpm/nginx-mod-brix-cache.spec

RUN mkdir -p /artifacts && \
    find ~/rpmbuild/RPMS ~/rpmbuild/SRPMS -name '*.rpm' -exec cp {} /artifacts/ \; && \
    rpm -qpl /artifacts/brix-tools-*.rpm > /tmp/brix-tools-files && \
    for p in \
        /usr/bin/xrdceph_striper_migrate \
        /usr/bin/xrdceph_cephfs_to_striper \
        /usr/bin/xrdrados_rescue \
        /usr/bin/xrdcephfs_rescue \
        /usr/bin/xrdceph_migrate \
        /usr/bin/xrdceph_striper_migrate.py \
        /usr/bin/xrdceph_cephfs_to_striper.py \
        /usr/libexec/brix/xrdceph_striper_migrate.py \
        /usr/libexec/brix/xrdceph_cephfs_to_striper.py \
        /usr/libexec/brix/pymigrate/__init__.py \
        /usr/libexec/brix/pymigrate/common.py \
        /usr/libexec/brix/pymigrate/cephfs_meta.py \
        /usr/libexec/brix/pymigrate/radosbridge.py \
        /usr/libexec/brix/pymigrate/shim/rados_manifest_shim.cpp \
        /usr/share/bash-completion/completions/xrdceph_striper_migrate \
        /usr/share/bash-completion/completions/xrdceph_cephfs_to_striper \
        /usr/share/bash-completion/completions/xrdrados_rescue \
        /usr/share/bash-completion/completions/xrdcephfs_rescue \
        /usr/share/bash-completion/completions/xrdceph_migrate; do \
        grep -qx "$p" /tmp/brix-tools-files; \
    done && \
    for m in \
        xrdceph_cephfs_to_striper \
        xrdceph_migrate \
        xrdceph_striper_migrate \
        xrdcephfs_rescue \
        xrdrados_rescue; do \
        grep -Eq "^/usr/share/man/man1/${m}[.]1([.].*)?$" /tmp/brix-tools-files; \
    done

FROM ${BRIX_RUNTIME_IMAGE} AS final

COPY --from=builder /artifacts /artifacts

CMD ["find", "/artifacts", "-name", "*.rpm"]
