# RPM Builder — builds nginx-xrootd module as an RPM inside AlmaLinux 9
# Used by CI pipeline to produce reproducible RPMs before baking into server images.
FROM almalinux:9 AS builder

RUN dnf install -y epel-release && \
    dnf install -y \
        gcc make rpm-build rpmdevtools redhat-rpm-config \
        nginx-mod-devel openssl-devel pcre2-devel zlib-devel \
    && dnf clean all

ARG VERSION=0.1.0
WORKDIR /build/src

# Copy the entire repository — spec file and source tree are both needed.
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
        /build/src/packaging/rpm/nginx-mod-xrootd.spec

RUN mkdir -p /artifacts && \
    find ~/rpmbuild/RPMS ~/rpmbuild/SRPMS -name '*.rpm' -exec cp {} /artifacts/ \;

FROM almalinux:9-minimal AS final

COPY --from=builder /artifacts /artifacts

CMD ["find", "/artifacts", "-name", "*.rpm"]
