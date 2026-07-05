# authority — provisioning tools + static HTTP distributor for the auth plane.
FROM almalinux:9
RUN dnf install -y epel-release \
    && dnf install -y python3 python3-pip openssl nginx \
                      krb5-server krb5-workstation \
    && (dnf install -y voms-clients || true) \
    && dnf clean all
RUN python3 -m pip install --no-cache-dir cryptography pyjwt
RUN curl -fsSLo /usr/local/bin/kubectl \
        "https://dl.k8s.io/release/v1.31.4/bin/linux/amd64/kubectl" \
    && chmod +x /usr/local/bin/kubectl
WORKDIR /opt/brix
COPY tests/ /opt/brix/tests/
COPY utils/ /opt/brix/utils/
COPY k8s-tests/images/authority/serve.conf /etc/nginx/nginx.conf
RUN mkdir -p /srv/dist/crl /srv/dist/certs /srv/dist/voms
EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
