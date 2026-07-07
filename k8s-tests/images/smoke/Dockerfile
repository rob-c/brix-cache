# smoke — minimal, registry-free image proving the build/load/deploy path.
# Same base family as the real server image so it is not a foreign throwaway.
ARG BRIX_SMOKE_BASE_IMAGE=almalinux:9-minimal
FROM ${BRIX_SMOKE_BASE_IMAGE}
RUN if command -v microdnf >/dev/null 2>&1; then \
        microdnf install -y nginx && microdnf clean all; \
    else \
        dnf install -y nginx && dnf clean all; \
    fi
COPY nginx-smoke.conf /etc/nginx/nginx.conf
EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
