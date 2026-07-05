# smoke — minimal, registry-free image proving the build/load/deploy path.
# Same base family as the real server image so it is not a foreign throwaway.
FROM almalinux:9-minimal
RUN microdnf install -y nginx && microdnf clean all
COPY nginx-smoke.conf /etc/nginx/nginx.conf
EXPOSE 8080
CMD ["nginx", "-g", "daemon off;"]
