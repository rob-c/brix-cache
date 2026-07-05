{{/*
brix-common.fetchSidecar — a container that refreshes url->dest every interval s.
Args(dict): name, url, dest, interval, volumeName.
*/}}
{{- define "brix-common.fetchSidecar" -}}
name: {{ .name }}
image: brix-authority:dev
imagePullPolicy: Never
command: ["/bin/sh","-c"]
args:
  - |
    while true; do
      curl -fsS {{ .url }} -o {{ .dest }}.tmp && mv {{ .dest }}.tmp {{ .dest }} || echo "fetch {{ .name }} failed" >&2
      sleep {{ .interval }}
    done
volumeMounts:
  - name: {{ .volumeName }}
    mountPath: {{ dir .dest }}
{{- end -}}
