{{/*
brix-common.resourceQuota — lab-sane hard caps for a profile namespace.
*/}}
{{- define "brix-common.resourceQuota" -}}
apiVersion: v1
kind: ResourceQuota
metadata:
  name: {{ include "brix-common.fullname" . }}-quota
  labels:
    {{- include "brix-common.labels" . | nindent 4 }}
spec:
  hard:
    requests.cpu: "8"
    requests.memory: 16Gi
    limits.cpu: "16"
    limits.memory: 32Gi
    pods: "50"
{{- end -}}
