{{/*
brix-common.networkPolicy — default-deny ingress, allow only same-lab pods.
*/}}
{{- define "brix-common.networkPolicy" -}}
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: {{ include "brix-common.fullname" . }}-allow-lab
  labels:
    {{- include "brix-common.labels" . | nindent 4 }}
spec:
  podSelector:
    matchLabels:
      {{- include "brix-common.selectorLabels" . | nindent 6 }}
  policyTypes:
    - Ingress
  ingress:
    - from:
        - podSelector:
            matchLabels:
              app.kubernetes.io/part-of: brix-test-lab
{{- end -}}
