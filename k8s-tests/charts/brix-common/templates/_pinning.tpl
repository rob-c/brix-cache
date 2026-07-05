{{/*
brix-common.nodePinning — hybrid one-role-per-node toggle.
  mode: off  -> emit nothing (scheduler places pods freely; portable).
  mode: role -> pod anti-affinity so no two lab pods share a node, giving
                one-container-per-VM when the cluster has >= role-count nodes.
Caller inserts the result under spec.template.spec.
*/}}
{{- define "brix-common.nodePinning" -}}
{{- $mode := "off" -}}
{{- if .Values.nodePinning -}}{{- $mode = (.Values.nodePinning.mode | default "off") -}}{{- end -}}
{{- if and .Values.role .Values.role.nodePinning -}}{{- $mode = (.Values.role.nodePinning.mode | default $mode) -}}{{- end -}}
{{- if eq $mode "role" -}}
affinity:
  podAntiAffinity:
    requiredDuringSchedulingIgnoredDuringExecution:
      - topologyKey: kubernetes.io/hostname
        labelSelector:
          matchLabels:
            app.kubernetes.io/part-of: brix-test-lab
{{- end -}}
{{- end -}}
