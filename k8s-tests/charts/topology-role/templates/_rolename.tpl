{{- define "topology-role.fullname" -}}
{{- printf "%s-%s" .Release.Name .Values.role.name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
