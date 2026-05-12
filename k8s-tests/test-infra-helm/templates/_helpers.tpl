{{- define "infra.fullname" -}}
{{- if .Release.Name }}{{ .Release.Name }}-{{ end }}k8s-tests-infra
{{- end -}}
