{{/*
brix-common.name — base name for all resources (the consuming chart's name).
*/}}
{{- define "brix-common.name" -}}
{{- .Chart.Name | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
brix-common.fullname — <release>-<name>, truncated to the 63-char k8s limit.
*/}}
{{- define "brix-common.fullname" -}}
{{- printf "%s-%s" .Release.Name (include "brix-common.name" .) | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
brix-common.chart — <chart>-<version>, sanitised for a label value.
*/}}
{{- define "brix-common.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}
