{{/*
brix-common.labels — full standard label set. Caller nindents the result.
*/}}
{{- define "brix-common.labels" -}}
helm.sh/chart: {{ include "brix-common.chart" . }}
{{ include "brix-common.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | default .Chart.Version | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: brix-test-lab
{{- end -}}

{{/*
brix-common.selectorLabels — the stable identity used by selectors.
*/}}
{{- define "brix-common.selectorLabels" -}}
app.kubernetes.io/name: {{ include "brix-common.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
