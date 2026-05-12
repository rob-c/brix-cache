{{- define "xrootd.fullname" -}}
{{- if .Release.Name }}{{ .Release.Name }}-{{ end }}xrootd-server
{{- end -}}

{{- define "xrootd.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "xrootd.labels" -}}
app.kubernetes.io/name: {{ include "xrootd.fullname" . }}
helm.sh/chart: {{ include "xrootd.chart" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- if .Values.commonLabels }}
{{ toYaml .Values.commonLabels }}
{{- end }}
{{- end -}}

{{- define "xrootd.selectorLabels" -}}
app.kubernetes.io/name: {{ include "xrootd.fullname" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
