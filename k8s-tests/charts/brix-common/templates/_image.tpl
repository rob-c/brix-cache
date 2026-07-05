{{/*
brix-common.image — "<repository>:<tag>" for the calling chart's .Values.image.
*/}}
{{- define "brix-common.image" -}}
{{- printf "%s:%s" .Values.image.repository .Values.image.tag -}}
{{- end -}}

{{/*
brix-common.imagePullPolicy — pull policy, defaulting to Never (images are
loaded straight into the node by `minikube image build`, never pulled).
*/}}
{{- define "brix-common.imagePullPolicy" -}}
{{- .Values.image.pullPolicy | default "Never" -}}
{{- end -}}
