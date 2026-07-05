{{/*
auth-authority.deploymentService — one Deployment + one Service for an authority.
Args (dict): root(.), name, port, image(dict repo/tag/pullPolicy), command(list),
             mounts(list), volumes(list).
*/}}
{{- define "auth-authority.deploymentService" -}}
{{- $root := .root -}}
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {{ $root.Release.Name }}-{{ .name }}
  labels:
    {{- include "brix-common.labels" $root | nindent 4 }}
    app.kubernetes.io/component: {{ .name }}
spec:
  replicas: 1
  selector:
    matchLabels:
      {{- include "brix-common.selectorLabels" $root | nindent 6 }}
      app.kubernetes.io/component: {{ .name }}
  template:
    metadata:
      labels:
        {{- include "brix-common.labels" $root | nindent 8 }}
        app.kubernetes.io/component: {{ .name }}
    spec:
      containers:
        - name: {{ .name }}
          image: "{{ .image.repository }}:{{ .image.tag }}"
          imagePullPolicy: {{ .image.pullPolicy | default "Never" }}
          {{- with .command }}
          command: {{ toYaml . | nindent 12 }}
          {{- end }}
          ports:
            - containerPort: {{ .port }}
          {{- with .mounts }}
          volumeMounts: {{ toYaml . | nindent 12 }}
          {{- end }}
      {{- with .volumes }}
      volumes: {{ toYaml . | nindent 8 }}
      {{- end }}
---
apiVersion: v1
kind: Service
metadata:
  name: {{ $root.Release.Name }}-{{ .name }}
  labels:
    {{- include "brix-common.labels" $root | nindent 4 }}
    app.kubernetes.io/component: {{ .name }}
spec:
  type: ClusterIP
  selector:
    {{- include "brix-common.selectorLabels" $root | nindent 4 }}
    app.kubernetes.io/component: {{ .name }}
  ports:
    - name: svc
      port: {{ .port }}
      targetPort: {{ .port }}
{{- end -}}
