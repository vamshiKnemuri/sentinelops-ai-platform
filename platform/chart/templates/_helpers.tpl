{{- define "sentinelops.name" -}}
sentinelops
{{- end }}

{{- define "sentinelops.labels" -}}
app.kubernetes.io/name: {{ include "sentinelops.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}
