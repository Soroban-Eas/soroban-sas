{{- define "sas.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{- define "sas.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- else -}}
{{- printf "%s-%s" .Release.Name .Chart.Name | trunc 63 | trimSuffix "-" }}
{{- end -}}
{{- end -}}

{{- define "sas.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | trunc 63 | trimSuffix "-" }}
{{- end -}}

{{- define "sas.labels" -}}
helm.sh/chart: {{ include "sas.chart" . }}
helm.sh/release: {{ .Release.Name }}
helm.sh/managed: "true"
{{- end -}}

{{- define "sas.selectorLabels" -}}
{{ include "sas.labels" . }}
app.kubernetes.io/name: {{ include "sas.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "sas.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "sas.fullname" .) .Values.serviceAccount.name }}
{{- else -}}
{{- default (default "default" .Values.serviceAccount.name) .Values.serviceAccount.name }}
{{- end -}}
{{- end -}}

{{- define "sas.image" -}}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end -}}
