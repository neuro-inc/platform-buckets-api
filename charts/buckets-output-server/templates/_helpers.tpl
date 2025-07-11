{{/*
Expand the name of the chart.
*/}}
{{- define "mlops-buckets-app.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "mlops-buckets-app.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "mlops-buckets-app.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "mlops-buckets-app.labels" -}}
helm.sh/chart: {{ include "mlops-buckets-app.chart" . }}
{{ include "mlops-buckets-app.selectorLabels" . }}
{{- if .Values.apolo_app_id }}
platform.apolo.us/app-id: {{ .Values.apolo_app_id | quote }}
{{- end }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "mlops-buckets-app.selectorLabels" -}}
app.kubernetes.io/name: {{ include "mlops-buckets-app.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}

{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "mlops-buckets-app.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "mlops-buckets-app.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}
