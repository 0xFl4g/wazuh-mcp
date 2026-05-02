{{/* Standard Helm helpers */}}

{{- define "wazuh-mcp.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "wazuh-mcp.fullname" -}}
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

{{- define "wazuh-mcp.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "wazuh-mcp.labels" -}}
helm.sh/chart: {{ include "wazuh-mcp.chart" . }}
{{ include "wazuh-mcp.selectorLabels" . }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{- define "wazuh-mcp.selectorLabels" -}}
app.kubernetes.io/name: {{ include "wazuh-mcp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "wazuh-mcp.serviceAccountName" -}}
{{- include "wazuh-mcp.fullname" . }}
{{- end }}

{{/*
Resolve the secret name actually used at runtime:
- if .Values.secrets.existingSecret is set, use it
- else if .Values.secrets.create is true, use "<fullname>-secrets"
- else empty (no secret mount)
*/}}
{{- define "wazuh-mcp.secretName" -}}
{{- if .Values.secrets.existingSecret -}}
{{- .Values.secrets.existingSecret -}}
{{- else if .Values.secrets.create -}}
{{- printf "%s-secrets" (include "wazuh-mcp.fullname" .) -}}
{{- end -}}
{{- end }}
