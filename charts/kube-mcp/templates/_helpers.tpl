{{- define "kube-mcp.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "kube-mcp.fullname" -}}
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

{{- define "kube-mcp.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimAll "-_." }}
{{- end }}

{{- define "kube-mcp.labels" -}}
helm.sh/chart: {{ include "kube-mcp.chart" . }}
{{ include "kube-mcp.selectorLabels" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Chart.AppVersion }}
app.kubernetes.io/version: {{ . | replace "+" "_" | trunc 63 | trimAll "-_." | quote }}
{{- end }}
{{- end }}

{{- define "kube-mcp.selectorLabels" -}}
app.kubernetes.io/name: {{ include "kube-mcp.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "kube-mcp.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "kube-mcp.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- required "serviceAccount.name is required when serviceAccount.create=false" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{- define "kube-mcp.clusterRoleName" -}}
{{- $namespaceHash := sha256sum .Release.Namespace | trunc 8 -}}
{{- printf "%s-%s-reader" (include "kube-mcp.fullname" . | trunc 46 | trimSuffix "-") $namespaceHash | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "kube-mcp.image" -}}
{{- if .Values.image.digest }}
{{- printf "%s@%s" .Values.image.repository .Values.image.digest }}
{{- else }}
{{- printf "%s:%s" .Values.image.repository (default .Chart.AppVersion .Values.image.tag) }}
{{- end }}
{{- end }}

{{- define "kube-mcp.allowedHosts" -}}
{{- $fullname := include "kube-mcp.fullname" . -}}
{{- $hosts := list $fullname (printf "%s.%s" $fullname .Release.Namespace) (printf "%s.%s.svc" $fullname .Release.Namespace) (printf "%s.%s.svc.cluster.local" $fullname .Release.Namespace) "localhost" "127.0.0.1" "[::1]" -}}
{{- range .Values.allowedHosts }}
{{- $hosts = append $hosts . -}}
{{- end }}
{{- $hosts | uniq | join ";" -}}
{{- end }}
