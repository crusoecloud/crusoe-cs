{{/* Assemble the digest-pinned image reference.

Resolution order (first match wins):
  1. .Values.image.full          — explicit escape hatch (the smoke
     passes the CCR ref it resolved dynamically via --set image.full)
  2. .Values.image.registry/repository/digest

The assembled ref MUST be digest-pinned (@sha256:...) — the chart
fails loudly otherwise; a floating tag could silently run different
bytes than the ones reviewed.

Note: Helm 4's env lookup was evaluated and rejected — it returns an
empty map on 4.3.1, so charts cannot reliably read the operator's
environment. Callers pass values (or --set), which is the GitOps-
correct contract anyway.
*/}}
{{- define "crusoe-distrust-emudhra-ca.imageRef" -}}
{{- if .Values.image.full -}}
{{- .Values.image.full -}}
{{- else if and .Values.image.registry .Values.image.repository .Values.image.digest -}}
{{- printf "%s/%s@%s" .Values.image.registry .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- fail (printf "image reference unresolved: set image.full, or all of image.registry/repository/digest (digest must be sha256:...-pinned)") -}}
{{- end -}}
{{- end -}}
