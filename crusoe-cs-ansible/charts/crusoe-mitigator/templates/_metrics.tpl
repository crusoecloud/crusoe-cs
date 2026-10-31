{{/* True when any enabled mitigation requests metrics (metrics: true
     or absent — the default is on). */}}
{{- define "crusoe-mitigator.metricsEnabled" -}}
{{- $enabled := false -}}
{{- range .Values.mitigations -}}
{{- if and (kindIs "map" .) (hasKey . "enabled") .enabled (not (and (hasKey . "metrics") (eq .metrics false))) -}}
{{- $enabled = true -}}
{{- end -}}
{{- end -}}
{{- $enabled -}}
{{- end -}}
