{{/* Assemble the digest-pinned image reference.

Resolution order (first match wins):
  1. .Values.image.full          — explicit escape hatch
  2. .Values.image.registry/repository/digest

The assembled ref MUST be digest-pinned (@sha256:...) — the chart
fails loudly otherwise; a floating tag could silently run different
bytes than the ones reviewed.
*/}}
{{- define "crusoe-mitigator.imageRef" -}}
{{- if .Values.image.full -}}
{{- .Values.image.full -}}
{{- else if and .Values.image.registry .Values.image.repository .Values.image.digest -}}
{{- printf "%s/%s@%s" .Values.image.registry .Values.image.repository .Values.image.digest -}}
{{- else -}}
{{- fail (printf "image reference unresolved: set image.full, or all of image.registry/repository/digest (digest must be sha256:...-pinned)") -}}
{{- end -}}
{{- end -}}

{{/* Assemble a mitigation entry's vars — the GENERIC mechanism: the
     entry's flat vars map renders as -e key=value pairs. The MODE is
     not special: the cve-2026-98432 entry runs label-driven (auto, the
     role's default — the chart renders NO mode var, and an extra var
     would beat the label resolution's set_fact anyway); a pinned
     cluster sets the role's mode var HERE (air-gapped, SSH path,
     freeze hold) and the role's label resolution no-ops. */}}
{{- define "crusoe-mitigator.entryVars" -}}
{{- $vars := dict -}}
{{- range $k, $v := .entry.vars -}}
{{- $_ := set $vars (toString $k) (toString $v) -}}
{{- end -}}
{{- $out := "" -}}
{{- range $k, $v := $vars -}}
{{- $out = printf "%s -e %s=%s" $out $k $v -}}
{{- end -}}
{{- trimPrefix " " $out -}}
{{- end -}}

{{/* Render the enabled mitigations into the MITIGATIONS env var:
     one line per mitigation:
       <name>|<wrapper-playbook>|<flat -e vars>|<interval-seconds>
     Only enabled entries are rendered; the entrypoint skips blank lines.
     vars must be a flat map of key: value — rendered as -e key=value
     pairs (values stringified; no nesting by contract).
     interval: 0 (default) = once per pod start; > 0 = re-run every
     interval seconds for the pod's lifetime (mitigations that must
     hold continuously or can be undone mid-life).
*/}}
{{- define "crusoe-mitigator.mitigations" -}}
{{- $lines := list -}}
{{- range .Values.mitigations -}}
{{- if and (kindIs "map" .) (hasKey . "enabled") .enabled (hasKey . "name") .name (hasKey . "playbook") .playbook -}}
{{- $vars := include "crusoe-mitigator.entryVars" (dict "entry" .) -}}
{{- $interval := 0 -}}
{{- if and (hasKey . "interval") (kindIs "float64" .interval) -}}
{{- $interval = .interval -}}
{{- end -}}
{{- $lines = append $lines (printf "%s|%s|%s|%v" .name .playbook $vars $interval) -}}
{{- end -}}
{{- end -}}
{{- join "\n" $lines -}}
{{- end -}}
