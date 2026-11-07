#!/bin/sh
# nft-metrics — the shared metrics engine for stateful nftables
# mitigations (roles/nft_rules/files/nft-metrics.sh).
#
# ONE file, two sections (the classic sh library idiom):
#   §1 LIBRARY — pure functions, no side effects at source time.
#      A future mitigation's host-side script SOURCES this file and
#      calls nft_metrics_publish with its own identity — the DRY
#      contract on the sh side (the pod-side counterpart,
#      nft-metrics.py, is the importable Python engine).
#   §2 CLI — runs only when EXECUTED (sh nft-metrics.sh): identity
#      comes from the environment. The systemd timer and the role's
#      one-shot task call this shape.
#
# POSIX sh only: the timer runs this on the HOST's userspace, where
# python3 is NOT a guaranteed dependency (metrics is not optional —
# unlike the probe, there is no run_probe:false escape hatch).
#
# CLI environment (§2):
#   NFT_METRICS_TABLE    the nft table to list (default cve_2026_98432)
#   NFT_METRICS_PREFIX   the metric series prefix (default cve_2026_98432)
#   NFT_METRICS_MATCH    the rule-shape fragment locating the MATCH
#                        counter (default 'hdrlength != 5') — the
#                        observe rule renders a SECOND, rate-limited
#                        log counter that must not be published
#   NFT_METRICS_NODE_EXPORTER_DIR  (default /var/lib/node_exporter)
#   NFT_METRICS_CHART_DIR          (default /var/lib/crusoe-mitigator)
#   LEGACY aliases: CVE_METRICS_NODE_EXPORTER_DIR / CVE_METRICS_CHART_DIR
#   (the cve-2026-98432-era names — deployed systemd units pass them;
#   honored until the units are replaced).
#
# Destination selection (first existing wins): node_exporter dir,
# else the chart dir; neither → no-op (exit 0, no file) — hosts
# without a metrics consumer publish nothing rather than failing.

# ============================================================
# §1 LIBRARY — sourceable, pure, parameterized as function args
# ============================================================

# nft_match_counter <chain_listing> <match_fragment>
# The VERDICT rule's match counter: the first `counter packets N`
# on a line that carries the rule-shape fragment AND a VERDICT
# (drop / log prefix). The probe/local split renders a count-only
# loopback rule FIRST that also matches the fragment — anchoring on
# 'first counter after the fragment' would read the LOOPBACK
# counter and under-report non-loopback traffic by orders of magnitude.
# A greedy `.*counter packets` match would additionally capture the
# observe rule's LOG counter (≤6/min clamp). Empty when the rule is
# absent.
nft_match_counter() {
    listing="$1"
    match="$2"
    printf '%s' "$listing" \
        | sed -nE "s/.*${match} counter packets ([0-9]*) bytes [0-9]*.*(drop|log prefix).*/\1/p" \
        | head -1
}

# nft_loopback_counter <chain_listing>
# The loopback count-only rule's counter: probe/local options
# traffic (the live probe is loopback-sourced; non-loopback traffic never
# is). The metrics publish it as the probe series; external =
# the verdict rule's total − this.
nft_loopback_counter() {
    printf '%s' "$1" \
        | sed -nE "s/.*ip saddr 127\.0\.0\.0\/8.*counter packets ([0-9]*) bytes [0-9]*$/\1/p" \
        | head -1
}

# nft_verdict <chain_listing>
# The loaded rule's verdict: observe (log prefix) or enforce (drop).
nft_verdict() {
    if printf '%s' "$1" | grep -q 'log prefix'; then
        printf 'observe'
    else
        printf 'enforce'
    fi
}

# nft_metrics_emit <prefix> <matched> <mode> [loopback]
# The Prometheus textfile exposition for a LOADED rule — HELP/TYPE
# per family (serve-metrics warns on malformed families). The
# optional loopback counter (the probe/local split) publishes
# loopback_packets_total (kernel-truth) and non_loopback_packets_total
# (total − probe) alongside the UNCHANGED matched/dropped series.
nft_metrics_emit() {
    prefix="$1"
    matched="$2"
    mode="$3"
    loopback="${4:-}"
    echo "# HELP ${prefix}_rule_loaded Whether the mitigation's rule is loaded (1 = loaded)."
    echo "# TYPE ${prefix}_rule_loaded gauge"
    echo "${prefix}_rule_loaded 1"
    # Labeled enum (kube-state-metrics pattern): the active mode is
    # 1, every other known mode 0 — readable in PromQL, extensible,
    # and dashboards select by label not magic numbers.
    echo "# HELP ${prefix}_mode The rule's mode: exactly one of the mode labels is 1."
    echo "# TYPE ${prefix}_mode gauge"
    echo "${prefix}_mode{mode=\"observe\"} $([ "$mode" = observe ] && echo 1 || echo 0)"
    echo "${prefix}_mode{mode=\"enforce\"} $([ "$mode" = enforce ] && echo 1 || echo 0)"
    echo "# HELP ${prefix}_matched_packets_total IPv4 TCP packets with IP options matched by the rule since it was last loaded (observe counts, enforce drops — same series either way)."
    echo "# TYPE ${prefix}_matched_packets_total counter"
    echo "${prefix}_matched_packets_total{scope=\"host\"} $matched"
    # ALWAYS present (series stability across mode flips): in
    # enforce every match is a drop (same value); in observe the
    # rule drops nothing (0). A mode-conditional series would
    # appear/vanish on flips and break rate() windows and
    # absent()-style alerts.
    echo "# HELP ${prefix}_dropped_packets_total IPv4 TCP packets with IP options dropped since the rule was last loaded (0 while observing)."
    echo "# TYPE ${prefix}_dropped_packets_total counter"
    if [ "$mode" = "enforce" ]; then
        echo "${prefix}_dropped_packets_total $matched"
    else
        echo "${prefix}_dropped_packets_total 0"
    fi
    # The probe/local split (optional — only when the loopback rule
    # renders, i.e. this ruleset generation): loopback_packets_total is
    # the kernel-truth count of loopback-sourced options traffic
    # (the live probe; any local options traffic); external is the
    # difference — options packets NOT from loopback. NB: "external"
    # is a SOURCE statement, not a verdict — scanners, health checks,
    # and misconfigured internal clients all land here too;
    # classification (scanner/external/internal-legit) is the gate
    # check's job. Both series absent when the loopback counter is
    # not passed (pre-split rulesets degrade cleanly).
    if [ -n "$loopback" ]; then
        echo "# HELP ${prefix}_loopback_packets_total Options packets sourced from loopback (127.0.0.0/8) since the rule was last loaded — primarily the live probe's own SYNs; any node-local options traffic lands here too. A source statement: the counter cannot attribute individual senders."
        echo "# TYPE ${prefix}_loopback_packets_total counter"
        echo "${prefix}_loopback_packets_total $loopback"
        echo "# HELP ${prefix}_non_loopback_packets_total Options packets NOT sourced from loopback since the rule was last loaded (matched total minus the loopback count): other pods, cluster-internal traffic, scanners, and external hosts all land here. A source statement, not a verdict — classification is the gate check's job; per-netns series attribute pod targets."
        echo "# TYPE ${prefix}_non_loopback_packets_total counter"
        # Clamp at 0: the ruleset guarantees loopback <= matched (every
        # loopback packet also hits the verdict rule), but a stale
        # listing or a ruleset regression could violate it — a
        # Prometheus counter must never go negative.
        if [ "$loopback" -gt "$matched" ]; then
            echo "${prefix}_non_loopback_packets_total 0"
        else
            echo "${prefix}_non_loopback_packets_total $((matched - loopback))"
        fi
    fi
}

# nft_metrics_emit_unloaded <prefix>
# The rule is absent: rule_loaded 0, nothing else (no stale series).
nft_metrics_emit_unloaded() {
    prefix="$1"
    echo "# HELP ${prefix}_rule_loaded Whether the mitigation's rule is loaded (1 = loaded)."
    echo "# TYPE ${prefix}_rule_loaded gauge"
    echo "${prefix}_rule_loaded 0"
}

# nft_atomic_write <output_file>
# stdin → the file, atomically (tmp + mv): a scraper must never see
# a half-written exposition.
nft_atomic_write() {
    output_file="$1"
    # mktemp in the SAME dir (cross-device mv is not atomic): a
    # unique, UNPREDICTABLE staging name — a guessable $$-suffixed
    # tmp in a dir root may not own is a symlink-clobber window
    # (the review's security finding). mktemp's XXXXXX is random;
    # the mv is atomic (same filesystem).
    temp_file="$(mktemp "${output_file}.XXXXXX")"
    cat > "$temp_file"
    # mktemp creates 0600 whatever the umask; the published file must
    # be world-readable — node_exporter runs as a dedicated non-root
    # user on bare VMs (the old `> file` path honoured the umask and
    # gave 0644; the mktemp switch silently broke that).
    chmod 0644 "$temp_file"
    mv "$temp_file" "$output_file"
}

# nft_metrics_publish <table> <prefix> <match> <node_exporter_dir> <chart_dir>
# The full pipeline. NFT_CHAIN_FIXTURE (env) overrides the nft call —
# the test seam (the library section itself stays env-free).
nft_metrics_publish() {
    table="$1"
    prefix="$2"
    match="$3"
    node_exporter_dir="$4"
    chart_dir="$5"

    if [ -d "$node_exporter_dir" ]; then
        output_file="${node_exporter_dir}/${prefix}.prom"
    elif [ -d "$chart_dir" ]; then
        output_file="${chart_dir}/${prefix}.prom"
    else
        return 0
    fi

    if [ -n "${NFT_CHAIN_FIXTURE:-}" ]; then
        listing="$NFT_CHAIN_FIXTURE"
    else
        listing="$(nft list chain ip "$table" input 2>/dev/null || true)"
    fi
    matched="$(nft_match_counter "$listing" "$match")"

    if [ -n "$matched" ]; then
        mode="$(nft_verdict "$listing")"
        loopback="$(nft_loopback_counter "$listing")"
        nft_metrics_emit "$prefix" "$matched" "$mode" "$loopback" \
            | nft_atomic_write "$output_file"
    else
        nft_metrics_emit_unloaded "$prefix" | nft_atomic_write "$output_file"
    fi
}

# ============================================================
# §2 CLI — runs only when EXECUTED, not when sourced
# ============================================================

case "${0##*/}" in
    nft-metrics.sh)
        TABLE="${NFT_METRICS_TABLE:-cve_2026_98432}"
        PREFIX="${NFT_METRICS_PREFIX:-cve_2026_98432}"
        MATCH="${NFT_METRICS_MATCH:-hdrlength != 5}"
        NODE_EXPORTER_DIR="${NFT_METRICS_NODE_EXPORTER_DIR:-${CVE_METRICS_NODE_EXPORTER_DIR:-/var/lib/node_exporter}}"
        CHART_DIR="${NFT_METRICS_CHART_DIR:-${CVE_METRICS_CHART_DIR:-/var/lib/crusoe-mitigator}}"
        nft_metrics_publish "$TABLE" "$PREFIX" "$MATCH" \
            "$NODE_EXPORTER_DIR" "$CHART_DIR"
        ;;
esac
