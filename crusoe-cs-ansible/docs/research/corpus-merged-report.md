# Merged report: where do the authoritative fingerprints come from?

**Panel:** faceted research (fusion-research merge shape) — 2026-10-21
**Question:** Is there an authoritative source the bad-CA fingerprint list must
match (Crusoe bulletin / distrust advisory), or is "fetch the public roots and
derive" the source of truth?

## Coverage Map

| Facet | Covered by | Status |
|-------|------------|--------|
| Distro/package records (Ubuntu, Debian, Rocky/Fedora) | `corpus-distro-records.md` | Covered |
| Public CA-ecosystem records (root programs, CCADB, advisory) | The advisory site itself, fetched directly by the composer (`emudhra.we-have-a-problem.com`) | Covered — the dedicated researcher dispatch failed (network error), but the advisory site is the primary coordination artifact this facet would have summarized (root-program action dates, Mozilla bug 2083449, dev-security-policy thread, machine-readable artifacts). No re-dispatch needed. |
| Crusoe-internal advisory (Jira/Confluence) | Not searched | Skipped by user answer — the user supplied the advisory site directly as the source of truth, superseding an internal-bulletin search. |

## Combined Answer

**The authoritative source is the incident advisory's machine-readable artifact:
`https://emudhra.we-have-a-problem.com/roots.json`.** The site is the community
coordination point for the distrust event (published 2026-10-20 by Dennis
Jackson / the Mozilla security community; incident tracked as Mozilla bug
2083449). `roots.json` lists the roots the eight compromised eMudhra
intermediates chain to; `impacted-intermediates.json` lists the intermediates
and their Sectigo cross-signs.

`roots.json` lists **four** roots (fetched and pinned post-panel; see the
design doc's fingerprint table):

1. **emSign ECC Root CA - G3** (cross_signer, Mozilla-included) —
   `86A1ECBA089C4A8D3BBE2734C612BA341D813E043CF9E8A862CD5C57A36BBE6B` — the
   root Linux distro updates blacklist.
2. **AAA Certificate Services** (Comodo/Sectigo, direct issuer of the Sectigo
   cross-signs) — `D7A7A0FB5D7E2731D771E9484EBCDEF71D5F0C3E0A2948782BC83EE0EA699EF4`
   — matches the Rocky c9s patch fingerprint verbatim.
3. **emSign Root TLS CA - G3** (direct_issuer, Microsoft-only) —
   `7DD78D5F4F13459A83DFF9ABBBA62EDBAF6F2D102BF257FD712F4D9F2746ED8D` —
   manual-add only on Linux.
4. **emSign Root CS CA - G3** (direct_issuer, Microsoft-only) —
   `F2EDAAFF3D9B701FB4D14C9F285F8C0BAD90FC3BCC1FA07D47F4718EDABA34A5` —
   manual-add only on Linux.

Fingerprint derivation and corroboration:

- Derive SHA-256 fingerprints from the root PEMs in `roots.json`.
- Cross-check against independent distro records: Rocky 9's (c9s)
  `remove-aaa-certificate-services.patch` embeds AAA's SHA-256 verbatim
  (`D7:A7:A0:FB:5D:7E:27:31:D7:71:E9:48:4E:BC:DE:F7:1D:5F:0C:3E:0A:29:48:78:2B:C8:3E:E0:EA:69:9E:F4`),
  and `remove-emsign-ecc-root-ca-g3.patch` embeds emSign's MD5
  (`ce:0b:72:d1:9f:88:8e:d0:50:03:e8:e3:b8:8b:67:40`) and SHA1
  (`30:43:fa:4f:f2:57:dc:a0:c3:80:ee:2e:58:ea:78:b2:3f:e6:bb:c1`) — enough to
  corroborate the roots.json PEMs even though no distro changelog prints
  emSign's SHA-256.
- Distro USNs/changelogs (Ubuntu USN-8944-1, Debian DSA-6572-1 /
  `20260816+nmu1`) carry **names only** — they corroborate the event and the
  root names, not fingerprints.

**Never match by name.** Sources disagree on the emSign root's name
("emSign Root TLS CA – G3" per the advisory/Ubuntu blog vs "emSign ECC Root
CA - G3" per USN/certdata/Rocky patches). The fingerprint is the only stable
identity — validating the design's fingerprint-matching decision.

**Remediation corroboration:** the advisory documents the official per-family
distrust methods — Debian/Ubuntu: `!`-prefix the entries in
`/etc/ca-certificates.conf` + `update-ca-certificates`; Fedora/RHEL/Rocky/
Alma/AL2023: extract the roots into `/etc/pki/ca-trust/source/blocklist/`
(fallback `blacklist/`) + `update-ca-trust`. Fixed package versions: Ubuntu
`20260816ubuntu0.{22.04,24.04,26.04,26.10}.1`, Debian
`20250419~deb12u2` / `20250419+deb13u1` / `20260816+nmu1`, Fedora
`2026.2.92_v9.0.319`. Rocky 9's fix only landed in c9s on 2026-10-21 —
released Rocky repos may lag, making the blocklist fallback the expected
Rocky path initially.

## Gaps

- **emSign SHA-256 (resolved post-panel):** no distro record prints it, but
  `roots.json` pins it (`86A1ECBA…BBE6B`), corroborated by the Rocky patch's
  serial (`3CF607A968700EDA8B84`) and MD5/SHA1. The role's build-time check
  asserts the shipped PEM hashes to the pinned value.
- **Rocky 9 released package version unconfirmed** (Fedora sources
  Anubis-blocked; only the c9s commit is visible). Affects e2e clean-fixture
  construction on Rocky: if the fixed package isn't in released repos, the
  fixture must construct the clean state via the advisory's blocklist commands.
- **Crusoe-internal advisory unsearched** (Atlassian CLIs not verified this
  session). Skipped deliberately: the user supplied the advisory site as the
  source of truth. If a Crusoe security bulletin with its own fingerprint list
  exists, it should be cross-checked at implementation time.

## Conflicts At Seams

- **emSign root naming** (advisory/blog: "emSign Root TLS CA – G3" vs
  USN/certdata/Rocky: "emSign ECC Root CA - G3"). Resolution: fingerprint-only
  matching; names are display labels. `roots.json` shows these are **two
  different certificates** (TLS: serial `0E760672…`, Microsoft-only; ECC:
  serial `3CF607A9…`, Mozilla-included) — the name overlap made name-based
  matching actively dangerous, validating the fingerprint decision.
- **Comodo AAA presence**: Ubuntu removed it from the bundle in the earlier
  `20260223` (Mozilla 2.82) update on 22.04+, while Debian's NMU blacklists it
  explicitly. Not a conflict — different distros, different timelines;
  per-host fingerprint detection handles each host's actual state.
