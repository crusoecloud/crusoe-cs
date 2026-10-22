# Research corpus: authoritative fingerprints for distrusted roots (distro package records)

> Persisted by the composer from the distro-records researcher's final report
> (researcher ran read-only and could not write the artifact itself).
> Slice: Linux distro/package records ONLY (Ubuntu, Debian, Rocky/Fedora).

## Findings

### 1. Ubuntu ca-certificates update records (USN, Launchpad, changelog)

- Ubuntu published **USN-8944-1** on **2026-10-20** for the `ca-certificates` package. It names the removed root as **"emSign ECC Root CA - G3"** and cites the reason as intermediate CA compromise. It does **not** include any SHA-256 fingerprint. — [1][2]
  > "This update removes the 'emSign ECC Root CA - G3' CA certificate due to intermediate CA certificates being compromised. In addition, in Ubuntu 22.04 LTS, Ubuntu 24.04 LTS, and Ubuntu 26.04 LTS, the ca-certificates package contained outdated CA certificates. This update refreshes the included certificates to those contained in the 2.90 version of the Mozilla certificate authority bundle."
- The Ubuntu Security blog post "eMudhra CA compromise fixes available" (2026-10-20) names **two** roots removed: **"emSign Root TLS CA – G3"** and **"Comodo AAA Certificate Services"**, and states the Comodo AAA root had already been removed on Ubuntu 22.04+ in an earlier update. — [3]
  > "two other root CAs have cross-signed the eMudhra CA: emSign Root TLS CA – G3 and Comodo AAA Certificate Services. These two roots have been removed from the Ubuntu trusted root store in the ca-certificates package..."
  > "AAA Certificate Services CA had previously been removed from the CA bundles in Ubuntu 22.04 (Jammy Jellyfish) and newer releases."
- **Naming discrepancy (important):** the USN and the Launchpad changelog say **"emSign ECC Root CA - G3"**, while the blog says **"emSign Root TLS CA – G3"**. The role matches by SHA-256 fingerprint, so this naming inconsistency does not affect matching, but it must not be relied on for identification. — [1][2][3]
- Launchpad changelog for `20260816ubuntu0.24.04.1` (noble-security, published 2026-10-20) confirms the blacklist entry and the Mozilla 2.90 refresh. It lists the emSign root by name only, no fingerprint. — [2]
  > "Blacklist the following CA cert due to intermediate cert compromise (LP: #2171507) + 'emSign ECC Root CA - G3'"
- The Comodo AAA root was removed from the Mozilla bundle on Ubuntu in the **20260223** update (Mozilla bundle 2.82), i.e. earlier than the emSign blacklist. Changelog entry: `- Comodo AAA Services root`. — [2]
- The pinned version `20260816ubuntu0.24.04.1` (the security update published 2026-10-20) is the one that blacklists emSign; Comodo AAA was already gone from 22.04+ by then. — [2][3]

### 2. Debian and Rocky/Fedora records

- **Debian** published **DSA-6572-1** (ca-certificates security update, 2026-10-20). — [4]
- Debian changelog `20260816+nmu1` (2026-10-20, NMU by Salvatore Bonaccorso) blacklists **both** roots by name: — [5]
  > "Blacklist 'emSign ECC Root CA - G3' and 'Comodo AAA Services root' (Closes: #1151413)"
- Debian's `20260223` (Mozilla 2.82) had already removed `Comodo AAA Services root` from the bundle; the NMU additionally blacklists it explicitly. — [5]
- Debian stable/oldstable security versions carrying the fix: `20250419+deb13u1` (trixie) and `20250419~deb12u2` (bookworm), both accepted 2026-10-20. — [4][6]
- **Rocky 9** is built from CentOS Stream 9 (c9s). The c9s `ca-certificates` repo has a commit **"CVE: Remove AAA Certificate Services and emSign ECC Root CA - G3"** (2026-10-21) adding two patches: `remove-aaa-certificate-services.patch` and `remove-emsign-ecc-root-ca-g3.patch`. — [7][8]
- The Rocky/Fedora spec changelog names the roots but carries no fingerprints; the fingerprints live in the **patch files** (certdata.txt blocks). — [8][9]

### 3. Do distro records carry fingerprints?

- **Ubuntu USN and Launchpad changelog: names only, no fingerprints.** — [1][2]
- **Debian changelog: names only, no fingerprints.** — [5]
- **Rocky/Fedora spec changelog: names only; but the shipped `remove-*.patch` files contain the full certdata.txt blocks, which DO include fingerprints.** — [8][9]
- The **Comodo AAA Certificate Services** SHA-256 fingerprint is present verbatim in the Rocky c9s `remove-aaa-certificate-services.patch`: — [9]
  > `Fingerprint (SHA-256): D7:A7:A0:FB:5D:7E:27:31:D7:71:E9:48:4E:BC:DE:F7:1D:5F:0C:3E:0A:29:48:78:2B:C8:3E:E0:EA:69:9E:F4`
  > (Issuer/Subject: `CN=AAA Certificate Services,O=Comodo CA Limited,L=Salford,ST=Greater Manchester,C=GB`, Serial `1 (0x1)`, valid 2004-01-01 to 2028-12-31)
- The **emSign ECC Root CA - G3** certdata.txt block in the Rocky patch carries only **MD5 and SHA1** fingerprints (no SHA-256 line in the captured block): — [9]
  > `Fingerprint (MD5): ce:0b:72:d1:9f:88:8e:d0:50:03:e8:e3:b8:8b:67:40`
  > `Fingerprint (SHA1): 30:43:fa:4f:f2:57:dc:a0:c3:80:ee:2e:58:ea:78:b2:3f:e6:bb:c1`
  > (Issuer/Subject: `CN=emSign ECC Root CA - G3,O=eMudhra Technologies Limited,OU=emSign PKI,C=IN`, Serial `3c:f6:07:a9:68:70:0e:da:8b:84`, valid 2018-02-18 to 2043-02-18; `CKA_NSS_MOZILLA_CA_POLICY CK_BBOOL CK_FALSE` — code-signing-only trust)
- **Practical verification method:** because distro changelogs/USNs carry only names, the reliable way to verify which roots a given ca-certificates version trusts is to (a) inspect the shipped cert files / the `certdata.txt` the package is generated from, or (b) for Rocky, read the `remove-*.patch` files which embed the certdata blocks with fingerprints. The SHA-256 for emSign is not printed in certdata.txt and must be computed from the certificate PEM. — [2][5][9]

## Sources
- [1] USN-8944-1: ca-certificates update — https://ubuntu.com/security/notices/USN-8944-1 (2026-10-20)
- [2] Launchpad ca-certificates changelog — https://launchpad.net/ubuntu/+source/ca-certificates/+changelog (2026-10-20)
- [3] Ubuntu blog: "eMudhra CA compromise fixes available" — https://ubuntu.com/blog/emudhra-ca-compromise-fixes-available (2026-10-20)
- [4] Debian Security Tracker, source package ca-certificates (DSA-6572-1) — https://security-tracker.debian.org/tracker/source-package/ca-certificates (2026-10-20)
- [5] Debian ca-certificates changelog 20260816+nmu1 — https://tracker.debian.org/media/packages/c/ca-certificates/changelog-20260816nmu1 (2026-10-20)
- [6] Debian Package Tracker, ca-certificates — https://tracker.debian.org/pkg/ca-certificates (2026-10-20)
- [7] CentOS Stream c9s ca-certificates commits — https://gitlab.com/redhat/centos-stream/rpms/ca-certificates/-/commits/c9s (2026-10-21)
- [8] CentOS Stream c9s ca-certificates spec — https://gitlab.com/redhat/centos-stream/rpms/ca-certificates/-/raw/c9s/ca-certificates.spec (2026-10-21)
- [9] CentOS Stream c9s patches: remove-aaa-certificate-services.patch / remove-emsign-ecc-root-ca-g3.patch — https://gitlab.com/redhat/centos-stream/rpms/ca-certificates/-/raw/c9s/remove-aaa-certificate-services.patch and .../remove-emsign-ecc-root-ca-g3.patch (2026-10-21)

## Open Questions
- **emSign SHA-256 fingerprint not captured.** The Rocky c9s `remove-emsign-ecc-root-ca-g3.patch` certdata.txt block printed only MD5 and SHA1 in the fetched excerpt; no SHA-256 line appeared. I could not corroborate the emSign SHA-256 from a distro record. It must be computed from the certificate PEM (or confirmed from a CA-ecosystem source, which is another panelist's slice). The role's exact-SHA-256 matching for emSign therefore depends on a fingerprint not present in any distro changelog.
- **Fedora/Rocky direct sources blocked.** `src.fedoraproject.org` and `bodhi.fedoraproject.org` are behind Anubis bot protection; I used the CentOS Stream GitLab c9s mirror (Rocky 9's base) instead. I could not confirm the exact Fedora/Rocky **release version number** that ships the fix, only the c9s commit/patches.
- **Debian DSA-6572-1 body not fetched.** The DSA page redirected to a lists.debian.org message behind a JS proof-of-work wall; I confirmed the DSA ID and the affected package versions from the security tracker but could not read the DSA's own text. The changelog `20260816+nmu1` independently confirms the blacklist.
- **Ubuntu blog vs USN naming.** The blog names "emSign Root TLS CA – G3" while the USN/changelog name "emSign ECC Root CA - G3". I could not determine which is the canonical certdata label; the role should rely on fingerprint, not name.
