# Paper K — PHP corpus manifest (pinned 2026-10-24)

All targets are public, deliberately-vulnerable PHP applications. Each is pinned to an exact commit and exported WITHOUT its .git directory (clean tree). To reproduce, re-run fetch_corpus.sh, which clones at the recorded SHA.

## Targets and commit pins
- DVWA            : a1978a2fed195acd093010af6395f86a281537ca  2026-10-18 18:11:33 +0100  https://github.com/digininja/DVWA.git
- Mutillidae II   : 126a1fdb4ff977f87e980d018f0def477afc3d5d  2026-09-24 19:04:06 -0400  https://github.com/webpwnized/mutillidae.git
- WackoPicko      : cabc1b3a06beda7df98e839fa2d84db9a4bdfee7  2021-11-17 09:51:38 -0700  https://github.com/adamdoupe/WackoPicko.git
- vulhub (subset) : vulhub (selected subset)  9b90d4276f84feed6333286afeb7e1250379a1da  2026-10-18 04:59:35 +0800  https://github.com/vulhub/vulhub.git

## Control-gaining class coverage (maps to plan Section 3)
- Object injection / unserialize / POP chains : vulhub joomla/CVE-2015-8562 ; php/CVE-2018-19518
- File inclusion -> code execution (LFI/RFI)  : vulhub php/inclusion ; phpmyadmin/CVE-2018-12613 ; DVWA (File Inclusion) ; Mutillidae
- Command / eval sinks -> RCE                 : vulhub php/CVE-2012-1823 ; php/CVE-2019-11043 ; thinkphp 2-rce/5-rce/5.0.23-rce ; drupal/CVE-2018-7600 ; drupal/CVE-2018-7602 ; laravel/CVE-2021-3129 ; DVWA (Command Injection)
- Unrestricted upload -> webshell             : DVWA (File Upload) ; Mutillidae
- Type-juggling auth bypass                   : DVWA (high levels) ; Mutillidae ; (candidate dedicated target TBD)
- SQL injection                               : DVWA ; Mutillidae ; vulhub thinkphp/in-sqlinjection ; drupal/CVE-2014-3704
- Modern framework takeover (Laravel)         : vulhub laravel/CVE-2021-3129 (Ignition debug-mode RCE)

## Not yet added (next-step decisions)
- bWAPP — optional 5th training app (PHP, ~100 catalogued bugs). Add if a broader training set is wanted.
- A dedicated type-juggling target beyond DVWA/Mutillidae, if the class needs isolation.
- Ground-truth label set (the artifact) — to be authored per target from each app's documented catalogue.
