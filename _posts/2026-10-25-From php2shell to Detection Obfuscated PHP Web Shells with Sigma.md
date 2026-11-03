---
title: "From php2shell to Detection: Hunting Obfuscated PHP Web Shells with Sigma"
date: 2026-10-25 07:00:00 +0300
categories: [Detection Engineering, Web Shells]
tags: [php, php2shell, webshell, sigma, detection-engineering, threat-hunting, dfir, fileless]
image:
  path: /assets/img/php2shell_post/php2shell-sigma-cover.png
  alt: From php2shell to Detection Hunting Obfuscated PHP Web Shells with Sigma
---
## Executive Summary
 
**Writer's note:** I decided to write this article because I was confused and overwhelmed by the number of PHP2Shell detections out there. Some focus on IOCs rather than the behavior of the CVEs themselves, and others cover only part of the activity. So I wrote this one as a reference for PHP2Shell, with coverage as comprehensive as I could make it.

The PHP web shell is probably the most re-skinned piece of malware on the internet. The same twenty lines of code get renamed, reencoded, and resold a thousand times under a hundred different names, and every few months a blog appears with a fresh list of "top web shells and their signatures." Those posts are useful for about a week right up until the attacker renames a variable or wraps the payload in one more layer of `base64`. Then the hash is wrong, the string is gone, and the signature is dead.

This is the exact gap I keep coming back to: the distance between *"we identified that sample"* and *"we can detect the next one."* A hash tells you about a file you already caught. It tells you nothing about the file sitting in `/var/www/uploads/` right now with a different name.
 
So in this post I'm not going to hand you a list of shell signatures. Instead we will do two things:
 
1. Reduce a PHP web shell to the handful of behaviors it **cannot** avoid, no matter how it's obfuscated, and
2. Build layered **Sigma** detection that targets those invariants instead of the skin, from the PHP2Shell exploit attempt all the way to the shell it hands the attacker.

**Why now: PHP2Shell.** On 20 and 21 October 2026, two critical bugs in PHP core were disclosed and fixed: CVE-2026-109618 and CVE-2026-109619. The researchers' combined exploit, which gave the issue its name, demonstrated unauthenticated code execution on WordPress, Drupal and Joomla, running as the PHP web worker. Fixes shipped in PHP 8.5.12, 8.4.27, 8.3.36 and 8.2.35, with source backports for 7.4, 8.0 and 8.1. Amazon Threat Intelligence logged an exploitation attempt on 17 October, four days before the fixes shipped. An exploit like this is a web shell without the file: the attacker's code runs inside the worker, with the worker's privileges. So the rules below watch the exploit attempt itself, and then everything a web shell does once it's running.

By the end you'll have a set of rules that still fire when the attacker renames everything, double-encodes the payload, or runs a shell that never touches the disk.
  
## Key Findings
 
Before the rules, here's the mental model the whole post hangs on. Every layer adds something the layer above it misses:
 
| Detection layer | What it catches | How the attacker evades it |
|-----------------|-----------------|----------------------------|
| File hash (MD5/SHA-256) | The exact known sample | Change one byte |
| Named-shell string signature | Known shells by their banner/variable names | Rename variables, strip comments |
| **Exposure** (Layer 1) | Servers still advertising a vulnerable PHP version | Not an attack signal; blind when the version header is hidden |
| **Exploit attempt** (Layer 2) | PHP2Shell trigger fields in the request body, and the memory error and worker crash they cause | Trigger variants without the logged markers, or servers that don't log request bodies |
| **Behavioral** (Layer 3) | The worker *executing* a shell or tool, whatever the code looks like | Stay inside PHP and start no process |
| **Hunting** (Layer 4) | Every process a PHP worker starts, and every PHP or config file it writes | Pure in-memory activity that writes no file |

### The anatomy every web shell shares
 
Strip away the obfuscation and a PHP web shell is always the same pipeline:
 
```
[ SOURCE ]  →  [ optional DECODE / UNPACK ]  →  [ SINK ]
attacker        base64 / gzinflate /            system / exec /
input from      str_rot13 / variable            eval / file write
a superglobal   functions                        / proc_open
```
 
- **SOURCE**: the attacker has to get their command *in*. In PHP that means a request superglobal: `$_GET`, `$_POST`, `$_REQUEST`, `$_COOKIE`, `$_SERVER` (headers), or the raw body via `php://input`. There is no web shell without attacker-controlled input, and there is no attacker-controlled input in PHP without one of these.
- **DECODE**: optional, and this is the only part that changes between "samples." Obfuscation lives entirely here.
- **SINK**: the command has to *run*. That means a code-execution function (`eval`, `assert`, `create_function`, `preg_replace` with the old `/e` modifier), an OS-command function (`system`, `shell_exec`, `passthru`, `exec`, `proc_open`, `popen`), or a filesystem write if the goal is to drop a second stage.

The signature of a web shell is not its name. It's the existence of a path from a **source** to a **sink**. You can't watch that path at runtime, but you can watch where it ends: an OS-command sink starts a process, and a file-write sink creates a file. Those are the invariants we're going to detect.
 
## Technical Analysis: Why Signatures Die
 
Let me show you concretely why the "list of signatures" approach is a losing game, because it motivates everything that follows.
 
Here's the simplest, un-obfuscated web shell on earth, the kind every tutorial starts with:
 
```php
<?php system($_GET['cmd']); ?>
```
 
Easy to catch. The strings `system` and `$_GET` are right there. But watch how little effort it takes to defeat a rule that only looks for the literal string `system`:
 
**Concatenation** breaks the string:
 
```php
$f = 'sys' . 'tem';
$f($_GET['cmd']);
```
 
**Variable functions** mean the sink name never appears as a call at all, it arrives as data:
 
```php
$_GET['f']($_GET['c']);   // the function name is attacker-supplied
```
 
**Encoding** hides both the sink and the source behind a decode layer:
 
```php
eval(base64_decode($_POST['x']));
```
 
**Stacked encoding** the thing php-malware-finder was built to catch, decodes twice, inflates, then executes, so none of the dangerous words are visible in the file:
 
```php
eval(gzinflate(base64_decode($_POST['x'])));
```
 
A string rule for `system` catches the first example and none of the others. A hash catches exactly one file and nothing else. This is why, every time you read "here are the IOCs for the XYZ web shell," you're reading about a battle that was already lost.
 
The move is to stop chasing the skin. Every one of those variants ends the same way once it runs: the decoded payload reaches a sink. When that sink runs a command or writes a file, it leaves a new process or a new file behind, and no encoding layer changes that, because by then the PHP has already decoded itself. Those runtime effects are the things we hunt.
 
## The Rule Set

Twelve Sigma rules follow, in four layers that track the attack: who is exposed, the exploit attempt, the shell running, and what an attacker does without a shell. The process and file rules use standard Sigma fields. Five rules use four custom log sources, which you map once in your pySigma pipeline:

| Log source | Fields the rules use |
|------------|----------------------|
| `product: modsecurity` | `cs-method`, `message` (the full audit record), `src_ip` |
| `product: php`, `service: error` | `message`, `client_ip` |
| `product: php`, `service: worker_crash` | `message` |
| `category: http_response_headers` | `Server`, `X-Powered-By` |

## Layer 1 (Exposure): Who Is Still Vulnerable

Before hunting for exploitation, find out where it can happen. Plenty of PHP servers still announce their version in the `X-Powered-By` or `Server` response header, and any reverse proxy, load balancer or Zeek sensor that records those headers can tell you which hosts run a vulnerable build.

```yaml
title: PHP2Shell Exposure - Vulnerable PHP Version Advertised
status: experimental
description: |
  Identifies web servers advertising a PHP version vulnerable to PHP2Shell
  (CVE-2026-109618 / CVE-2026-109619) in the Server or X-Powered-By response header:
  8.2 < 8.2.35, 8.3 < 8.3.36, 8.4 < 8.4.27, 8.5 < 8.5.12, and the EOL branches 5.4 to 8.1.
  This is exposure inventory, not attack detection; route results to patch management.
  A match is a hint, not proof: distributions backport fixes without changing the
  version string, and servers with expose_php = Off send no version at all.
  Corelight ships the same logic as the Potentially_Affected_PHP_Version Zeek notice.
references:
  - https://corelight.com/blog/php2shell-detection-before-disclosure
  - https://www.php.net/archive/2026.php#2026-10-21-5
author: Mohammad Alattas
date: 2026-10-24
modified: 2026-10-25
tags:
  - attack.initial-access
  - attack.t1190
  - cve.2026-109618
  - cve.2026-109619
  - detection.emerging-threats
logsource:
  category: http_response_headers
  definition: 'Requirements: a source that records response header values as fields named Server and X-Powered-By, such as reverse proxy or load balancer logs, Zeek with header logging, or scanner output. Plain web server access logs do not contain them.'
detection:
  selection_server:
    Server|re: 'PHP/(5\.[4-6]\.|7\.[0-4]\.|8\.[01]\.|8\.2\.([0-9]|[12][0-9]|3[0-4])([^0-9]|$)|8\.3\.([0-9]|[12][0-9]|3[0-5])([^0-9]|$)|8\.4\.([0-9]|1[0-9]|2[0-6])([^0-9]|$)|8\.5\.([0-9]|1[01])([^0-9]|$))'
  selection_powered:
    X-Powered-By|re: 'PHP/(5\.[4-6]\.|7\.[0-4]\.|8\.[01]\.|8\.2\.([0-9]|[12][0-9]|3[0-4])([^0-9]|$)|8\.3\.([0-9]|[12][0-9]|3[0-5])([^0-9]|$)|8\.4\.([0-9]|1[0-9]|2[0-6])([^0-9]|$)|8\.5\.([0-9]|1[01])([^0-9]|$))'
  condition: 1 of selection_*
falsepositives:
  - Distribution packages with backported fixes that keep the old version string (for example Ubuntu 8.1.2-1ubuntu2.x); confirm with installed package versions
level: low
```

This is a patch list, not an alert, which is why it's rated `low`. Read a match as a hint: distributions backport fixes without changing the version string (Ubuntu's `8.1.2-1ubuntu2.x`, for example), and a server with `expose_php = Off` sends no version at all. Confirm with the installed package version before you act.

## Layer 2 (The Attempt): What the Exploit Leaves Behind

PHP2Shell is triggered while PHP parses a crafted `multipart/form-data` POST, before any application code runs. That gives us three places to look, each in a different log: the request body in the WAF audit log, the memory error in the PHP error log, and the crashed worker in the PHP-FPM, Apache or kernel log.

### 2.1 Trigger primitives in the request body

The exploit needs specific shapes in the request body: `PHP_SESSION_UPLOAD_PROGRESS` fields for the CVE-2026-109619 use-after-free, form keys nested eight or more levels deep to blow up memory for the CVE-2026-109618 out-of-memory bailout, and PHP session-serialized objects (`|O:`) in the public proof-of-concept code. When the non-file part of a body is oversized, ModSecurity rejects it outright, and that rejection message is a signal too.

```yaml
title: PHP2Shell Exploitation Attempt - Suspicious Multipart Upload Anomalies
status: experimental
description: |
  Detects POST requests whose ModSecurity audit record carries PHP2Shell trigger
  primitives (CVE-2026-109618 / CVE-2026-109619):
  PHP_SESSION_UPLOAD_PROGRESS fields (the CVE-2026-109619 producer path); form keys
  nested 8 or more levels deep (heap amplification for the CVE-2026-109618
  out-of-memory bailout); PHP session-serialized objects ("|O:") as used by public
  PoCs; or a ModSecurity rejection for non-file body data above
  SecRequestBodyNoFilesLimit.
  Empty file-upload controls (filename="") are part of the trigger but are not used as
  a marker, because browsers send them for every optional file input left empty.
  The upload-progress and serialized-object markers also match the percent-encoded form
  that ModSecurity v2 writes to audit part I. The nested-key marker needs raw part C,
  and ModSecurity v3 logs no request body at all without part C.
  The upload-progress marker assumes the default session.upload_progress.name.
references:
  - https://www.php.net/archive/2026.php#2026-10-21-5
  - https://corelight.com/blog/php2shell-detection-before-disclosure
  - https://blog.cloudflare.com/php-vulnerabilities-waf-protection
  - https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/
  - https://github.com/owasp-modsecurity/ModSecurity/blob/41721c1b17146dfc5e14b55ecf01a076cedca0a9/apache2/msc_multipart.c
author: Mohammad Alattas
date: 2026-10-24
modified: 2026-10-25
tags:
  - attack.initial-access
  - attack.t1190
  - cve.2026-109618
  - cve.2026-109619
  - detection.emerging-threats
logsource:
  product: modsecurity
  definition: 'Requirements: ModSecurity audit log with part C (raw request body) in SecAuditLogParts; the recommended ABIJDEFHZ omits it. Field "message" holds the full audit record text and "cs-method" the request method.'
detection:
  selection_post:
    cs-method: 'POST'
  indicator_upload_progress:
    message|contains:
      - 'PHP_SESSION_UPLOAD_PROGRESS'
      - 'PHP%5fSESSION%5fUPLOAD%5fPROGRESS'
  indicator_nested_keys:
    message|re: '(\[[^\[\]"]{0,64}\]){8,}'
  indicator_session_object:
    message|contains:
      - '|O:'
      - '%7cO%3a'
  indicator_body_limit:
    message|contains:
      - 'Request body no files data length is larger than the configured limit'
      - 'Request body excluding files is bigger than the maximum expected'
  condition: selection_post and 1 of indicator_*
falsepositives:
  - Applications that use PHP upload progress tracking; allowlist their upload endpoints
  - Form frameworks that generate field names nested 8 or more levels deep
  - Legitimate forms that submit more non-file data than SecRequestBodyNoFilesLimit (128 KB in the recommended config)
level: high
```

I deliberately left out `filename=""`. Empty file-upload controls are part of the trigger, but every browser sends one for each optional file input a user leaves empty, so on its own it would page you all day.

This rule needs raw request bodies (ModSecurity audit log part C), and those include passwords and personal data from form posts, so restrict access to that log and keep retention short.

### 2.2 Memory exhaustion before any script runs

The CVE-2026-109618 primitive is an out-of-memory bailout forced inside PHP's multipart parser. That leaves a very specific error: `Allowed memory size of ... bytes exhausted`, reported `in Unknown on line 0` because no script was running yet. Debug builds also name `rfc1867.c`, the parser's source file. Ordinary memory errors inside application code name a real file and line, which is what keeps this rule quiet on a busy WordPress or Magento site.

```yaml
title: PHP2Shell Exploitation Attempt - PHP Memory Exhaustion During Request Parsing
status: experimental
description: |
  Detects a PHP "Allowed memory size ... exhausted" fatal error raised before any script
  runs ("in Unknown on line 0") or inside the multipart parser (rfc1867.c, which appears
  in debug builds). The CVE-2026-109618 primitive is an out-of-memory bailout forced
  inside rfc1867_post_handler(), so this error is the server-side fingerprint of an
  attempt. Nextron's SigmaHQ proposal keys on the same two strings.
  Ordinary memory_limit errors inside application code are left to the low-level
  building-block rule 266f9f0d-8d5e-4e23-9702-0de94a5ee90c.
references:
  - https://www.php.net/archive/2026.php#2026-10-21-5
  - https://github.com/corelight/php2shell-detect
  - https://www.nextron-systems.com/2026/10/22/php2shell-detection-coverage-in-thor/
author: Mohammad Alattas
date: 2026-10-24
modified: 2026-10-25
tags:
  - attack.initial-access
  - attack.t1190
  - cve.2026-109618
  - detection.emerging-threats
logsource:
  product: php
  service: error
  definition: 'Requirements: PHP error lines, from the PHP error_log or from the web server error log that receives them (Apache error_log with mod_php, nginx error.log via "FastCGI sent in stderr"). Field "message" holds the log line.'
detection:
  selection_oom:
    message|contains|all:
      - 'Allowed memory size of'
      - 'exhausted'
  selection_location:
    message|contains:
      - 'Unknown on line 0'
      - 'rfc1867.c'
  condition: all of selection_*
falsepositives:
  - Legitimate requests whose form or upload parsing exceeds memory_limit (rare; usually very large forms on sites with a low memory_limit)
level: high
```

### 2.3 The worker crash

Both CVEs are memory-corruption bugs, and attempts that miss tend to crash the worker. Where the crash shows up depends on the stack: the PHP-FPM master logs the child that died on a signal, Apache logs `AH00052` for a mod_php child, and the kernel logs a segfault for the process. Corruption caught by the allocator often ends in `SIGABRT` rather than a segfault, so the rule covers both. Every pattern is tied to PHP, PHP-FPM or Apache, so an nginx or PostgreSQL crash on the same box doesn't fire it.

```yaml
title: PHP2Shell Exploitation Attempt - PHP Worker Crash
status: experimental
description: |
  Detects PHP worker crashes: PHP-FPM children killed by SIGSEGV, SIGABRT or SIGBUS,
  Apache (mod_php) children exiting on the same signals (AH00052), kernel segfault
  reports for PHP or Apache processes, and Zend heap corruption errors.
  Both PHP2Shell CVEs are memory-corruption bugs, so a worker crashing right after
  anomalous multipart traffic is a strong exploitation indicator. Allocator-detected
  corruption often aborts (SIGABRT) instead of segfaulting.
  Every pattern is anchored to PHP-FPM, Apache or PHP process names, so crashes of
  unrelated software do not match.
references:
  - https://www.php.net/archive/2026.php#2026-10-21-5
  - https://corelight.com/blog/php2shell-detection-before-disclosure
  - https://github.com/php/php-src/blob/3472eda4cb0f193cd5792038fb040dceb8067fca/sapi/fpm/fpm/fpm_children.c
author: Mohammad Alattas
date: 2026-10-24
modified: 2026-10-25
tags:
  - attack.impact
  - attack.t1499
  - cve.2026-109618
  - cve.2026-109619
  - detection.emerging-threats
logsource:
  product: php
  service: worker_crash
  definition: 'Requirements: PHP-FPM master log, Apache error log (mod_php) and kernel log (dmesg or journald) from PHP web servers. Field "message" holds the log line.'
detection:
  selection_fpm_child:
    message|contains|all:
      - '] child '
      - ' exited on signal '
  selection_fpm_signal:
    message|contains:
      - 'signal 11 (SIGSEGV'
      - 'signal 6 (SIGABRT'
      - 'signal 7 (SIGBUS'
  selection_apache_child:
    message|contains: 'AH00052: child pid'
  selection_apache_signal:
    message|contains:
      - 'exit signal Segmentation fault (11)'
      - 'exit signal Aborted (6)'
      - 'exit signal Bus error (7)'
  selection_kernel_segfault:
    message|re: '(php|apache2|httpd|lsphp|frankenphp)[^ \[]*\[[0-9]+\]: segfault at '
  selection_zend_heap:
    message|contains: 'zend_mm_heap corrupted'
  condition: (selection_fpm_child and selection_fpm_signal) or (selection_apache_child and selection_apache_signal) or selection_kernel_segfault or selection_zend_heap
falsepositives:
  - Crashes caused by buggy PHP extensions or opcache issues; alert on bursts, or review alongside multipart anomalies on the same host
level: medium
```

One crash is a lead. A burst of them right after anomalous multipart traffic is an attempt.

### 2.4 Correlating the attempt

Each of these signals has an innocent explanation: upload-progress fields have legitimate uses, and memory errors happen. From the same client within ten minutes, they describe the trigger sequence; this is the SIEM-side version of Corelight's `PHP_Crash_Sequence` Zeek notice. The correlation pairs the multipart rule from 2.1 with a deliberately broad memory-exhaustion rule that exists mainly as its input:

```yaml
title: PHP Memory Exhaustion Fatal Error
status: experimental
description: |
  Matches any PHP memory_limit exhaustion fatal error. It is the building block for the
  PHP2Shell correlation rule d467b686-0240-4dd8-af7d-b077ffe6eb83. On its own it is
  common on busy WordPress or Magento sites, so it is rated low. The high-confidence
  variant is dc466ddb-387f-4689-b3b9-2df706fa1549.
references:
  - https://www.php.net/archive/2026.php#2026-10-21-5
author: Mohammad Alattas
date: 2026-10-25
tags:
  - attack.initial-access
  - attack.t1190
  - cve.2026-109618
  - detection.emerging-threats
logsource:
  product: php
  service: error
  definition: 'Requirements: PHP error lines, from the PHP error_log or from the web server error log that receives them. Field "message" holds the log line; the correlation rule expects the client IP in "client_ip".'
detection:
  selection:
    message|contains|all:
      - 'Allowed memory size of'
      - 'exhausted'
  condition: selection
falsepositives:
  - Undersized memory_limit on busy applications
level: low
```

```yaml
title: PHP2Shell - Multipart Anomaly and PHP Memory Exhaustion From Same Client
status: experimental
description: |
  Correlates a PHP2Shell-shaped multipart anomaly (b9096762-30f5-4ca1-a686-21616432e9b1)
  with a PHP memory-exhaustion fatal error (266f9f0d-8d5e-4e23-9702-0de94a5ee90c) from
  the same client within 10 minutes. This is the SIEM-side version of Corelight's
  PHP_Crash_Sequence notice: either event alone has an innocent explanation, but
  together they match the documented trigger behavior of CVE-2026-109618.
  The match is unordered on purpose. WAF audit records and PHP error lines are written
  at different moments, so an ordered sequence would drop real pairs (and the Splunk
  backend cannot convert temporal_ordered).
  The "client" alias maps each source's client IP field; adjust the alias values to your
  pipeline. If PHP errors only reach PHP-FPM's own log, which has no client IP, alias
  "client" to the server host name in both rules instead.
  generate is true so both referenced rules also alert on their own.
references:
  - https://corelight.com/blog/php2shell-detection-before-disclosure
  - https://www.php.net/archive/2026.php#2026-10-21-5
author: Mohammad Alattas
date: 2026-10-24
modified: 2026-10-25
tags:
  - attack.initial-access
  - attack.t1190
  - cve.2026-109618
  - cve.2026-109619
  - detection.emerging-threats
correlation:
  type: temporal
  rules:
    - b9096762-30f5-4ca1-a686-21616432e9b1
    - 266f9f0d-8d5e-4e23-9702-0de94a5ee90c
  aliases:
    client:
      b9096762-30f5-4ca1-a686-21616432e9b1: src_ip
      266f9f0d-8d5e-4e23-9702-0de94a5ee90c: client_ip
  group-by:
    - client
  timespan: 10m
  generate: true
falsepositives:
  - A client whose legitimate upload-progress request coincides with an unrelated memory_limit error on the same site
level: critical
```

The match is unordered on purpose: the two events come from different logs written on different schedules, and requiring an order would drop real pairs. The `client` alias maps each source's client IP field. PHP-FPM's own log has no client IP, so if that's where your PHP errors land, alias `client` to the server host name in both rules instead.

## Layer 3 (Behavior at Runtime): The Worker Spawns a Shell

Here's the part most web shell content skips, and it's the part that actually closes the gap. **Every rule so far watches the exposure or the attempt.** But a web shell's real purpose is to *run commands*, and running commands leaves evidence that has nothing to do with how the PHP was written or how the attacker got in.

This matters enormously for two cases:

- **Obfuscation we didn't anticipate**: a packer or encoding nobody has written a signature for.
- **Fileless shells**: a one-liner like `<?php system($_GET[0]);?>` injected through a Local File Inclusion or a poisoned log or session file, which may never land as a recognizable file on disk. PHP2Shell takes this further, because the attacker's code runs inside the worker straight from a crafted request.

In both cases the PHP is invisible to us. But the moment it executes, the web server process does something web server processes almost never do.

### 3.1 The behavioral smoking gun: the worker spawns a shell

A healthy `apache2` or `php-fpm` worker serves pages. It does **not**, as a rule, spawn `/bin/sh`, run `whoami`, or call `curl`. When it does, that's command execution through the web tier, and it fires regardless of obfuscation, because by this point the attacker's cleverly-encoded PHP has already decoded itself and is calling the OS in plain sight. Datadog Security Labs calls this event the most direct evidence of a successful PHP2Shell exploit.

This is the highest-value web shell detection you can deploy, and it's the logic behind SigmaHQ's own *Linux Webshell Indicators* rule. Three details make this version hold up in production:

- **The parents are the processes that actually run PHP**: Apache with mod_php, PHP-FPM, php-cgi, LiteSpeed's `lsphp` and FrankenPHP. nginx never runs PHP itself; behind nginx, the shell's parent is the PHP-FPM worker.
- **Interpreters are matched with `contains`.** Linux telemetry usually records the resolved binary, so `python3` arrives as `python3.12` and `nc` as `nc.openbsd`. A rule that matches names ending in `/python3` never sees them.
- **PHP's `mail()` is filtered out, carefully.** On Linux, `mail()` runs `sh -c /usr/sbin/sendmail -t -i` through `popen()`, so every WordPress email looks like a worker spawning a shell. The filter drops that call only when the command line has no shell metacharacters, so `sendmail -t -i; id` still fires.

```yaml
title: PHP2Shell Exploitation Success - Shell Spawned by PHP Web Worker
status: experimental
description: |
  Detects a web server or PHP worker process (Apache mod_php, PHP-FPM, php-cgi,
  LiteSpeed lsphp, FrankenPHP) spawning a shell, interpreter or download/network tool.
  PHP2Shell (CVE-2026-109618 / CVE-2026-109619) gives code execution as the web worker,
  and shell-based post-exploitation shows up here however the HTTP payload was
  obfuscated or encrypted; Datadog Security Labs calls a worker spawning a shell the most
  direct evidence of successful exploitation.
  Payloads that stay inside PHP (dropping a .php file, reading config files, PHP-native
  sockets) spawn no child process. Pair this rule with the hunting rules for PHP worker
  children and PHP file writes.
  Interpreters are matched with "contains" because Linux telemetry usually records the
  resolved binary (python3 becomes python3.12, nc becomes nc.openbsd).
  PHP mail() runs "sh -c <sendmail_path>" through popen(). That call is excluded unless
  its command line contains shell metacharacters.
references:
  - https://www.php.net/archive/2026.php#2026-10-21-5
  - https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/
  - https://www.sygnia.co/threat-reports-and-advisories/php2shell-two-critical-php-vulnerabilities-expose-web-servers-to-remote-code-execution/
  - https://github.com/php/php-src/blob/3472eda4cb0f193cd5792038fb040dceb8067fca/ext/standard/mail.c
author: Mohammad Alattas
date: 2026-10-24
modified: 2026-10-25
tags:
  - attack.execution
  - attack.t1059.004
  - cve.2026-109618
  - cve.2026-109619
  - detection.emerging-threats
logsource:
  category: process_creation
  product: linux
detection:
  selection_parent:
    ParentImage|contains:
      - '/httpd'
      - '/apache2'
      - '/php-fpm'
      - '/php-cgi'
      - '/lsphp'
      - '/frankenphp'
  selection_child_shell_tool:
    Image|endswith:
      - '/sh'
      - '/bash'
      - '/dash'
      - '/zsh'
      - '/ksh'
      - '/busybox'
      - '/curl'
      - '/wget'
      - '/nc'
      - '/nc.openbsd'
      - '/nc.traditional'
      - '/ncat'
      - '/netcat'
      - '/socat'
      - '/php'
      - '/php7.4'
      - '/php8.0'
      - '/php8.1'
      - '/php8.2'
      - '/php8.3'
      - '/php8.4'
      - '/php8.5'
  selection_child_interpreter:
    Image|contains:
      - '/python'
      - '/perl'
      - '/ruby'
  filter_main_php_mail:
    CommandLine|contains:
      - '/sendmail -t'
      - '/msmtp -t'
  mail_cmdline_tampered:
    CommandLine|contains:
      - ';'
      - '|'
      - '&'
      - '`'
      - '$('
      - '>'
      - '<'
  condition: selection_parent and 1 of selection_child_* and not (filter_main_php_mail and not mail_cmdline_tampered)
falsepositives:
  - Web applications that shell out by design (ImageMagick wrappers, backup or deployment tools); baseline per host and add filter_optional entries
  - Perl or Python CGI scripts served by Apache (parent httpd or apache2)
  - A custom sendmail_path other than sendmail or msmtp
level: high
```

The false positives here are real but *finite and learnable*: a given app shells out to a small, fixed set of binaries. Baseline that set over a week, add a `filter` block for it, and everything left over is worth waking someone up for.

### 3.2 The same signal on Windows

On Windows, PHP runs as `php-cgi.exe` under IIS FastCGI or nginx, inside `httpd.exe` with mod_php on XAMPP-style stacks, or as `php.exe`. The vulnerable code is in PHP core, which Windows builds share, but public reproductions so far target Linux, so treat Windows exploitability as unconfirmed. The child list covers shells, script hosts and the LOLBins attackers reach for first, including `whoami.exe` started directly through `proc_open()` with no shell in between.

```yaml
status: experimental
description: |
  Detects PHP on Windows (php-cgi.exe under IIS FastCGI or nginx, php.exe, or Apache
  httpd.exe with mod_php) spawning a command shell, script host or LOLBin.
  The PHP2Shell bugs are in PHP core code that Windows builds share, but public
  reproductions so far target Linux (mod_php and PHP-FPM), so treat Windows
  exploitability as unconfirmed. A successful exploit runs commands as the web worker
  account, so the process tree is visible however the HTTP payload was obfuscated.
references:
  - https://www.php.net/archive/2026.php#2026-10-21-5
  - https://www.sygnia.co/threat-reports-and-advisories/php2shell-two-critical-php-vulnerabilities-expose-web-servers-to-remote-code-execution/
author: Mohammad Alattas
date: 2026-10-24
modified: 2026-10-25
tags:
  - attack.execution
  - attack.t1059.003
  - cve.2026-109618
  - cve.2026-109619
  - detection.emerging-threats
logsource:
  category: process_creation
  product: windows
detection:
  selection_parent:
    ParentImage|endswith:
      - '\php-cgi.exe'
      - '\php.exe'
      - '\httpd.exe'
  selection_child:
    Image|endswith:
      - '\cmd.exe'
      - '\powershell.exe'
      - '\pwsh.exe'
      - '\curl.exe'
      - '\wget.exe'
      - '\certutil.exe'
      - '\bitsadmin.exe'
      - '\wscript.exe'
      - '\cscript.exe'
      - '\mshta.exe'
      - '\rundll32.exe'
      - '\regsvr32.exe'
      - '\whoami.exe'
  condition: all of selection_*
falsepositives:
  - PHP applications that call system() or exec() by design; baseline per host
  - Command-line php.exe jobs (Composer, scheduled-task scripts) that run shell commands
level: high
```

## Layer 4 (Hunting): What Never Spawns a Shell

Layer 3 has a blind spot, and an attacker with code execution inside PHP doesn't have to walk into it. They can stay in PHP: write a web shell to disk, plant an `.htaccess` or `.user.ini` directive for persistence, read `wp-config.php`, or open a socket from PHP itself. None of that starts a process. Or they can start something the fixed child list doesn't name: `proc_open()` with an argument array runs `id` directly with no shell, and a binary executed from memory has no recognizable name at all.

The two hunts below cover the file writes and the unnamed processes. Reading `wp-config.php` or opening a socket from PHP leaves neither a process nor a file, so catching those takes network or application logs. The hunts return everything and leave the judgment to you, so run them as hunts rather than alerts, and run them back to 17 October, not to the disclosure date.

### 4.1 Every child of a PHP worker

Instead of naming the bad children, return all of them, minus known noise (PHP `mail()` calls on Linux; Apache's own worker, FastCGI `php-cgi.exe` processes and console hosts on Windows), and stack them: count by parent, image and command line. On a typical server the list is short and boring; anything you see once is where to start.

```yaml
title: Child Processes of PHP Web Workers - Linux
status: experimental
description: |
  Hunting rule. Returns every process started by a web server or PHP worker (Apache,
  PHP-FPM, php-cgi, LiteSpeed lsphp, FrankenPHP), except PHP mail() calls to sendmail or
  msmtp. Stack the results by parent, image and command line and review the rare ones.
  This catches what the PHP2Shell detection rule's fixed child list misses: direct execs
  through proc_open() with an argument array (id, uname), renamed binaries and memfd
  executions. Hunt back to 2026-10-17, the earliest exploitation attempt reported by
  Amazon Threat Intelligence.
references:
  - https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/
  - https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/
author: Mohammad Alattas
date: 2026-10-25
tags:
  - attack.execution
  - attack.t1059.004
  - attack.persistence
  - attack.t1505.003
  - detection.threat-hunting
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    ParentImage|contains:
      - '/httpd'
      - '/apache2'
      - '/php-fpm'
      - '/php-cgi'
      - '/lsphp'
      - '/frankenphp'
  filter_main_php_mail:
    CommandLine|contains:
      - '/sendmail -t'
      - '/msmtp -t'
  mail_cmdline_tampered:
    CommandLine|contains:
      - ';'
      - '|'
      - '&'
      - '`'
      - '$('
      - '>'
      - '<'
  condition: selection and not (filter_main_php_mail and not mail_cmdline_tampered)
falsepositives:
  - Expected by design; the rule returns all worker children for stacking and baselining
level: low
```

```yaml
title: Child Processes of PHP Web Workers - Windows
status: experimental
description: |
  Hunting rule. Returns every process started by PHP on Windows (php-cgi.exe, php.exe
  or Apache httpd.exe), except Apache's own worker, FastCGI php-cgi.exe processes and
  console hosts. Stack the results by parent, image and command line and review the
  rare ones. This catches direct execs, renamed binaries and tools that the PHP2Shell
  detection rule's fixed child list does not name.
references:
  - https://aws.amazon.com/blogs/security/amazon-threat-intelligence-identifies-php2shell-exploitation-prior-to-public-disclosure-in-madpot/
  - https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/
author: Mohammad Alattas
date: 2026-10-25
tags:
  - attack.execution
  - attack.t1059.003
  - attack.persistence
  - attack.t1505.003
  - detection.threat-hunting
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    ParentImage|endswith:
      - '\php-cgi.exe'
      - '\php.exe'
      - '\httpd.exe'
  filter_main_php_runtime:
    Image|endswith:
      - '\httpd.exe'
      - '\php-cgi.exe'
      - '\conhost.exe'
  condition: selection and not 1 of filter_main_*
falsepositives:
  - Expected by design; the rule returns all worker children for stacking and baselining
level: low
```

### 4.2 Files the worker has no business writing

The other half of staying inside PHP is the file write. A worker creating a `.php` file in an uploads folder, or an `.htaccess` or `.user.ini` that can switch on PHP execution or prepend code to every request, is how a short-lived exploit becomes a persistent web shell. Framework caches that compile templates to PHP (Laravel's `storage/framework/views`, Smarty's `templates_c`, WordPress caches) are excluded as optional filters. CMS updates installed from the admin panel will still show up, so compare hits against your change windows.

```yaml
title: PHP or Web Config File Written by PHP Web Worker - Linux
status: experimental
description: |
  Hunting rule. A web server or PHP worker creates a PHP file, a .htaccess file or a
  .user.ini file. After PHP2Shell code execution an attacker can stay inside PHP and
  drop a web shell, or plant .htaccess or .user.ini directives (auto_prepend_file, for
  example) for persistence, without starting any process.
  Framework template and cache directories are excluded as optional filters. CMS updates
  installed from the admin panel (WordPress plugins and themes) also write PHP files as
  the worker; compare results against your change windows.
references:
  - https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/
  - https://www.php.net/manual/en/configuration.file.per-user.php
author: Mohammad Alattas
date: 2026-10-25
tags:
  - attack.persistence
  - attack.t1505.003
  - detection.threat-hunting
logsource:
  category: file_event
  product: linux
detection:
  selection_writer:
    Image|contains:
      - '/httpd'
      - '/apache2'
      - '/php-fpm'
      - '/php-cgi'
      - '/lsphp'
      - '/frankenphp'
  selection_target_code:
    TargetFilename|endswith:
      - '.php'
      - '.phtml'
      - '.phar'
      - '.php5'
      - '.php7'
      - '.pht'
  selection_target_config:
    TargetFilename|endswith:
      - '/.htaccess'
      - '/.user.ini'
  filter_optional_framework_cache:
    TargetFilename|contains:
      - '/storage/framework/views/'
      - '/bootstrap/cache/'
      - '/var/cache/'
      - '/templates_c/'
      - '/wp-content/cache/'
      - '/wp-content/upgrade/'
  condition: selection_writer and 1 of selection_target_* and not 1 of filter_optional_*
falsepositives:
  - CMS core, plugin and theme updates installed through the web admin panel
  - Applications that generate PHP files at runtime outside the filtered cache paths
level: low
```

```yaml
title: PHP or Web Config File Written by PHP Web Worker - Windows
status: experimental
description: |
  Hunting rule. PHP on Windows (php-cgi.exe or Apache httpd.exe) creates a PHP file, a
  .htaccess file or a .user.ini file, which is how an attacker who stays inside PHP
  drops a web shell or plants persistence directives. php.exe is left out because
  Composer and other command-line jobs write PHP files constantly.
  Framework template and cache directories are excluded as optional filters. CMS updates
  installed from the admin panel also write PHP files as the worker; compare results
  against your change windows.
references:
  - https://securitylabs.datadoghq.com/articles/php2shell-critical-vulnerabilities-in-php/
  - https://www.php.net/manual/en/configuration.file.per-user.php
author: Mohammad Alattas
date: 2026-10-25
tags:
  - attack.persistence
  - attack.t1505.003
  - detection.threat-hunting
logsource:
  category: file_event
  product: windows
detection:
  selection_writer:
    Image|endswith:
      - '\php-cgi.exe'
      - '\httpd.exe'
  selection_target_code:
    TargetFilename|endswith:
      - '.php'
      - '.phtml'
      - '.phar'
      - '.php5'
      - '.php7'
      - '.pht'
  selection_target_config:
    TargetFilename|endswith:
      - '\.htaccess'
      - '\.user.ini'
  filter_optional_framework_cache:
    TargetFilename|contains:
      - '\storage\framework\views\'
      - '\bootstrap\cache\'
      - '\var\cache\'
      - '\templates_c\'
      - '\wp-content\cache\'
      - '\wp-content\upgrade\'
  condition: selection_writer and 1 of selection_target_* and not 1 of filter_optional_*
falsepositives:
  - CMS core, plugin and theme updates installed through the web admin panel
  - Applications that generate PHP files at runtime outside the filtered cache paths
level: low
```

## Correlation: Closing the Loop

Any one of these rules in isolation produces leads. The payoff is correlating them into a timeline, which turns "an alert fired" into "here's exactly what happened." This is the archaeology.

A clean hunt reads a single event backwards through the layers:

1. **Behavioral hit (3.1).** `php-fpm` spawned `/bin/sh` at `14:07:12`. That's your anchor, and once tuned it's almost never a false positive.
2. **Pivot to the attempt (Layer 2).** Look for a multipart anomaly, a memory error or a worker crash on that host in the minutes before `14:07`; the correlation rule (2.4) may already have paired them. The audit record gives you the source IP, the User-Agent and the request that carried the exploit.
3. **Pivot to the file (4.2).** Did the worker write a `.php`, `.htaccess` or `.user.ini` file around `14:07`? A new PHP file owned by `www-data` in an uploads directory is your shell, and the attacker's way back in after you patch.
4. **Pivot to everything else the worker ran (4.1).** Stack the worker's children for the window. That's the attacker's tooling, and any outbound connection those processes made is your C2 and your next set of indicators to block and hunt.

In four pivots you've gone from one process event to: the exploit request, the attacker's IP, the dropped shell, and their tooling. None of it depended on recognizing the *name* of the shell, which is the entire point.

## MITRE ATT&CK Mapping

| Tactic | Technique | ID | Detection surface |
|--------|-----------|-----|-------------------|
| Initial Access | Exploit Public-Facing Application | T1190 | Vulnerable PHP version (Layer 1); multipart anomalies, memory exhaustion and their correlation (2.1, 2.2, 2.4) |
| Impact | Endpoint Denial of Service | T1499 | PHP worker crash (2.3) |
| Execution | Command and Scripting Interpreter: Unix Shell | T1059.004 | Worker spawns a shell or tool on Linux (3.1, 4.1) |
| Execution | Command and Scripting Interpreter: Windows Command Shell | T1059.003 | Worker spawns a shell or LOLBin on Windows (3.2, 4.1) |
| Persistence | Server Software Component: Web Shell | T1505.003 | PHP, `.htaccess` or `.user.ini` file written by the worker (4.2); worker children (4.1) |

## Summary
 
If there's one idea to take from this, it's the shift in what you point your detection *at*.
 
Hash and string signatures detect a specific shell. They are built on the things the attacker controls (the file bytes, the variable names, the banner), so the attacker defeats them for free, every time, by changing those things. That's why the "top 10 web shell signatures" post is obsolete before you finish reading it.
 
The durable detections target what the attacker **cannot** change:
 
- The memory error and worker crash the bugs themselves produce (**attempt Sigma**).
- The simple, damning fact that a web server process spawned a shell (**behavioral Sigma**).
- Every process the worker starts, and every file it has no business writing (**hunting Sigma**).

Rename every variable, stack five encoders, go fully fileless: the decoded payload still has to call the OS or write a file to do anything lasting, and the web server still has to light up a child process or a file event. That event is the one the operator can't obfuscate away, and it's the one that lets us finally cross from *"we identified that sample"* to *"we'll catch the next one."*

Use the exposure rule to build your patch list, and patch first: none of this fixes the bug. Then deploy the `process_creation` rules as your paging alerts and the attempt rules and their correlation as early warning, run the hunting rules back to 17 October, and wire the four-step correlation into your playbook. Then the next shell, the one nobody's written a signature for yet, walks into a net that was never looking for its name.
 
---
 
### References

- PHP: security releases 8.5.12, 8.4.27, 8.3.36 and 8.2.35 for CVE-2026-109618 and CVE-2026-109619 (php.net news archive, 21 October 2026)
- Amazon Threat Intelligence: PHP2Shell exploitation observed in MadPot before public disclosure
- Datadog Security Labs: PHP2Shell analysis, exploit reproduction and detection guidance
- Corelight: PHP2Shell detection before disclosure, and the `php2shell-detect` Zeek and Suricata package
- Nextron Systems: *PHP2SHELL Detection Coverage in THOR*, and SigmaHQ pull request #6506
- Sygnia: PHP2Shell advisory
- OWASP ModSecurity: recommended configuration (`SecAuditLogParts`) and `msc_multipart.c` (audit log part I)
- NSA / CISA: *Detect and Prevent Web Shell Malware* (CSI, 2020)
- SigmaHQ: *Linux Webshell Indicators* (`proc_creation_lnx_webshell_detection`), Florian Roth & Nasreddine Bencherchali, Nextron Systems
- SigmaHQ: *Suspicious Process By Web Server Process* (`proc_creation_win_webshell_susp_process_spawned_from_webserver`)
- php-malware-finder (jvoisin): semantic YARA-based PHP malware/web shell detection
- MITRE ATT&CK: T1190 (Exploit Public-Facing Application), T1499 (Endpoint Denial of Service), T1059.004 (Unix Shell), T1059.003 (Windows Command Shell), T1505.003 (Web Shell)
