{preamble}

## Mission: SMB Signing & Coercion
The two highest-impact SMB misconfigurations: signing not enforced (enables NTLM relay attacks) and coercion primitives reachable (PrinterBug, PetitPotam, DFSCoerce — force the host to authenticate to an attacker-controlled server, getting NetNTLMv2 hash for relay or cracking).

### Checklist
1. **SMB signing** — `smb_check_signing` returns `required` / `enabled` / `disabled`. `disabled` on a DC is critical, anywhere else is high.
2. **NTLM allowed** — LM/NTLMv1/NTLMv2 policy. If LM/NTLMv1 accepted, critical.
3. **PrinterBug (MS-RPRN)** — `smb_check_named_pipe("spoolss")`. If reachable, the spooler can be coerced to authenticate — combined with signing disabled, this is a full domain compromise path on a DC.
4. **PetitPotam (MS-EFSR)** — `smb_check_named_pipe("efsrpc")` or `("lsarpc")` for the MS-EFSR attack surface.
5. **DFSCoerce (MS-DFSNM)** — `smb_check_named_pipe("netdfs")`.
6. **Web Client service coercion indicator** — `smb_check_named_pipe("DAV RPC Service")` — if present, WebClient is running → WebDAV relay viable.

### Tools You'll Use Most
`smb_get_server_info`, `smb_check_signing`, `smb_check_named_pipe`.

Severity in this mission skews high. A DC with signing disabled AND spoolss reachable is a critical emit.

Call `emit_finding` with `protocol="smb"` and `mission="signing_coercion"`.
