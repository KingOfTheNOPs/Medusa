+++
title = "execute_coff"
chapter = false
weight = 100
hidden = false
+++

## Summary

Executes a trusted AMD64 Beacon Object File in the Medusa process.

- Python version: 3.8
- OS: Windows x64
- Admin required: No
- Entrypoint: `go` by default

### Arguments

- `bof_file`: a newly uploaded, one-shot `.x64.o` BOF.
- `coff_name`: an object previously cached with `register_coff`.
- `function_name`: exported BOF function, normally `go`.
- `coff_arguments`: ordered `int16`, `int32`, `string`, `wchar`, or `base64` values.

For example, `dir.x64.o` uses `string:C:\Windows int16:0`.

### Staged loading

The initial payload does not need these commands or the native helper. Include
Medusa's small `load` command, then task `load register_coff` and
`load execute_coff` when BOF support is required. Optional `list_coffs` and
`unregister_coff` commands manage the persistent memory cache. `unload` removes
the Python command modules again; the helper DLL is unloaded after every run.

## Safety and observability

The native COFF is validated and run from memory with writable relocation pages
changed to read-only or execute-read before the entrypoint runs. Sizes, symbols,
strings, relocations, and output are capped at 2 MiB. Missing entry points/imports,
auxiliary-symbol references, unsafe DLL names, unknown relocations, inconsistent
argument lengths, and unsupported Beacon APIs fail closed. Dynamic function
references load only from System32. Spawn and injection Beacon APIs are deliberately
rejected; token impersonation is reverted during cleanup.

The integrity-pinned helper is manually mapped from memory, including imports,
unwind metadata, TLS, final page protections, and attach/detach callbacks. It never
needs an image path or transient DLL in `%TEMP%`. BOFs can still invoke arbitrary
Win32 APIs, and a native fault can terminate the Python process, so treat BOFs as
trusted code.

Apollo and Ditto do not attach a browser script to their COFF execution/register
commands. Apollo does use a browser script for its persistent registered-file
list. Medusa mirrors that behavior with `list_coffs`, including a button that
tasks `unregister_coff` to zero and remove a cached object.

## Compatibility validated

Validated against TrustedSec CS-Situational-Awareness-BOF AMD64 objects including
`whoami`, `hostname`, `arp`, `env`, `ipconfig`, `netstat`, `routeprint`, `uptime`,
`listdns`, `windowlist`, `driversigs`, `enumlocalsessions`, `list_firewall_rules`,
typed-argument `dir`, and a separately compiled clang-cl/MSVC-ABI object.
