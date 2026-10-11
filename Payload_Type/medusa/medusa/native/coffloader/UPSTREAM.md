# COFFLoader provenance

The native loader and Beacon compatibility layer were ported from
TrustedSec COFFLoader commit `edfa7639a137bee639e535732a1aa67cc2b33549`.

Medusa-specific changes add strict COFF/argument/output bounds, safe symbol
handling, W^X memory protections, output lifecycle exports, cleanup-time token
reversion, and no-op spawn/injection compatibility functions. The upstream
license is retained in `LICENSE.txt`.

The checked-in `coffloader.x64.dll` targets AMD64 Windows and is built with
MinGW-w64 via `scripts/build_coffloader.ps1`.
