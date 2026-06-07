# Diagramy

## `state-architecture.svg` — architektura pakietu `internal/state`

Warstwy uwierzytelnionego magazynu stanu DPKI. SMT jest scalony w
`internal/state` (decyzja ADR 007), a nie wydzielony do osobnego pakietu —
diagram odzwierciedla stan faktyczny kodu.

```
┌────────────────────────────────────────────────────┐
│                  internal/state                     │
│  ┌──────────────────────────────────────────────┐  │
│  │  Domain layer — domain.go                     │  │
│  │  SetDomain / GetDomain / DeleteDomain         │  │
│  │  ProveDomain / VerifyDomainProof              │  │
│  └───────────────────────┬──────────────────────┘  │
│                          │                          │
│  ┌───────────────────────▼──────────────────────┐  │
│  │  SMT — smt.go + proof.go                      │  │
│  │  Set / Get / Delete / Root                    │  │
│  │  Prove / VerifyProof (inclusion + non-incl.)  │  │
│  └───────────────────────┬──────────────────────┘  │
│                          │                          │
│  ┌───────────────────────▼──────────────────────┐  │
│  │  KVStore — kvstore.go                         │  │
│  │  Get / Set / Delete / Close                   │  │
│  └───────────────────────┬──────────────────────┘  │
│              ┌───────────┴───────────┐              │
│  ┌───────────▼─────────┐ ┌───────────▼───────────┐  │
│  │  MemoryStore        │ │  BadgerDB / Pebble    │  │
│  │  (memstore.go)      │ │  (future, ADR 006)    │  │
│  └─────────────────────┘ └───────────────────────┘  │
└────────────────────────────────────────────────────┘
```

Źródło wektorowe: `state-architecture.svg`. Aby osadzić w pracy (LaTeX), można
zaimportować SVG bezpośrednio (`\includesvg`) lub wyeksportować do PDF:

```sh
# wymaga rsvg-convert (librsvg) lub inkscape
rsvg-convert -f pdf -o state-architecture.pdf state-architecture.svg
# albo
inkscape state-architecture.svg --export-type=pdf
```
