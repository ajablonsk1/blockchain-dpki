# ADR 006: KVStore abstraction with an in-memory default backend

## Status
Accepted

## Context
The authenticated state store (`internal/state`) must persist tree nodes and
domain values. The thesis prototype needs to run, be benchmarked, and be tested
deterministically, but does not yet need production-grade durability. Three
backend options were considered:

| Option | Pros | Cons |
|---|---|---|
| In-memory (`map[string][]byte`) | Simplest, instant setup, ideal for tests | No persistence; restart loses state |
| BadgerDB | Embedded KV store, fast, ACID, snapshots | Heavier dependency, lifecycle to manage |
| PebbleDB | Very fast LevelDB successor (CockroachDB) | Smaller community than Badger |

The state tree must not depend on any one of these directly: the choice of
backend is an operational concern, not a correctness concern.

## Decision
Define a minimal `KVStore` interface (`Get`, `Set`, `Delete`, `Close`) and
implement it first with an in-memory `MemoryStore`. The SMT depends only on the
interface, so a disk-backed implementation (BadgerDB is the intended first
choice) can be added later by writing one new type and changing one construction
site — tree logic and tests are untouched. Tests keep using `MemoryStore` for
speed and determinism.

`MemoryStore` copies keys and values on the way in and out so callers cannot
corrupt stored data through retained slices, and it is guarded by an `RWMutex`.

The interface deliberately **omits an iterator** for now. The SMT addresses every
node by an exact key (depth + masked path) and never scans ranges, so an iterator
would be dead code. It will be added when a feature that needs ordered traversal
appears (state export for genesis, state-sync between nodes).

## Consequences
- **Positive:** no storage dependency in the core module yet; the prototype
  builds and tests with zero external services.
- **Positive:** swapping to BadgerDB/Pebble is a localized change behind a stable
  interface.
- **Negative:** the in-memory backend has no durability; a node restart rebuilds
  state from the block history (acceptable for the prototype, must be revisited
  before any long-running deployment).
- **Negative:** the copy-in/copy-out discipline in `MemoryStore` costs
  allocations; this is a fair price for safety in a non-production backend and
  does not affect the interface.
