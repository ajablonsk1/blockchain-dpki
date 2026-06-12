# Notatki do rozdziału 8 — Ocena systemu

Surowe dane: `results/20260612_095627/` (JSON + środowisko). Wykresy:
`results/20260612_095627/charts/` (generowane `scripts/plot-results.py`).

## 8.1 Środowisko testowe

Z `environment.txt`: Apple M2 Max, 32 GB RAM, macOS (Darwin 25.5.0),
Go 1.26.3, CometBFT v0.38.23. Testnet: 4 walidatorów jako procesy lokalne
(Faza 6), block interval ~1 s (timeout_commit domyślny), weryfikacja DNS
wyłączona (`--no-verify`) — mierzona jest ścieżka konsensusu i stanu, nie
zewnętrzny DNS. **Zastrzeżenie:** localhost = zerowe opóźnienia sieciowe;
liczby są dolnym ograniczeniem latencji i górnym przepustowości dla danego
sprzętu; relacje (liniowość, log N) pozostają w mocy.

Metodyka: warmup 15 s przed pomiarami; przepustowość liczona z transakcji
faktycznie zatwierdzonych w blokach (span timestampów bloków), nie z tempa
wysyłania; mempool drenowany między seriami.

## 8.2 Przepustowość

Po 15 s obciążenia na każde tempo; RegisterTx (~150 B), wysyłka
`broadcast_tx_sync` z 8 współbieżnych nadawców; „osiągnięte" = transakcje
zatwierdzone w blokach / span timestampów bloków:

| zadane [tx/s] | wysłane | odrzucone (CheckTx) | zatwierdzone | osiągnięte [tx/s] | śr. tx/blok | max tx/blok |
|---|---|---|---|---|---|---|
| 25 | 375 | 0 | 375 | 25,9 | 31 | 37 |
| 50 | 750 | 0 | 750 | 51,5 | 62 | 70 |
| 100 | 1 500 | 0 | 1 500 | 104,1 | 125 | 140 |
| 200 | 2 999 | 0 | 2 999 | 188,9 | 231 | 298 |
| 400 | 5 987 | 0 | 5 987 | 385,6 | 461 | 568 |
| 800 | 11 879 | 0 | 11 879 | 758,0 | 914 | 1 195 |
| 1 600 | 23 417 | 0 | 23 417 | 1 588,3 | 1 951 | 4 003 |

Skalowanie **liniowe w całym mierzonym zakresie** — nasycenia nie osiągnięto
do 1 600 tx/s na tym sprzęcie; każda transakcja zatwierdzona, zero odrzuceń.
Bloki rosną proporcjonalnie do obciążenia (system absorbuje burst w większych
blokach zamiast wydłużać kolejkę). Spodziewane pierwsze ograniczenie powyżej:
rozmiar mempoola (domyślnie 5 000 tx) przy dłuższych burstach. Dla kontekstu
PKI: 1 588 tx/s ≈ 137 mln operacji na dobę — rzędy wielkości ponad globalne
tempo wystawiania certyfikatów TLS (Let's Encrypt ≈ 4–5 mln/dobę).

Wykresy: `charts/throughput.{png,svg}`, `charts/block-fill.{png,svg}`.

## 8.3 Latencja zatwierdzenia

100 transakcji sekwencyjnie (`broadcast_tx_commit`), przerwa 500 ms:

| metryka | wartość |
|---|---|
| średnia | 825 ms |
| p50 | 813 ms |
| p95 | 920 ms |
| p99 | 950 ms |
| min / max | 784 / 1024 ms |

Latencja jest zdominowana przez interwał bloku (~1 s): transakcja czeka
średnio pół interwału na propozycję + czas finalizacji rund konsensusu.
Rozrzut p99−p50 ≈ 140 ms — system jest przewidywalny. Wniosek do porównania
z PKI: wystawienie i unieważnienie certyfikatu finalizuje się w ~1 s,
deterministycznie. Wykres: `charts/latency.{png,svg}`.

## 8.4 Koszty stanu

Wstawianie domen partiami po 10 000 (in-process, `MemoryStore`):

| domeny | magazyn | kluczy w KV | B/domenę | µs/insert |
|---|---|---|---|---|
| 10 000 | 156 MB | 2,4 mln | ~16,3 k | ~190 |
| 50 000 | 776 MB | 12,1 mln | ~16,3 k | ~180 |
| 100 000 | 1 546 MB | 24,1 mln | ~16,2 k | ~185 |

Wzrost **liniowy** (R² ≈ 1; wykres `charts/state-growth.{png,svg}`), czas
wstawienia **stały** względem N (~180–240 µs — 256 hashy ścieżki SMT).

Uczciwa analiza kosztu stałego: ~16 kB/domenę to nie certyfikat (≈150 B),
lecz ~241 węzłów wewnętrznych ścieżki SMT po 64 B w naiwnym magazynie
węzeł-po-węźle. Produkcyjne implementacje SMT kompresują ścieżki (extension
nodes, jak w Jellyfish Merkle Tree / Ethereum MPT) — wskazać jako future work;
nie zmienia asymptotyki O(N), zmienia stałą ~50–100×.

## 8.5 Proofy Merkle

Próbkowanie 200 losowych proofów na rozmiar drzewa:

| N domen | proof inkluzji (śr.) | siblings (śr.) | nie-inkluzja (śr.) | weryfikacja |
|---|---|---|---|---|
| 1 000 | 466 B | 10,3 | 392 B | 27,5 µs |
| 10 000 | 572 B | 13,6 | 492 B | 27,8 µs |
| 100 000 | 677 B | 16,9 | 605 B | 28,0 µs |

Rozmiar rośnie jak **O(log₂ N)** (10,3 ≈ log₂ 1000, 16,9 ≈ log₂ 100000 —
kompresja bitmapą pomija domyślne hashe), weryfikacja w czasie **stałym**
~28 µs. Ekstrapolacja: przy 10⁹ domen proof ≈ 30 siblingów ≈ 1,1 kB — wciąż
mniej niż typowy łańcuch certyfikatów X.509 (2–6 kB). Wykresy:
`charts/proof-size.{png,svg}`, `charts/proof-verify-time.{png,svg}`.

## 8.6 Porównanie z klasyczną PKI

| Kryterium | Klasyczna PKI (X.509 + CA) | DPKI (ta praca, zmierzono) |
|---|---|---|
| Czas wystawienia | minuty–dni (proces CA) | p50 = 0,81 s (następny blok) |
| Propagacja rewokacji | godziny–dni (CRL/OCSP, soft-fail) | p50 = 0,81 s, trwała |
| Dowód ważności | łańcuch certów 2–6 kB + OCSP online | proof 0,5–0,7 kB, offline |
| Czas weryfikacji | ~ms (łańcuch podpisów) | 28 µs (proof) + podpis |
| Pojedynczy punkt awarii | CA (wystawianie i rewokacja) | brak ≤ f awarii; halt < 2/3 |
| Zapytanie o nieistnienie | niemożliwe (brak dowodu negatywnego) | proof nie-inkluzji ~0,5 kB |
| Koszt infrastruktury weryfikatora | dostęp do OCSP/CRL online | zaufany app hash + matematyka |

## 8.7 Skalowalność — analiza i ograniczenia

- **Konsensus:** komunikacja O(n²) między walidatorami — praktyczny sufit
  ~100–200 walidatorów (znane ograniczenie CometBFT); przepustowość nie
  rośnie z liczbą walidatorów, spada z opóźnieniem sieci.
- **Stan:** O(N) bez ograniczenia górnego; rewokowane wpisy muszą zostać
  (trwałość rewokacji, T13) — pruning niemożliwy bez zmiany modelu
  bezpieczeństwa. Mitygacje (future work): kompresja ścieżek SMT, sharding po
  TLD, state sync ze snapshotami.
- **Klienci lekcy:** proof O(log N) + nagłówek — koszt klienta praktycznie
  stały; brakuje weryfikacji podpisów walidatorów (pełny light client, ADR 020).
- **Replay przy restarcie:** O(wysokość łańcucha) — akceptowalne dla testnetu,
  produkcja wymaga trwałego KVStore (ADR 023).

## 8.8 Dyskusja

Teza empiryczna rozdziału: system osiąga przepustowość i latencję o rzędy
wielkości lepsze niż procesy klasycznej PKI tam, gdzie to się liczy
(rewokacja!), kosztem stałego narzutu pamięciowego na domenę i ograniczeń
skali zbioru walidatorów — koszt zamiany zaufanej trzeciej strony na
replikowaną maszynę stanów.
