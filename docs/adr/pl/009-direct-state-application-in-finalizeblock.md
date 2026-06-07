# ADR 009: Bezpośrednia aplikacja stanu w FinalizeBlock (bez kopii roboczej)

## Status
Zaakceptowany

## Kontekst
ABCI dzieli wykonanie bloku na `FinalizeBlock` (wykonaj transakcje, zwróć app
hash) i `Commit` (utrwal). Typowym wzorcem jest aplikowanie transakcji na *kopii
roboczej* stanu w `FinalizeBlock` i awansowanie jej do stanu kanonicznego
dopiero w `Commit`, tak aby blok, który zostałby porzucony, nie zostawił śladu.

Kopia robocza wymaga taniego tworzenia migawek stanu i wycofywania (rollback).
Obecny backend stanu to in-memory `MemoryStore` za minimalnym interfejsem
`KVStore` (ADR 006), który nie ma ani jednego, ani drugiego. Implementacja
copy-on-write lub mechanizmu savepoint to realna praca dla właściwości, której
prototyp jednowęzłowy nie potrzebuje: CometBFT wywołuje `FinalizeBlock`, a
następnie `Commit` sekwencyjnie dla każdego uzgodnionego bloku, a sfinalizowany
blok nie jest w normalnej pracy jednowęzłowej nigdy wycofywany.

## Decyzja
`FinalizeBlock` aplikuje każdą transakcję bezpośrednio do drzewa stanu i zwraca
wynikowy korzeń Merkle'a jako app hash. `Commit` jest no-opem, który jedynie
potwierdza blok. Transakcja, która nie przejdzie walidacji, zwraca niezerowy kod
wyniku i nie zmienia stanu, ale nie przerywa bloku.

Wszystkie punkty wejścia ABCI serializują dostęp do drzewa przez jeden
`RWMutex`: `FinalizeBlock`/`InitChain` biorą blokadę zapisu, a
`CheckTx`/`Query`/`Info` blokadę odczytu, ponieważ CometBFT obsługuje połączenia
konsensusu, mempoola i zapytań współbieżnie.

## Konsekwencje
- **Pozytywne:** brak maszynerii migawek/rollbacku; aplikacja pozostaje mała, a
  pakiet stanu zachowuje minimalny interfejs.
- **Pozytywne:** app hash jest liczony dokładnie tam, gdzie oczekuje go ABCI 2.0
  (`FinalizeBlock`), a nie w `Commit` jak w ABCI 1.0.
- **Negatywne:** wewnątrz aplikacji nie ma atomowej granicy bloku. Jest to
  bezpieczne dla jednego węzła, ale musi zostać ponownie rozważone dla
  trwałego, wielowęzłowego wdrożenia, gdzie potrzebna jest kopia robocza (lub
  transakcyjny backend, np. BadgerDB z savepointami), aby móc czysto odrzucić
  blok. Zapisane jako przyszła praca.
- **Negatywne:** przy backendzie in-memory restart traci stan; CometBFT odtwarza
  swoją historię bloków przez `FinalizeBlock`, aby go odbudować — dlatego chain
  ID jest pobierany z genesis przy konstrukcji, a nie z `InitChain` (które
  wykonuje się tylko raz).
