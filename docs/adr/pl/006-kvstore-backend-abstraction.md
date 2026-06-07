# ADR 006: Abstrakcja KVStore z domyślnym backendem in-memory

## Status
Zaakceptowany

## Kontekst
Uwierzytelniony magazyn stanu (`internal/state`) musi utrwalać węzły drzewa i
wartości domen. Prototyp pracy dyplomowej musi się uruchamiać, być
benchmarkowany i testowany deterministycznie, ale nie potrzebuje jeszcze
trwałości klasy produkcyjnej. Rozważono trzy opcje backendu:

| Opcja | Zalety | Wady |
|---|---|---|
| In-memory (`map[string][]byte`) | Najprostsze, natychmiastowa konfiguracja, idealne do testów | Brak trwałości; restart traci stan |
| BadgerDB | Wbudowany magazyn KV, szybki, ACID, snapshoty | Cięższa zależność, cykl życia do zarządzania |
| PebbleDB | Bardzo szybki następca LevelDB (CockroachDB) | Mniejsza społeczność niż Badger |

Drzewo stanu nie może zależeć bezpośrednio od żadnego z nich: wybór backendu to
kwestia operacyjna, a nie kwestia poprawności.

## Decyzja
Definiujemy minimalny interfejs `KVStore` (`Get`, `Set`, `Delete`, `Close`) i
implementujemy go najpierw jako in-memory `MemoryStore`. SMT zależy wyłącznie od
interfejsu, więc implementacja oparta na dysku (BadgerDB jest zamierzonym
pierwszym wyborem) może zostać dodana później przez napisanie jednego nowego
typu i zmianę jednego miejsca konstrukcji — logika drzewa i testy pozostają
nietknięte. Testy nadal używają `MemoryStore` dla szybkości i determinizmu.

`MemoryStore` kopiuje klucze i wartości przy wejściu i wyjściu, aby wywołujący
nie mogli uszkodzić przechowywanych danych przez zachowane slice'y, i jest
chroniony przez `RWMutex`.

Interfejs celowo **pomija iterator** na razie. SMT adresuje każdy węzeł
dokładnym kluczem (głębokość + zamaskowana ścieżka) i nigdy nie skanuje zakresów,
więc iterator byłby martwym kodem. Zostanie dodany, gdy pojawi się funkcja
wymagająca uporządkowanego przejścia (eksport stanu do genesis, state-sync między
węzłami).

## Konsekwencje
- **Pozytywne:** brak zależności od magazynu w rdzeniu modułu na razie; prototyp
  buduje się i testuje bez żadnych usług zewnętrznych.
- **Pozytywne:** przejście na BadgerDB/Pebble to zlokalizowana zmiana za
  stabilnym interfejsem.
- **Negatywne:** backend in-memory nie ma trwałości; restart węzła odbudowuje
  stan z historii bloków (akceptowalne dla prototypu, musi zostać ponownie
  rozważone przed jakimkolwiek długotrwałym wdrożeniem).
- **Negatywne:** dyscyplina kopiowania na wejściu/wyjściu w `MemoryStore`
  kosztuje alokacje; to uczciwa cena za bezpieczeństwo w backendzie
  nieprodukcyjnym i nie wpływa na interfejs.
