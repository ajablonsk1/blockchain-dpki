# ADR 014: Weryfikacja domeny to bramka przed konsensusem, nie część FinalizeBlock

## Status
Zaakceptowany

## Kontekst
Weryfikacja domeny (ADR 013) to zapytanie DNS: niedeterministyczne I/O
zewnętrzne. Maszyna stanu blockchaina musi być natomiast idealnie
deterministyczna — każdy walidator musi policzyć ten sam app hash, a restartujący
węzeł musi przeliczyć tę samą historię.

Umieszczenie zapytania DNS w `FinalizeBlock` psuje oba warunki:

- **Replay:** przy backendzie in-memory restartujący węzeł odbudowuje stan,
  re-wykonując `FinalizeBlock` po swojej historii bloków (ADR 009). Do tego czasu
  właściciel usunął już rekord TXT (potrzebny tylko raz), więc ta sama
  `RegisterTx` teraz nie przeszłaby weryfikacji — przeliczony app hash rozjechałby
  się z zatwierdzoną historią i węzeł nigdy by nie dogonił.
- **Wielowęzłowość:** różni walidatorzy odpytujący DNS w różnych momentach
  (cache, TTL, propagacja) mogą zobaczyć różne wyniki, dając różne app hashe dla
  tego samego bloku i rozbijając konsensus.

Pierwotny plan fazy proponował weryfikację w `FinalizeBlock` z grace period; to
nie rozwiązuje żadnego z problemów, bo re-wykonanie następuje dowolnie później
niż jakikolwiek grace period.

## Decyzja
Weryfikacja działa **wyłącznie przed konsensusem**, nigdy w `FinalizeBlock`:

- **CheckTx** weryfikuje `RegisterTx` przed wpuszczeniem do mempoola (zapytanie
  DNS biegnie poza blokadą stanu, więc sieciowe I/O nigdy nie blokuje wykonania
  bloku).
- **ProcessProposal** re-weryfikuje każdą rejestrację w proponowanym bloku; jeśli
  którakolwiek zawiedzie, walidator odrzuca cały blok. To powstrzymuje
  proponującego przed przemyceniem niezweryfikowanej rejestracji z pominięciem
  mempoola.
- **FinalizeBlock** nie robi żadnej weryfikacji: deterministycznie aplikuje to,
  co konsensus zgodził się włączyć. Rejestracja, która trafiła do sfinalizowanego
  bloku, *jest* zapisem tego, że weryfikacja przeszła.

## Konsekwencje
- **Pozytywne:** `FinalizeBlock` pozostaje deterministyczny i replay-safe; app
  hash zależy tylko od zatwierdzonych transakcji, nie od żywego DNS.
- **Pozytywne:** weryfikacja nadal bramkuje każdą uczciwą ścieżkę — admisję do
  mempoola i propozycję bloku — więc niezweryfikowana rejestracja nie może być
  zatwierdzona przez poprawny zbiór walidatorów.
- **Negatywne:** to celowe odstępstwo od planu fazy, który umieszczał weryfikację
  w `FinalizeBlock`. Kompromis: weryfikacja jest własnością
  liveness/admisji, a nie własnością re-sprawdzaną w czasie wykonania.
- **Negatywne:** `ProcessProposal` robiące DNS I/O oznacza, że przejściowa awaria
  DNS może skłonić walidatora do odrzucenia skądinąd poprawnego bloku, wpływając
  na liveness. Ograniczone retry/backoff zapisane jako przyszła praca; dla MVP
  jednowęzłowego nieistotne.
- **Negatywne:** w bizantyjskim ustawieniu wielowęzłowym zmowa proponującego i
  walidatorów mogłaby nadal wpuścić niezweryfikowaną rejestrację; pełna ochrona
  wymaga, by każdy uczciwy walidator weryfikował, co zapewnia `ProcessProposal`,
  o ile uczciwa większość potrafi rozwiązać DNS.
