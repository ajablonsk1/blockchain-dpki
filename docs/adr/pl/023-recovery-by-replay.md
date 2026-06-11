# ADR 023: Odzyskiwanie po awarii przez replay bloków zamiast persystencji stanu

## Status
Zaakceptowany

## Kontekst
Stan aplikacji żyje w SMT w pamięci (`state.MemoryStore`, ADR 006);
zrestartowany walidator wraca z pustym drzewem na wysokości 0. Testnet musi
mimo to zademonstrować recovery: ubity walidator dołącza z powrotem i kończy z
tym samym app hashem co pozostali. Alternatywą jest trwały KVStore (np.
BadgerDB), który wymaga commitów spójnych przy awarii, wyrównanych z Commit
CometBFT, snapshotów i własnego ADR-a trybów awarii.

## Decyzja
**Recovery opiera się na replayu CometBFT; aplikacja nie persystuje niczego.**
CometBFT trwale przechowuje block store i WAL w home węzła. Po restarcie
handshake ABCI porównuje wysokość aplikacji (0, in-memory) ze zsynchronizowanym
łańcuchem i odtwarza każdy zatwierdzony blok przez `FinalizeBlock`,
deterministycznie odbudowując SMT; blocksync dociąga bloki przegapione w czasie
niedostępności i walidator wraca do konsensusu.

Dwie wcześniejsze decyzje czynią to poprawnym:

- wykonanie jest w pełni deterministyczne (ADR 002, 009) — replay dowodliwie
  odtwarza ten sam app hash, co test recovery weryfikuje na wszystkich
  walidatorach;
- weryfikacja DNS-01 jest bramką przed-konsensusową, nigdy w `FinalizeBlock`
  (ADR 014) — replay nie powtarza zapytań DNS, więc rejestracje, których
  rekordy TXT dawno zniknęły, odtwarzają się czysto.

## Konsekwencje
- **Pozytywne:** zero kodu persystencji w aplikacji; SMT pozostaje czystą
  strukturą w pamięci, a ścieżka replay jest zarazem stałym testem determinizmu
  całej historii transakcji.
- **Pozytywne:** odzyskiwanie „wyczyść aplikację, zachowaj łańcuch" to
  dokładnie historia minimalizacji zaufania: stan jest zawsze wyprowadzalny z
  konsensusu.
- **Negatywne:** koszt restartu rośnie liniowo z długością łańcucha (replay
  wszystkich bloków). W porządku dla testnetu pracy; wdrożenie produkcyjne
  dodałoby trwały KVStore za istniejącym interfejsem `state.KVStore` (ADR 006)
  bez dotykania konsensusu.
- **Negatywne:** brak snapshotów state-sync dla szybko dołączających nowych
  węzłów; nowi walidatorzy też replayują od genesis.
