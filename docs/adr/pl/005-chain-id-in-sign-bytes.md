# ADR 005: chain_id zawarty w SignBytes

## Status
Zaakceptowany

## Kontekst
Podpisana transakcja to sekwencja bajtów związana z konkretnym zamiarem. Bez
identyfikatora łańcucha transakcja podpisana dla sieci testowej mogłaby zostać
powtórzona w sieci produkcyjnej (lub jakimkolwiek innym wdrożeniu dzielącym ten
sam genesis). To jest atak replay między łańcuchami.

Rozważone opcje:
- **Pominięcie chain_id przy podpisywaniu** — najprostsze, ale umożliwia replay
  między łańcuchami.
- **Dołączenie chain_id jako osobnego prefiksu przed podpisem** — jawne, ale
  wymaga niestandardowego kroku wstępnego przetwarzania poza schematem protobuf.
- **Dołączenie chain_id jako pola w komunikacie Transaction i objęcie go
  podpisem** — chain_id jest już pełnoprawnym polem w `Transaction`; ponieważ
  `SignBytes` serializuje wszystkie pola oprócz `Signature`, chain_id jest
  automatycznie zawarty w podpisanym ładunku.

## Decyzja
`chain_id` jest wymaganym polem `Transaction` (odrzucanym przez `Validate`,
jeśli jest puste lub dłuższe niż `MaxChainIDLength = 50`). Ponieważ `SignBytes`
marshalluje pełną transakcję bez pola `Signature`, `chain_id` jest zawsze
częścią podpisanego ładunku. Nie jest potrzebna żadna dodatkowa obsługa.

## Konsekwencje
- **Pozytywne:** replay między łańcuchami jest blokowany bez żadnego specjalnego
  traktowania w logice podpisywania.
- **Pozytywne:** chain_id jest widoczny w rekordzie transakcji, co upraszcza
  audyt.
- **Negatywne:** każda transakcja musi nieść chain_id; klienci, którzy zapomną
  go ustawić, będą mieli transakcje odrzucone przy `Validate`, co jest pożądanym
  zachowaniem, ale może zaskoczyć deweloperów nieznających tego wymogu.
