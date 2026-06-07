# ADR 012: Pozostawienie domyślnych PrepareProposal / ProcessProposal

## Status
Zaakceptowany

## Kontekst
ABCI 2.0 dodaje dwa haki czasu proponowania: `PrepareProposal` (proponujący
wybiera i może zmienić kolejność/zawartość transakcji swojego bloku) oraz
`ProcessProposal` (każdy walidator waliduje proponowany blok przed głosowaniem).
Są to miejsca na politykę poziomu bloku: pomiar gas, ograniczanie tempa per
nadawca, anti-spam, reguły kolejności transakcji.

`abci.BaseApplication` dostarcza domyślne implementacje: `PrepareProposal`
bierze transakcje z mempoola w kolejności do limitu rozmiaru, a
`ProcessProposal` akceptuje każdy proponowany blok.

## Decyzja
Aplikacja embeduje `abci.BaseApplication` i **nie** nadpisuje `PrepareProposal`
ani `ProcessProposal`. MVP polega na walidacji per transakcja w `CheckTx` i
`FinalizeBlock` (ADR 011) w zakresie całej poprawności; polityka poziomu bloku
jest poza zakresem prototypu jednowęzłowego.

## Konsekwencje
- **Pozytywne:** mniej kodu i brak drugiego miejsca, gdzie ocenia się ważność
  transakcji; los transakcji jest rozstrzygany w całości przez
  `CheckTx`/`FinalizeBlock`.
- **Pozytywne:** akceptowanie wszystkich bloków przez `ProcessProposal` jest tu
  bezpieczne, bo każda transakcja jest w pełni re-walidowana w `FinalizeBlock`,
  więc niepoprawna zostaje zapisana z niezerowym kodem, zamiast uszkodzić stan.
- **Negatywne:** brak gas, brak limitu tempa i brak anti-spamowej kolejności.
  Jeden węzeł nie jest przeciwnikiem, ale publiczne wdrożenie wielowęzłowe
  wymagałoby `PrepareProposal`/`ProcessProposal` do ograniczenia pracy bloku i
  odrzucania spamu przed wykonaniem. Zapisane jako przyszła praca i omówione w
  analizie bezpieczeństwa.
