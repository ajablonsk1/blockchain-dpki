# ADR 015: Deterministyczna, związana z kluczem wartość wyzwania

## Status
Zaakceptowany

## Kontekst
Wartość wyzwania publikowana w DNS musi być odtwarzalna zarówno przez klienta
(gdy instruuje właściciela), jak i przez każdego walidatora (gdy sprawdza), więc
nie może zawierać losowości wybranej przez serwer. Musi też być związana z
rejestracją w sposób pokonujący front-running: atakujący, który widzi oczekującą
`RegisterTx`, nie może móc ponownie użyć tego samego opublikowanego rekordu do
rejestracji pod własnym kluczem.

## Decyzja
Wyzwanie to skrót po publicznych, związanych z transakcją wejściach, z separacją
domen:

```
challenge = SHA-256( domena || 0x00 || pubKey || 0x00 || chainID )   (małe hex)
```

publikowany pod `_dpki-challenge.<domena>` (ADR 013). Separatory `0x00`
zapobiegają kolizjom konkatenacji (np. `("ab","c")` vs `("a","bc")`).

Związanie z:
- **pubKey** to własność anty-front-running: wartość publikowana przez prawdziwego
  właściciela jest związana z *jego* kluczem, więc atakujący podstawiający własny
  klucz liczy inną oczekiwaną wartość i opublikowany rekord nie będzie pasował.
- **chainID** powstrzymuje powtórzenie wyzwania opublikowanego dla jednego
  łańcucha w celu przejęcia domeny na innym.

Nie używamy losowości po stronie serwera; determinizm jest wymagany dla zgody
klient/walidator, a związanie z kluczem publicznym już zapewnia unikalność per
rejestracja i nieodgadywalność (klucz jest świeżo generowany).

## Konsekwencje
- **Pozytywne:** klient i walidatorzy wyprowadzają identyczną wartość bez
  współdzielonego sekretu ani koordynacji.
- **Pozytywne:** front-running jest pokonany strukturalnie, a nie przez timing.
- **Negatywne:** wartość jest w pełni wyznaczona przez wejścia publiczne, więc
  *nie* jest sekretna — każdy obserwujący łańcuch może ją policzyć. To w porządku:
  tylko prawdziwy kontroler DNS domeny może opublikować ją pod domeną, i tylko
  posiadacz klucza prywatnego może podpisać pasującą transakcję.
- **Negatywne:** format jest stały; zmiana preimage'a lub funkcji skrótu to zmiana
  łamiąca weryfikację i musi być wersjonowana wraz z kodowaniem stanu.
