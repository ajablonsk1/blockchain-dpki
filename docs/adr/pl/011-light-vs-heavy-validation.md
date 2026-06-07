# ADR 011: Lekka walidacja w CheckTx, autorytatywna w FinalizeBlock

## Status
Zaakceptowany

## Kontekst
Transakcja jest walidowana w dwóch bardzo różnych kontekstach. `CheckTx`
strzeże mempoola: wykonuje się często, na transakcjach, które mogą nigdy nie
zostać włączone, musi być tania i nie może zmieniać stanu. `FinalizeBlock`
wykonuje uzgodniony blok: wykonuje się raz na włączoną transakcję i jest jedynym
miejscem, gdzie akceptacja jest autorytatywna i stan faktycznie się zmienia.

Ryzyko polega na robieniu zbyt wiele w `CheckTx` (np. egzekwowaniu dokładnego
następnego nonce'a) i odrzucaniu z mempoola transakcji całkowicie poprawnych po
wylądowaniu ich poprzednika, albo na robieniu zbyt mało i wpuszczaniu
oczywistych śmieci, które marnują miejsce w bloku.

## Decyzja
Obie ścieżki dzielą pierwsze trzy etapy — dekodowanie, syntaktyczne `Validate()`,
zgodność chain ID, weryfikację podpisu względem klucza właściciela — ale różnią
się semantyką:

- **CheckTx (lekka):** domena istnieje, gdy musi, nie jest unieważniona, a nonce
  *nie jest przeterminowany* (`nonce > zapisany`). Celowo **nie** wymaga
  dokładnego następnego nonce'a, aby transakcja ustawiona przed swoim
  poprzednikiem nie była odrzucana.
- **FinalizeBlock (autorytatywna):** pełna kontrola semantyczna, w tym
  **dokładny** następny nonce (`nonce == zapisany + 1`), a następnie mutacja
  stanu.

`CheckTx` nigdy nie zapisuje stanu; tylko czyta. Decyzje o dokładnym nonce oraz
o już-zarejestrowano/już-unieważniono, które wyznaczają wynik kanoniczny, żyją
wyłącznie w `FinalizeBlock`.

## Konsekwencje
- **Pozytywne:** tania, wolna od efektów ubocznych admisja do mempoola, która i
  tak odrzuca złe podpisy oraz oczywiście skazane transakcje, zanim trafią do
  bloku.
- **Pozytywne:** poprawność nie zależy od `CheckTx`; nawet gdyby węzeł go
  pominął, `FinalizeBlock` i tak wyegzekwowałby każdą regułę.
- **Negatywne:** logika walidacji jest wyrażona dwa razy (wariant lekki i pełny),
  co trzeba utrzymywać w synchronizacji. Współdzielony helper
  dekodowania/walidacji/podpisu ogranicza duplikację do warstwy semantycznej.
- **Negatywne:** łagodna reguła nonce'a w `CheckTx` pozwala transakcji z
  przyszłym nonce'em siedzieć w mempoolu i ostatecznie zawieść w
  `FinalizeBlock`; jest to lepsze niż odrzucanie zmienialnych-ale-poprawnych
  transakcji, a anti-spam odłożono do późniejszego mechanizmu gas/limitów
  (ADR 012).
