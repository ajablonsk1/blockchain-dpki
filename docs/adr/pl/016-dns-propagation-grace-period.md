# ADR 016: Grace period propagacji DNS po stronie klienta

## Status
Zaakceptowany

## Kontekst
Po opublikowaniu przez właściciela rekordu TXT wyzwania potrzeba czasu na jego
propagację przez cache DNS (ograniczoną przez TTL rekordu). Jeśli walidator
odpyta zbyt wcześnie, może zobaczyć przeterminowaną odpowiedź negatywną i
odrzucić skądinąd poprawną rejestrację. Istnieją trzy złagodzenia:

- **Grace period (po stronie klienta):** właściciel czeka przed wysłaniem
  `RegisterTx` i ustawia niski TTL, by propagacja była szybka.
- **Retry z backoffem (po stronie walidatora):** verifier ponawia kilka razy
  przed poddaniem się.
- **Zapytanie autorytatywne (po stronie walidatora):** verifier rozwiązuje
  autorytatywne serwery nazw domeny i pyta je bezpośrednio, omijając cache.

## Decyzja
Dla MVP polegamy na **grace period po stronie klienta**: komenda `dpki-cli
challenge` instruuje właściciela, by opublikował rekord z niskim TTL (np. 60 s) i
potwierdził propagację przez `dpki-cli challenge-check` przed wysłaniem
transakcji. Walidator wykonuje pojedyncze, zwykłe zapytanie DNS, używając
resolwera Go z `PreferGo`. Retry/backoff i zapytania autorytatywne zapisane jako
przyszła praca.

## Konsekwencje
- **Pozytywne:** walidator pozostaje prosty — jedno zapytanie, brak maszyny stanu
  retry, brak odkrywania serwerów nazw — co utrzymuje ścieżkę weryfikacji łatwą do
  analizy i testowania.
- **Pozytywne:** `challenge-check` daje użytkownikowi konkretny sygnał „czy już
  gotowe?", przenosząc problem propagacji tam, gdzie człowiek i tak czeka.
- **Negatywne:** użytkownik, który wyśle za wcześnie albo którego ścieżka
  resolwera wolno propaguje, może mieć poprawną rejestrację odrzuconą i musi
  ponowić. Przy niskim TTL to okno jest małe.
- **Negatywne:** pojedyncze zapytanie jest bardziej wrażliwe na przejściowe awarie
  DNS niż ponawiane; w połączeniu z ADR 014 (DNS w `ProcessProposal`) to kwestia
  liveness dla przyszłego wdrożenia wielowęzłowego, a nie poprawności.
