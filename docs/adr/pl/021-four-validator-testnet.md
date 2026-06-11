# ADR 021: Czterech walidatorów w referencyjnym testnecie

## Status
Zaakceptowany

## Kontekst
Testnet ma demonstrować własności, które praca twierdzi: zdecentralizowane
działanie, replikację stanu, deterministyczne wykonanie i odporność BFT.
Konsensus CometBFT toleruje `f` bizantyjskich walidatorów tylko gdy łączna
liczba to `n ≥ 3f + 1`; finalność bloku wymaga ponad 2/3 mocy głosów.
Typowe rozmiary testnetów to 4, 7, 10 lub 21 walidatorów; każdy dodatkowy
węzeł to kolejny proces, logi i czas startu bez zmiany matematyki.

## Decyzja
**Czterech walidatorów o równej mocy głosów** — najmniejsze `n` z nietrywialną
odpornością na awarie (`f = 1` z `n = 3f + 1`). Ten rozmiar demonstruje każdy
reżim potrzebny analizie bezpieczeństwa:

- 4/4 żywych — normalny konsensus, bloki co ~1 s;
- 3/4 żywych (75% > 2/3) — konsensus i zapisy działają dalej: tolerowana
  pojedyncza awaria;
- 2/4 żywych (50% < 2/3) — konsensus **zatrzymuje się** zamiast forkować:
  CometBFT wybiera bezpieczeństwo ponad żywotność — empiryczny argument, że
  DPKI na BFT nie da się rozszczepić na dwie historie certyfikatów;
- recovery — zrestartowani walidatorzy dołączają z powrotem i wszystkie app
  hashe ponownie się zbiegają.

Topologia to pełna siatka przez `persistent_peers`; wszyscy walidatorzy są
równi (bez seedów, bez sentry) — wystarczające na jednej maszynie i najprostsza
uczciwa konfiguracja.

## Konsekwencje
- **Pozytywne:** każdy reżim BFT (praca, tolerancja, halt, recovery) pokazany
  przy minimalnej liczbie ruchomych części; scenariusze biegną minuty na
  laptopie.
- **Pozytywne:** `n = 4` trzyma logi na tyle małe, że da się je cytować w
  pracy.
- **Negatywne:** jedna maszyna oznacza brak realnych opóźnień sieci i
  partycji; liczby wydajnościowe Fazy 7 trzeba czytać jako dolne ograniczenia
  opóźnień.
- **Negatywne:** `f = 1` nie pozwala zademonstrować bizantyjskiego
  *zachowania* podkworum (np. ekwiwokacji mniejszości); ta analiza pozostaje
  teoretyczna.
