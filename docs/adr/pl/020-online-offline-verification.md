# ADR 020: Ścieżki weryfikacji online i offline

## Status
Zaakceptowany

## Kontekst
Strona ufająca pyta: „czy to jest aktualny, nieunieważniony klucz domeny X?"
Kluczowa teza DPKI (ADR 007, 010) brzmi: odpowiedź jest *samoweryfikowalna* —
proof Merkle względem zatwierdzonego app hasha — więc klient nigdy nie powinien
wierzyć węzłowi na słowo. Jedna subtelność: ABCI zatwierdza app hash z
opóźnieniem. Stan po bloku H jest zatwierdzony w nagłówku bloku **H+1**, więc
proof dla zapytania na wysokości H weryfikuje się względem
`header(H+1).AppHash`.

## Decyzja
Trzy ścieżki odczytu, wszystkie kończące się w `state.VerifyDomainProof`:

1. **`lookup`** (pojedynczy węzeł) — pobiera stan + proof, wyznacza root z
   nagłówka następnego bloku (krótko odpytując na czubku łańcucha), weryfikuje
   lokalnie i dopiero wtedy drukuje. W CLI celowo **nie ma niezweryfikowanego
   odczytu**: nawet zwykły lookup uwierzytelnia to, co pokazuje.
2. **`verify --nodes a,b,c`** (wiele węzłów) — wykonuje weryfikację jak w
   lookup na każdym węźle, po czym sprawdza krzyżowo: wszystkie udowodnione
   stany muszą być równe, a węzły na tej samej wysokości muszą raportować ten
   sam app hash. Pojedynczy skompromitowany węzeł zostaje wykryty, chyba że
   potrafi też sforkować nagłówki pozostałych; kotwicą zaufania jest zbiór
   walidatorów, a nie pojedynczy endpoint RPC.
3. **`verify-offline`** — konsumuje paczkę proof zapisaną przez
   `lookup --save-proof` (chain id, domena, wysokość, bajty proofa) plus root
   przekazany jawnie przez `--root`. Paczka zapisuje też app hash, względem
   którego została wydana, ale ta kopia jest **wyłącznie informacyjna**:
   zaufanie jej sprowadziłoby proof do „bo tak mówi plik". Pozyskanie roota
   innym kanałem to istota weryfikacji offline. `--cert` opcjonalnie porównuje
   certyfikat otrzymany innym kanałem z udowodnionym stanem.

## Konsekwencje
- **Pozytywne:** sprawdzanie unieważnień nie wymaga infrastruktury w stylu
  CRL/OCSP; przeterminowanej odpowiedzi nie da się odtworzyć względem nowszego
  roota.
- **Pozytywne:** nie-inkluzja jest pełnoprawna — „domena niezarejestrowana" to
  weryfikowalne stwierdzenie, nie błąd.
- **Negatywne:** ścieżki online ufają odpytywanemu węzłowi co do *nagłówków*;
  pełna weryfikacja light client (podpisy walidatorów nad nagłówkami) to
  future work dla fazy wielowęzłowej. Krzyżowa kontrola multi-node zawęża tę
  lukę do tego czasu.
- **Negatywne:** na czubku łańcucha klient może czekać ~1 blok na nagłówek
  zatwierdzający odpytany stan.
