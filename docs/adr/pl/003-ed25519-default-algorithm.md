# ADR 003: Ed25519 jako domyślny algorytm podpisu

## Status
Zaakceptowany

## Kontekst
System potrzebuje schematu podpisu z kluczem publicznym do uwierzytelniania
transakcji. Wymagania: małe rozmiary klucza i podpisu (klucze wędrują w każdym
certyfikacie i transakcji), szybka weryfikacja (każdy węzeł weryfikuje każdą
transakcję) oraz odporność na pułapki implementacyjne.

Rozważone kandydatury:
- **ECDSA P-256** — szeroko wdrożony (TLS, X.509), wsparcie sprzętowe, ale
  wymaga losowego nonce'a na podpis; słaby lub ponownie użyty nonce ujawnia
  klucz prywatny. Zawarty w enumie `Algorithm` jako `ALGORITHM_ECDSA_P256`, ale
  zwraca `ErrAlgorithmNotSupported` w `validatePublicKey`.
- **RSA-2048/4096** — dobrze poznany, ale duże rozmiary kluczy (256–512 bajtów
  vs. 32 bajty dla Ed25519) i wolna weryfikacja czynią go nieodpowiednim do
  zastosowań blockchain o wysokiej przepustowości.
- **Ed25519** — deterministyczny (brak losowości na podpis), klucze 32-bajtowe,
  podpisy 64-bajtowe, szybka weryfikacja wsadowa oraz odporność na klasę ataków
  związanych z ponownym użyciem nonce'a.

## Decyzja
Ed25519 (`ALGORITHM_ED25519 = 1`) jest jedynym wspieranym algorytmem. ECDSA
P-256 jest zarezerwowany w enumie dla kompatybilności w przód, ale jest jawnie
odrzucany na etapie walidacji.

## Konsekwencje
- **Pozytywne:** małe klucze i podpisy o stałym rozmiarze upraszczają układ
  stanu i format transmisji.
- **Pozytywne:** deterministyczne podpisywanie eliminuje całą klasę błędów
  implementacyjnych.
- **Negatywne:** Ed25519 nie jest jeszcze powszechnie wspierany w HSM-ach i
  narzędziach PKI klasy enterprise; dodanie wsparcia dla ECDSA w przyszłości
  wymaga zaimplementowania `validatePublicKey` dla tego wariantu.
