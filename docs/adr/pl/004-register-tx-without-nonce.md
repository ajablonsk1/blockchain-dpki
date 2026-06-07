# ADR 004: RegisterTx nie zawiera nonce'a

## Status
Zaakceptowany

## Kontekst
Transakcje Revoke i Rotate używają nonce'a per domena, aby zapobiec atakom
replay (ADR 001). Pytanie brzmi, czy RegisterTx potrzebuje tej samej ochrony.

Replay transakcji RegisterTx próbowałby zarejestrować domenę, która już istnieje
w stanie. Dwa scenariusze:
1. **Domena nadal aktywna** — aplikacja odrzuca transakcję, ponieważ domena jest
   już zarejestrowana; nonce nic by nie wniósł.
2. **Domena została usunięta** — jeśli ponowna rejestracja jest kiedykolwiek
   dozwolona, powtórzona RegisterTx od poprzedniego właściciela mogłaby przejąć
   domenę. To ryzyko istnieje niezależnie od nonce'a, jeśli nowy rejestrujący
   akurat użyje nonce = 1.

## Decyzja
`RegisterTx` nie zawiera pola nonce. Ochrona przed replay jest zapewniona w
całości przez niezmiennik unikalności egzekwowany przez stan aplikacji:
RegisterTx jest akceptowana tylko wtedy, gdy domena jest nieobecna w stanie.
Znacznik czasu `Certificate.ValidFrom` dostarcza słabego sygnału kolejności, ale
nie jest używany jako licznik replay.

## Konsekwencje
- **Pozytywne:** prostsza struktura transakcji; jedno pole mniej do walidacji i
  przechowywania.
- **Pozytywne:** spójne z semantyką — nonce śledzi liczbę mutacji, a domena
  rejestrowana po raz pierwszy nie ma wcześniejszych mutacji.
- **Negatywne:** jeśli usuwanie domen zostanie dodane w przyszłości, aplikacja
  musi zapewnić, że ponowna rejestracja nie może być powtórzona ze starej
  podpisanej RegisterTx; może to wymagać mechanizmu tombstone lub licznika epoki
  rejestracji.
