# ADR 002: Protobuf z deterministycznym marshallingiem zamiast kanonicznej serializacji JSON

## Status
Zaakceptowany

## Kontekst
Podpisywanie transakcji wymaga reprezentacji bajtowej, która jest:
1. **Deterministyczna** — ten sam logicznie komunikat zawsze daje te same bajty.
2. **Kompletna** — zawiera wszystkie pola wpływające na ważność.
3. **Wieloplatformowa** — inne węzły lub klienci mogą być napisani w językach
   innych niż Go.

Rozważone kandydatury:
- **Kanoniczny JSON (RFC 8785 / JCS)** — czytelny dla człowieka, powszechnie
  rozumiany, ale wymaga dodatkowej biblioteki kanonikalizacji i jest wolniejszy
  w parsowaniu.
- **protobuf z `MarshalOptions{Deterministic: true}`** — już używany do
  transportu; tryb deterministyczny sortuje klucze map i daje stabilne wyjście
  w obrębie jednej wersji binarki.
- **Surowa konkatenacja pól** — szybka, ale krucha; dodanie pola po cichu psuje
  schemat podpisywania.

## Decyzja
Używamy `proto.MarshalOptions{Deterministic: true}` do wytworzenia kanonicznej
reprezentacji bajtowej zarówno do podpisywania (`SignBytes`), jak i hashowania
(`Hash`). Pole `Signature` jest zerowane przed marshallingiem, więc jest
wykluczone z podpisywanego ładunku (zob. `Transaction.SignBytes`).

## Konsekwencje
- **Pozytywne:** brak dodatkowych zależności; protobuf jest już formatem
  transmisji.
- **Pozytywne:** ewolucja schematu (dodawanie pól opcjonalnych) jest bezpieczna,
  o ile starzy sygnatariusze ustawiają nowe pola na ich wartości zerowe.
- **Negatywne:** deterministyczny tryb protobufa jest gwarantowany tylko w
  obrębie tej samej wersji biblioteki protobuf. Większa aktualizacja biblioteki
  musi być przetestowana pod kątem stabilności serializacji przed wdrożeniem.
- **Negatywne:** podpisane bajty nie są czytelne dla człowieka; debugowanie
  wymaga narzędzia rozumiejącego proto.
