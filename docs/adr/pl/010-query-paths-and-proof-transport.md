# ADR 010: Ścieżki Query i transport dowodu

## Status
Zaakceptowany

## Kontekst
Klienci czytają stan przez ABCI `Query`. Istnieją dwie potrzeby: zwykły odczyt
bieżącego stanu domeny oraz odczyt wraz z dowodem kryptograficznym, który lekki
klient może zweryfikować offline względem zatwierdzonego app hasha — funkcja
zastępująca CRL/OCSP samoweryfikującą się odpowiedzią (ADR 007).

Dowód wytwarzany przez pakiet stanu to kompaktowa struktura Go (`state.Proof`:
klucz, wartość, hashe sąsiadów, bitmapa). Musi podróżować po sieci w stabilnym
kodowaniu i musi pasować do kształtu `ResponseQuery`, który CometBFT już
definiuje.

## Decyzja
Dwie ścieżki zapytań:

- `/domain` — `req.Data` to nazwa domeny; `Value` to zserializowany
  `DomainState` lub puste dla niezarejestrowanej domeny. Brak nie jest błędem
  (`Code == 0`).
- `/domain/proof` — to samo `Value` plus dowód w `ResponseQuery.ProofOps`. Dowód
  podróżuje jako pojedynczy `ProofOp{Type: "dpki:smt", Key: domainKey, Data:
  proofBytes}`, gdzie `proofBytes` to `state.Proof.MarshalBinary()`. Klient
  dekoduje go przez `UnmarshalBinary` i weryfikuje przez
  `state.VerifyDomainProof` względem zaufanego korzenia.

`state.Proof` otrzymuje jawny, samoopisujący się kodek binarny
(`MarshalBinary`/`UnmarshalBinary`), zamiast ponownego użycia protobufa lub
`gob` z Go, aby format transmisji był stabilny i niezależny od układu w pamięci.

## Konsekwencje
- **Pozytywne:** dowody są transportowane w standardowej kopercie
  `ResponseQuery`; brak kanału bocznego.
- **Pozytywne:** inkluzja i nie-inkluzja są obsługiwane jednolicie — obie zwracają
  weryfikowalny dowód; rozróżnia je tylko `Value`.
- **Negatywne:** łańcuch `ProofOp.Type` `"dpki:smt"` to prywatna konwencja, a nie
  zarejestrowany operator dowodu CometBFT, więc generyczny runtime dowodów
  CometBFT nie zweryfikuje go; weryfikacja idzie przez `state.VerifyDomainProof`.
  Jest to akceptowalne, bo lekki klient jest nasz i linkuje pakiet stanu.
- **Negatywne:** obok protobufa istnieje drugi, specyficzny dla aplikacji format
  binarny; jest mały i w pełni pokryty testami round-trip oraz obcięcia.
