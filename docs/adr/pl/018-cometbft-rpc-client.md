# ADR 018: Dostęp do węzła przez oficjalny klient JSON-RPC CometBFT

## Status
Zaakceptowany

## Kontekst
CLI potrzebuje czterech wywołań węzła: `status`, `broadcast_tx_commit`,
`abci_query` i `header`. Kandydujące transporty:

1. **Ręczny HTTP + parsowanie JSON** — pełna kontrola, ale JSON-RPC CometBFT
   koduje `[]byte` jako base64, `int64` jako stringi, a proofy w zagnieżdżonej
   kopercie; poprawne zdekodowanie wszystkiego (i utrzymanie tego przy
   aktualizacjach CometBFT) to dokładnie ta klasa cichych błędów, na którą
   klient PKI nie może sobie pozwolić.
2. **gRPC** — CometBFT v0.38 wystawia po gRPC tylko minimalny serwis
   broadcast; zapytania i nagłówki i tak wymagałyby JSON-RPC.
3. **Oficjalny klient Go** `github.com/cometbft/cometbft/rpc/client/http` —
   ten sam protokół JSON-RPC po HTTP, z całym kodowaniem/dekodowaniem
   należącym do modułu CometBFT, z którego zbudowany jest sam węzeł.

## Decyzja
Używamy oficjalnego klienta, opakowanego w `cmd/dpki-cli/client`:

- Wrapper wystawia wywołania w kształcie DPKI (`QueryDomain`,
  `QueryDomainProof`, `AppHashAt`, `BroadcastTxCommit` przyjmujący
  `*types.Transaction`) i opakowuje błędy transportowe adresem węzła oraz
  praktyczną wskazówką.
- Transakcje są serializowane przez `proto.MarshalOptions{Deterministic:
  true}` — dokładnie ten format wire, który dekoduje aplikacja (ADR 002).
- Proof `dpki:smt` podróżuje w `ResponseQuery.ProofOps` i jest dekodowany
  przez `state.Proof.UnmarshalBinary` (ADR 010); generyczny runtime proofów
  CometBFT nie bierze w tym udziału.
- Timeout RPC to 15 s — powyżej 10 s, przez które CometBFT może trzymać
  `broadcast_tx_commit` w oczekiwaniu na blok.

## Konsekwencje
- **Pozytywne:** brak kruchego ręcznego dekodowania base64/string-int; typy
  odpowiedzi to te same struktury, które serializuje węzeł.
- **Pozytywne:** rozjazd wersji między klientem a węzłem łapie wspólny pin
  CometBFT w go.mod.
- **Negatywne:** binarka klienta linkuje stos RPC CometBFT; rośnie rozmiar i
  powierzchnia zależności. Zaakceptowane — moduł i tak zależy od CometBFT.
- **Negatywne:** tylko JSON-RPC po HTTP; brak subskrypcji strumieniowych.
  Żadna komenda Fazy 5 ich nie potrzebuje.
