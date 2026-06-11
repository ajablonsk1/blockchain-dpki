# ADR 022: Narzędzia testnetu — subkomenda w Go, procesy lokalne najpierw, Docker jako demo

## Status
Zaakceptowany

## Kontekst
Inicjalizacja wielowalidatorowego testnetu jest grząska: każdy home potrzebuje
unikalnych kluczy walidatora i węzła, bajtowo identycznego genesis z listą
wszystkich walidatorów, niekolidujących portów i poprawnie sformatowanych
`persistent_peers` (`node_id@host:port`). Skrypt bash robiący to wszystko
wołałby binarkę `cometbft` (zależność, której skądinąd nie dostarczamy) i
przepisywał TOML sedem. Jest też pytanie o topologię: procesy lokalne czy
kontenery?

## Decyzja
Trzy elementy, każdy z jednym zadaniem:

1. **`dpkid testnet init`** (Go) generuje home'y. Używa tych samych bibliotek
   config/privval/p2p CometBFT, na których chodzi sam węzeł, więc nie ma
   zewnętrznej binarki ani żonglerki tekstem: porty ustawiane są na strukturze
   `Config`, peers liczone z prawdziwych ID `NodeKey`, a jeden `GenesisDoc`
   zapisywany do każdego home'a. `--docker` przełącza adresowanie peers z
   `127.0.0.1:26656+10i` na hostnames compose `node{i}:26656`. Pełna siatka na
   localhost wymaga `AllowDuplicateIP = true` i `AddrBookStrict = false`.
2. **Procesy lokalne** (`scripts/start-testnet.sh` / `stop-testnet.sh`) to
   podstawowa topologia deweloperska: natychmiastowy start, logi w zwykłych
   plikach, węzły ubijalne pojedynczo — na czym polegają testy odporności.
3. **Docker Compose** to topologia demo/reprodukowalności: jedno
   `docker compose up --build` daje recenzentowi pełny testnet z tymi samymi
   portami RPC na hoście, więc każdy przykład `dpki-cli` działa bez zmian.

## Konsekwencje
- **Pozytywne:** generowanie testnetu to typowany, testowalny kod Go; pułapki
  genesis i formatu peers wyeliminowane konstrukcyjnie.
- **Pozytywne:** harness odporności (`scripts/test-testnet.sh`) może trywialnie
  ubijać i restartować pojedynczych walidatorów.
- **Negatywne:** dwie topologie do utrzymania (procesy i kontenery); ścieżka
  kontenerowa współdzieli kod init, więc powierzchnia jest mała.
- **Negatywne:** `testnet init` generuje tylko statyczne setupy
  lokalne/compose — bez provisioningu chmurowego; poza zakresem pracy.
