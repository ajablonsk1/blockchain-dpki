# ADR 017: Cobra jako framework CLI dla dpki-cli

## Status
Zaakceptowany

## Kontekst
Do Fazy 5 `dpki-cli` miało dwie komendy pomocnicze (`challenge`,
`challenge-check`) z ręcznym dispatch'em na standardowym pakiecie `flag` — ten
sam wzorzec, którego używa `dpkid`. Faza 5 rozbudowuje je do pełnego klienta:
dziesięć komend, wspólne flagi globalne (`--node`, `--chain-id`, `--config`,
`-v`), walidacja flag wymaganych, grupowanie podkomend (`keys generate`/`keys
show`) i autouzupełnianie powłoki. Ręczny dispatch skaluje się źle powyżej
kilku komend: każda komenda osobno parsuje flagi globalne, teksty pomocy są
utrzymywane ręcznie i brakuje jednolitej ścieżki błędów.

## Decyzja
`dpki-cli` jest zbudowane na `github.com/spf13/cobra` — de facto standardzie
ekosystemu Go (kubectl, docker, cometbft, cosmos-sdk). Konwencje:

- `commands.NewRootCommand()` buduje **świeże, samodzielne drzewo komend**; nic
  nie jest globalne na poziomie pakietu. Testy uruchamiają całe komendy
  in-process z własnymi buforami stdin/stdout.
- Flagi globalne żyją na korzeniu jako persistent flags i są rozwiązywane
  względem opcjonalnego pliku konfiguracyjnego w `PersistentPreRunE`
  (flaga > config > wartość domyślna).
- Komendy nie zawierają logiki biznesowej: parsują flagi, wołają
  `internal/types`/`internal/crypto` oraz pakiet `client` i formatują wyjście.
  Werdykty walidacyjne należą do węzła.

`dpkid` zostaje na standardowym pakiecie `flag`: dwie podkomendy nie
uzasadniają zależności, a daemon dla operatora ma inne potrzeby UX.

## Konsekwencje
- **Pozytywne:** `--help` dla każdej komendy, egzekwowanie flag wymaganych i
  `completion bash|zsh|fish` za darmo.
- **Pozytywne:** świeże drzewa komend czynią testy CLI trywialnymi i
  bezpiecznymi przy równoległości.
- **Negatywne:** nowa zależność bezpośrednia (cobra była już zależnością
  pośrednią przez CometBFT).
- **Negatywne:** w `cmd/` współistnieją dwa style CLI (`dpkid` na flag,
  `dpki-cli` na cobrze). Zaakceptowane: interfejs daemona to dwie stałe
  podkomendy, a interfejs klienta jest produktem.
