# ADR 001: Strategia nonce'a per domena

## Status
Zaakceptowany

## Kontekst
Transakcje Revoke i Rotate muszą być chronione przed atakami typu replay:
atakujący, który przechwyci poprawnie podpisaną transakcję, nie może mieć
możliwości ponownego jej wysłania (np. po tym, jak właściciel wrócił do starego
klucza lub ponownie zarejestrował domenę).

Istnieje kilka strategii ochrony przed replay:
- **Globalny numer sekwencyjny per nadawca** — proste, ale wiąże ochronę przed
  replay z pojedynczą tożsamością klucza publicznego, a nie z domeną.
- **Hash transakcji w stanie** — zapobiega dokładnym powtórzeniom, ale wymaga
  przechowywania każdego napotkanego hasha w nieskończoność.
- **Nonce per domena** — monotonicznie rosnący licznik trzymany w stanie dla
  każdej domeny; transakcja jest ważna tylko wtedy, gdy jej nonce równa się
  bieżący + 1.

## Decyzja
Używamy nonce'a per domena przechowywanego w stanie aplikacji. Nonce jest
zawarty w `RevokeTx` i `RotateTx` i musi być większy od zera. Jest nieobecny w
`RegisterTx`, ponieważ domena jeszcze nie istnieje w stanie (zob. ADR 004).

## Konsekwencje
- **Pozytywne:** przestrzeń nonce'ów jest niezależna między domenami;
  kompromitacja klucza jednej domeny nie wpływa na kolejność nonce'ów dla
  pozostałych.
- **Pozytywne:** walidacja nonce'a jest bezstanowa z punktu widzenia transakcji
  — aplikacja po prostu porównuje tx.Nonce z przechowywaną wartością.
- **Negatywne:** warstwa aplikacji musi wczytać bieżący nonce ze stanu przy
  każdym Revoke/Rotate, co dodaje jeden odczyt stanu na transakcję.
- **Negatywne:** jeśli domena zostanie usunięta i ponownie zarejestrowana, nonce
  resetuje się do zera, co trzeba obsłużyć ostrożnie, aby uniknąć powtórzenia
  starych unieważnień.
