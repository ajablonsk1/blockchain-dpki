# ADR 019: Format przechowywania klucza prywatnego

## Status
Zaakceptowany

## Kontekst
`dpki-cli` trzyma klucze użytkownika na dysku. Kandydujące formaty: PEM/PKCS#8
(standardowy, ale wciąga ASN.1 i zaprasza niejednoznaczność algorytmów),
szyfrowany keystore JSON (najlepsza ochrona, ale wymaga UX hasła, wyboru KDF i
ścieżek odzyskiwania) albo surowe bajty klucza.

## Decyzja
Plik klucza zawiera **surowy 64-bajtowy klucz prywatny Ed25519** (seed ‖ klucz
publiczny, natywny układ `crypto/ed25519`) i nic więcej.

Reguły obsługi, egzekwowane w `internal/crypto` i komendach `keys`:

- Pliki są zapisywane z prawami **0600**; `keys generate` odmawia nadpisania
  istniejącego pliku i tworzy katalogi nadrzędne z prawami 0700.
- Odczyt **odrzuca** klucze z bitami uprawnień grupy/świata
  (`ErrInsecurePermissions`), zamiast ostrzegać i kontynuować.
- Klucz prywatny nigdy nie jest drukowany ani logowany — `keys show` pokazuje
  tylko klucz publiczny, jego odcisk SHA-256 i algorytm; tryb verbose loguje
  sign bytes i podpisy, nigdy klucz.

## Konsekwencje
- **Pozytywne:** zero niejednoznaczności parsowania; plik *jest* kluczem,
  trywialnie audytowalny i testowalny.
- **Pozytywne:** odrzucanie niebezpiecznych uprawnień zamienia cichą
  misconfigurację w twardy, praktyczny błąd.
- **Negatywne:** brak szyfrowania w spoczynku; kto przeczyta plik, ten
  przejmuje domenę. Zaakceptowane dla MVP pracy i wpisane jako future work
  (keystore szyfrowany hasłem); mitygowane przez 0600 + kontrolę uprawnień.
- **Negatywne:** jeden plik na klucz, brak keyringa; inwentarz kluczy to
  higiena systemu plików użytkownika.
