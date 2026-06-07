# ADR 007: Rzadkie drzewo Merkle'a dla uwierzytelnionego commitmentu stanu

## Status
Zaakceptowany

## Kontekst
System musi zatwierdzać (commit) całe mapowanie domena → stan do pojedynczego
hasha korzenia, na który zgadza się konsensus, oraz musi pozwalać dowolnej
stronie zweryfikować względem tego korzenia zarówno to, że domena mapuje się na
konkretny stan (**inkluzja**), jak i to, że domena jest **nieobecna**
(**nie-inkluzja**). Nie-inkluzja jest tym, co pozwala stronie ufającej udowodnić
„ten certyfikat *nie* jest aktualnym powiązaniem dla tej domeny", a inkluzja
stanu `revoked` jest tym, co zastępuje CRL/OCSP pojedynczym, zawsze dostępnym,
samoweryfikującym się dowodem względem zatwierdzonego korzenia.

Rozważone opcje drzew:

| Opcja | Zalety | Wady |
|---|---|---|
| Zwykłe binarne drzewo Merkle'a | Łatwe do implementacji i opisania | Pozycja zależy od kolejności wstawiania; brak wydajnych dowodów nie-inkluzji |
| Rzadkie drzewo Merkle'a (SMT) | Deterministyczne wg klucza, natywne dowody nie-inkluzji, standard branżowy | Bardziej złożone niż zwykłe drzewo |
| IAVL (Cosmos SDK, gotowe) | Gotowe do produkcji | Mało implementujemy sami; trudniej uznać za wkład własny |

Zwykłe drzewo binarne (jak w `playground/merkle-trees`) zatwierdza uporządkowaną
*listę*; pozycje jego liści zależą od kolejności wstawiania i nie ma ono
naturalnego pojęcia „klucz nieobecny", więc nie może wytworzyć dowodów
nie-inkluzji. To dyskwalifikuje je tutaj.

## Decyzja
Implementujemy własne **rzadkie drzewo Merkle'a** w `internal/state`:

- **Stała głębokość 256.** Klucze to skróty SHA-256 nazw domen (ADR 002/003
  używają SHA-256 wszędzie). Każdy klucz adresuje dokładnie jeden liść na
  głębokości 256, więc pozycja liścia zależy wyłącznie od jego klucza — nigdy od
  historii. To właśnie czyni korzeń deterministycznym niezależnie od kolejności
  wstawiania, co jest nadrzędnym wymaganiem.
- **Domyślne hashe.** Hash całkowicie pustego poddrzewa na każdej głębokości jest
  wstępnie obliczony. Nieobecny sąsiad jest z definicji domyślnym hashem dla
  swojej głębokości, więc drzewo reprezentuje 2^256 możliwych liści,
  przechowując jedynie zapełnione ścieżki. Korzeń pustego drzewa to domyślny hash
  głębokości 0.
- **Separacja domen.** Preimage'e liści są oznaczane `0x00`, preimage'e węzłów
  wewnętrznych `0x01`. To uniemożliwia reinterpretację hasha liścia jako hasha
  węzła wewnętrznego (lub odwrotnie), zamykając klasę niejednoznaczności
  second-preimage przy znikomym koszcie.
- **Kanoniczny zbiór węzłów.** Przy każdej aktualizacji jedyna ścieżka
  korzeń-liść jest przepisywana; węzły, których hash zapada się do domyślnego dla
  ich głębokości, są usuwane, a nie przechowywane. Usunięcie klucza przywraca
  dokładnie ten korzeń, jaki drzewo miałoby, gdyby klucz nigdy nie został
  wstawiony, więc dwa backendy o identycznej zawartości trzymają identyczny zbiór
  węzłów.
- **Skompresowane dowody.** Naiwny dowód SMT niesie 256 hashy sąsiadów (8 KiB).
  My niesiemy zamiast tego 256-bitową bitmapę zaznaczającą, które poziomy mają
  niedomyślnego sąsiada, plus tylko tych sąsiadów; weryfikator rekonstruuje
  resztę z ich głębokości. W drzewie 10 000 wpisów dowód ma ~14 sąsiadów / ~520
  bajtów.
- **Samodzielna weryfikacja.** `VerifyProof` i `VerifyDomainProof` potrzebują
  tylko korzenia i dowodu, bez dostępu do drzewa, więc lekki klient (np. klient
  TLS) może zweryfikować aktualne, nieunieważnione powiązanie domeny w trybie
  offline.

## Konsekwencje
- **Pozytywne:** natywne, tanie dowody nie-inkluzji — techniczny rdzeń tezy pracy
  wobec CRL/OCSP.
- **Pozytywne:** niezależne od kolejności, bajtowo identyczne korzenie między
  węzłami; tego właśnie wymaga konsensus.
- **Pozytywne:** w pełni zaimplementowane samodzielnie → kompletny rozdział do
  napisania i obrony, przywołujący rodowód SMT (Plasma, Diem/Libra, Ethereum
  stateless).
- **Negatywne:** każda aktualizacja przepisuje 256 poziomów (~256 hashy); dla
  prototypu jest to w porządku (~0,18 ms/aktualizację w benchmarkach), ale system
  produkcyjny przyjąłby kompaktowy/zoptymalizowany SMT (np. Jellyfish Merkle),
  aby skondensować ścieżki z jednym dzieckiem. Zapisane jako przyszła praca.
- **Negatywne:** determinizm zależy od konstrukcji SHA-256 oraz stałego schematu
  separacji domen/kodowania; jakakolwiek ich zmiana jest zmianą łamiącą
  kompatybilność korzenia stanu i musi być wersjonowana.
