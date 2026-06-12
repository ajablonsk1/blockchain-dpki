# Model adwersarza i klasyfikacja zagrożeń (STRIDE)

Materiał do sekcji 7.1–7.2 pracy. Metodyka: STRIDE (Howard & LeBlanc,
*Writing Secure Code*; Shostack, *Threat Modeling: Designing for Security*).

## 1. Aktorzy

| ID | Aktor | Zdolności |
|----|-------|-----------|
| A1 | **Atakujący zewnętrzny** | wysyła dowolne transakcje i zapytania RPC, obserwuje cały publiczny stan i ruch; nie kontroluje żadnego walidatora |
| A2 | **Skompromitowany walidator** | A1 + podpisuje wiadomości konsensusu jako ≤ f walidatorów, może dowolnie modyfikować lokalny stan i odpowiedzi swojego RPC |
| A3 | **Atakujący sieciowy** | A1 + opóźnia/upuszcza/duplikuje wiadomości na kontrolowanych łączach (partycja, eclipse pojedynczego węzła) |
| A4 | **Atakujący z kluczem domeny** | posiada klucz prywatny właściciela domeny (kradzież/wyciek) |
| A5 | **Złośliwy operator węzła (insider)** | A2 + pełny dostęp do dysku i pamięci własnego węzła |

Poza modelem: adwersarz kontrolujący > f = ⌊(n−1)/3⌋ walidatorów (BFT z
założenia nie chroni), kompromitacja kryptografii (Ed25519, SHA-256) oraz
adwersarz kontrolujący infrastrukturę DNS ofiary w trakcie rejestracji
(ograniczenie DNS-01, ADR 013).

## 2. Aktywa

1. **Integralność rejestru** — nikt nie może związać cudzej domeny ze swoim
   kluczem ani zmienić/unieważnić cudzego wpisu.
2. **Niefałszowalność proofów** — żaden proof nie weryfikuje się względem
   uczciwego roota, jeśli nie odpowiada zatwierdzonemu stanowi.
3. **Dostępność** — rejestracja, mutacje i odczyty działają przy ≤ f awariach.
4. **Spójność replik** — wszyscy uczciwi walidatorzy mają identyczny stan
   (app hash) na tej samej wysokości.

## 3. Tabela STRIDE

| Komponent | S (Spoofing) | T (Tampering) | R (Repudiation) | I (Info disclosure) | D (DoS) | E (Elevation) |
|---|---|---|---|---|---|---|
| RegisterTx | ✓ T1,T2,T3 | ✓ T4 | — ¹ | — ² | ✓ T9,T10 | ✓ T13 |
| RevokeTx / RotateTx | ✓ T5,T6 | ✓ T6 | — ¹ | — ² | ✓ T11 | ✓ T12,T14,T15 |
| Stan (SMT) | — | ✓ T7 | — | — ² | — | — |
| Konsensus | ✓ ³ | ✓ T7 | — | — | ✓ N1,N2 | ✓ ³ |
| Weryfikacja domeny (DNS-01) | ✓ T8 | ✓ T8 | — | — | ✓ ⁴ | — |
| Query / Proof | — | ✓ T7,T16 | — | — ² | ✓ T9 | — |

¹ Niezaprzeczalność zapewniona konstrukcyjnie: każda mutacja jest podpisana
kluczem właściciela i trwale zapisana w łańcuchu — historia jest dowodem.
² Rejestr jest jawny z założenia (jak Certificate Transparency); nie ma danych
poufnych poza kluczami prywatnymi, które nigdy nie opuszczają klienta (ADR 019).
³ Sybil/ekwiwokacja walidatorów — poza zasięgiem testów przy f=1; własność
CometBFT, analiza teoretyczna w pracy.
⁴ DoS na resolver DNS opóźnia rejestracje (nie mutacje); timeout ogranicza
skutki (ADR 016).

## 4. Mapowanie zagrożeń na testy empiryczne

Testy w `internal/app` (`security_test.go` — Faza 3, `stride_test.go` — Faza 7,
`verification_test.go` — Faza 4) oraz scenariusze sieciowe na żywym testnecie
(`scripts/test-testnet.sh`, logi w `docs/testnet/logs/`).

| ID | Atak (aktor) | Test | Obrona |
|----|--------------|------|--------|
| T1 | Revoke cudzej domeny podpisany własnym kluczem (A1) | `TestSTRIDE_Spoofing_WrongSignerRejected` | podpis weryfikowany kluczem właściciela ze stanu |
| T2 | Register z certyfikatem na cudzy klucz (A1) | `TestSTRIDE_Spoofing_CertKeyMismatchRejected` | podpis musi pochodzić z klucza w certyfikacie |
| T3 | Sfałszowany / brakujący podpis (A1) | `TestSTRIDE_Spoofing_ForgedSignatureRejected`, `..._MissingSignatureRejected` | Ed25519 nad deterministycznymi SignBytes |
| T4 | Modyfikacja payloadu po podpisaniu (A1/A3) | `TestSTRIDE_Tampering_PayloadMutationDetected` | podpis pokrywa całe SignBytes |
| T5 | Przekierowanie podpisanej RevokeTx na inną domenę (A1) | `TestSTRIDE_Spoofing_CrossDomainSwapRejected` | domena wewnątrz podpisanych bajtów |
| T6 | Nieautoryzowany revoke/rotate (A1) | `TestSTRIDE_EoP_UnauthorizedRotateRejected` + T1 | klucz właściciela ze stanu autoryzuje mutacje |
| T7 | Edycja stanu z pominięciem API (A5) | `TestSTRIDE_Tampering_DirectStateEditDetected` | zmiana roota → rozjazd app hash → konsensus odrzuca; proofy nie weryfikują się |
| T8 | Front-running rejestracji (A1) | `TestFrontRunning_AppLevel` (Faza 4) | challenge związany z kluczem (ADR 015) |
| T9 | Spam 10 000 śmieciowych tx (A1) | `TestSTRIDE_DoS_SpamDoesNotBlockLegitTraffic` | tanie odrzucenie na dekodowaniu, przed kryptografią |
| T10 | Domena 1 MB (A1) | `TestSTRIDE_DoS_OversizedDomainRejected` | limity walidacji (253 B domeny) |
| T11 | Powód unieważnienia 1 MB (A1) | `TestSTRIDE_DoS_OversizedReasonRejected` | limit 256 B |
| T12 | Replay mutacji (A1) | `TestSTRIDE_EoP_ReplayRejected` | nonce ściśle rosnący (ADR 001) |
| T13 | Replay RegisterTx po revoke — „un-revoke" (A1/A4) | `TestSTRIDE_EoP_RevocationIsPermanent` | stan unieważniony pozostaje w drzewie; rejestracja odrzucona |
| T14 | Nonce z przyszłości / zmiana kolejności (A1) | `TestSTRIDE_EoP_NonceGapRejected` | FinalizeBlock wymaga dokładnie kolejnego nonce |
| T15 | Replay między łańcuchami (A1) | `TestSTRIDE_CrossChainReplayRejected` | chain ID w SignBytes (ADR 005) |
| T16 | Węzeł kłamie w odpowiedzi lookup (A2/A5) | test integracyjny Fazy 5 (`lookup` weryfikuje proof lokalnie) + `verify` multi-node | klient nie ufa pojedynczemu węzłowi (ADR 020) |
| N1 | Awaria 1/4 walidatorów (A2/A3) | `test-4-one-node-failure` (testnet) | konsensus działa przy 3/4 > 2/3 |
| N2 | Awaria 2/4 walidatorów (A2/A3) | `test-5-two-node-failure` (testnet) | halt zamiast forka — bezpieczeństwo ponad żywotność |
| N3 | Partycja sieci 2+2 (A3) | teoretycznie (równoważna N2: żadna partycja nie ma > 2/3) | jw. |
| N4 | Long-range attack starym kluczem walidatora (A2) | teoretycznie | finalność natychmiastowa BFT — brak reorganizacji łańcucha |

## 5. Zagrożenia rezydualne (ograniczenia)

- **Cenzura przez ≥ 2/3 walidatorów** — koalicja może nie umieszczać wybranych
  transakcji w blokach; niewykrywalne kryptograficznie, ograniczenie wrodzone
  BFT (mitygacja: dobór zdecentralizowanego zbioru walidatorów — governance,
  nie technika).
- **Kompromitacja DNS w oknie rejestracji** — DNS-01 dowodzi kontroli nad
  DNS, nie „własności" domeny; adwersarz kontrolujący strefę ofiary
  zarejestruje ją na swój klucz (wspólne z ACME/Let's Encrypt; ADR 013).
- **Utrata klucza domeny (A4) przed rotacją** — atakujący z kluczem może
  unieważnić lub przejąć wpis rotacją; system gwarantuje jedynie, że historia
  jest jawna (wykrywalność), a rewokacja trwała (T13).
- **Eclipse pojedynczego klienta CLI** — klient pytający wyłącznie węzły
  atakującego dostanie spójne kłamstwo *tylko* jeśli atakujący sforkuje też
  nagłówki, czego nie umie bez > 2/3 mocy; pełny light client (weryfikacja
  podpisów walidatorów nad nagłówkami) pozostaje future work (ADR 020).
