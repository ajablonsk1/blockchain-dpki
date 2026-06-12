# Notatki do rozdziału 7 — Analiza bezpieczeństwa

Szkielet rozdziału + gotowe ustalenia. Pełny model adwersarza i mapowanie
zagrożeń: `docs/security/adversary-model.md`. Surowe logi testów:
`results/<timestamp>/security-tests.log` oraz `docs/testnet/logs/`.

## 7.1 Model adwersarza

Przenieść z `adversary-model.md`: aktorzy A1–A5, zdolności, aktywa, założenia
(≤ f bizantyjskich walidatorów, bezpieczna kryptografia, DNS ofiary poza
kontrolą atakującego w oknie rejestracji). Cytować: Howard & LeBlanc,
Shostack.

## 7.2 Klasyfikacja STRIDE

Tabela STRIDE z `adversary-model.md` §3 + uzasadnienie pominięć
(Repudiation — niezaprzeczalność konstrukcyjna; Information disclosure —
rejestr jawny z założenia, jak w Certificate Transparency).

## 7.3 Analiza wektorów ataku

Schemat każdego podrozdziału: opis ataku → mechanizm obrony → wynik testu
empirycznego (nazwa testu + PASS z logów). 21 scenariuszy (T1–T16, N1–N4 +
front-running), wszystkie przechodzą.

### 7.3.1 Kompromitacja walidatora (A2, A5)
- Edycja stanu z dysku (T7): root SMT się rozjeżdża → app hash niezgodny w
  konsensusie → uczciwa większość odrzuca bloki/voty tamperowanego węzła;
  proofy z tamperowanego stanu nie weryfikują się u klienta. Test:
  `TestSTRIDE_Tampering_DirectStateEditDetected`.
- Kłamiący RPC (T16): `lookup` weryfikuje proof lokalnie względem app hash z
  nagłówka; `verify` porównuje odpowiedzi wielu węzłów. Pojedynczy węzeł nie
  jest zaufany (ADR 020).
- Awarie walidatorów (N1, N2): wyniki empiryczne z testnetu — 3/4 działa,
  2/4 halt (bezpieczeństwo ponad żywotność), recovery przez replay
  (`docs/testnet/logs/test-4..6`).

### 7.3.2 Ataki na warstwę kryptograficzną (A1)
- Sfałszowany/brakujący/cudzy podpis (T1–T3), modyfikacja payloadu (T4),
  przekierowanie tx na inną domenę (T5): wszystko sprowadza się do własności
  Ed25519 nad deterministycznymi SignBytes (ADR 002) — podpis pokrywa domenę,
  nonce, chain ID i cały body.

### 7.3.3 Front-running rejestracji (A1)
- Challenge DNS-01 związany z kluczem publicznym i chain ID (ADR 015):
  przechwycenie cudzej wartości TXT jest bezużyteczne — atakujący z własnym
  kluczem oczekuje innej wartości. Test: `TestFrontRunning_AppLevel`.

### 7.3.4 Ataki replay (A1)
- Replay mutacji w ramach łańcucha (T12): nonce ściśle rosnący (ADR 001).
- Replay między łańcuchami (T15): chain ID w SignBytes (ADR 005).
- Replay rejestracji po unieważnieniu — atak „un-revoke" (T13): unieważniony
  wpis pozostaje w drzewie na zawsze, więc ponowna rejestracja (nawet
  oryginalnymi, poprawnie podpisanymi bajtami) jest odrzucana. **Rewokacja
  jest trwała konstrukcyjnie** — kluczowa własność przy kompromitacji klucza
  (A4). Dwustopniowość nonce (CheckTx toleruje przyszłe, FinalizeBlock wymaga
  dokładnego — ADR 011) nie osłabia obrony: rozstrzyga FinalizeBlock (T14).

### 7.3.5 Denial of Service (A1)
- Spam (T9): odrzucenie na etapie dekodowania, przed jakąkolwiek kryptografią
  (~kilka µs/tx — liczba z logu testu); legalny ruch przechodzi.
- Przerośnięte pola (T10, T11): limity walidacji (253 B domena / 256 B powód)
  odrzucają przed dotknięciem stanu.
- DoS na DNS resolver: opóźnia tylko rejestracje, timeout ogranicza (ADR 016).

## 7.4 Porównanie z klasyczną PKI

| Własność | Klasyczna PKI (X.509 + CA) | DPKI (ta praca) |
|---|---|---|
| Punkt zaufania | pojedyncze CA (i każde z ~150 w magazynie) | ≥ 2/3 z n walidatorów |
| Skutek kompromitacji punktu zaufania | dowolny cert dla dowolnej domeny (DigiNotar) | < 1/3: nic; do 2/3: halt, nie fałszerstwo |
| Rewokacja | CRL/OCSP — opóźniona, soft-fail w przeglądarkach | następny blok (~1 s), trwała, dowodliwa proofem |
| Dowód ważności | łańcuch certyfikatów + status OCSP | proof Merkle względem app hash (offline) |
| Transparentność | CT — opcjonalny dodatek | wbudowana: rejestr = łańcuch |
| Wykrywalność mis-issuance | monitoring logów CT | niemożliwa bez > 2/3 (konsensus odrzuca) |

## 7.5 Ograniczenia

Z `adversary-model.md` §5: cenzura ≥ 2/3, kompromitacja DNS w oknie
rejestracji, kradzież klucza domeny przed rotacją, eclipse klienta bez pełnego
light clienta. Plus uczciwe zastrzeżenie metodyczne: testy dowodzą, że
**konkretne ataki nie działają**, nie że system jest bezpieczny.
