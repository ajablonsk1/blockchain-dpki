# ADR 013: Wyzwanie DNS-01 do weryfikacji własności domeny

## Status
Zaakceptowany

## Kontekst
Bez dowodu, że rejestrujący włada domeną, DPKI jest Trust-On-First-Use: kto
pierwszy wyśle `RegisterTx` dla `example.com`, ten wygrywa, nawet jeśli nie jest
właścicielem. Weryfikacja kontroli to centralne pytanie badawcze projektu.
Opcje:

| Opcja | Jak | Zalety | Wady |
|---|---|---|---|
| DNS-01 | Właściciel publikuje rekord TXT pod `_dpki-challenge.<domena>` | Standard branżowy (ACME), obsługuje wildcardy, niezależny od HTTP/HTTPS | Ufa DNS; nie każdy kontroluje DNS |
| HTTP-01 | Właściciel udostępnia plik pod `/.well-known/...` | Proste dla każdego z serwerem WWW | Brak wildcardów; HTTPS „jajko-kura" z samym DPKI |
| Dziedziczenie X.509 | Właściciel podpisuje wyzwanie istniejącym certyfikatem od CA | Wykorzystuje istniejące PKI | Wymaga klasycznego CA — przekreśla sens DPKI |

## Decyzja
Używamy **wyzwania w stylu DNS-01**, wzorowanego na ACME / Let's Encrypt.
Właściciel publikuje deterministyczną wartość (ADR 015) w rekordzie TXT pod
`_dpki-challenge.<domena>`; walidator potwierdza ją zapytaniem DNS
(`internal/verifier.DNSVerifier`). Verifier jest interfejsem, więc `MockVerifier`
może go zastąpić w testach i uruchomieniach bez DNS.

## Konsekwencje
- **Pozytywne:** rozpoznawalny, cytowalny mechanizm („jak w Let's Encrypt");
  obsługuje domeny wildcard; niezależny od certyfikatu, który bootstrapuje, co
  unika problemu „jajko-kura" z HTTPS.
- **Pozytywne:** pojedyncza, dobrze zdefiniowana zależność zewnętrzna (DNS) za
  małym interfejsem; podmiana lub dodanie HTTP-01 później to nowa implementacja,
  a nie przepisanie.
- **Negatywne:** bezpieczeństwo opiera się na integralności rozwiązywania DNS;
  przeciwnik spoofujący DNS może podać fałszywą wartość TXT. Wpływ jest
  ograniczony — atakujący nadal nie ma klucza prywatnego i nie podpisze
  użytecznej transakcji — ale to realne ograniczenie, omówione w analizie
  bezpieczeństwa. DNSSEC zapisany jako przyszła praca.
- **Negatywne:** domeny, których właściciele nie mogą edytować DNS, nie mogą się
  zarejestrować; to to samo ograniczenie, co w ACME DNS-01.
