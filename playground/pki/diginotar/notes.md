## DigiNotar

### Co się stalo?

Doszło do włamania do holenderskiej firmy CA DigiNotar. Haker przeszedł przez wiele warstw zabezpieczeń i wystawił bardzo dużo sfałszowanych certyfikatów. Przez co w Iranie powstały strony, które naśladowały Google i przeglądarka się z nimi łączyła, ponieważ certyfikat był podpisany przez zaufany CA, czyli DigiNotar.

### Dlaczego tradycyjne PKI zawiodlo

Ponieważ CA, która jest częścią PKI, została zhakowana i jest to newralgiczny punkt. Jeżeli w CA, mimo zaufania, będzie jakiś niechciany aktor, to wszystko może się zawalić. Problemem jest też to, że przeglądarki ufają setkom różnych CA na świecie — wystarczy zhakować jedną z nich.

### Co by się zmieniło gdyby certyfikaty były na blockchainie?

Rejestr certyfikatów byłby zdecentralizowany — zamiast ufać jednemu CA, zaufanie byłoby rozłożone na tysiące węzłów sieci. Sfałszowanie historii certyfikatów byłoby praktycznie niemożliwe, bo atakujący musiałby przejąć ponad 1/3 węzłów jednocześnie. Każdy certyfikat byłby też publicznie widoczny od razu po wystawieniu — podobnie jak CT, ale bez centralnego operatora logów.

### Jak Certificate Transparency częściowo rozwiązuje ten problem?

Ponieważ wszystkie certyfikaty są zapisywane w logu CT i w każdej chwili firma Google może sprawdzić, czy ktoś nie wystawił fałszywego certyfikatu. Przeglądarka sprawdza też, czy dany certyfikat jest widoczny w CT. Natomiast CT wykrywa fałszywy certyfikat dopiero po jego wystawieniu (detektywistycznie), nie zapobiega samemu wystawieniu. Właściciel domeny musi aktywnie monitorować logi. Blockchain móże to zrobić prewencyjnie — nie da się wystawić certyfikatu bez konsensusu sieci.
