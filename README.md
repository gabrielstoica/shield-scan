# shield-scan

## Descriere utilitar
Utilitarul shield-scan pentru detectia fisierelor noi incarcate in cadrul unui director sensibil, potentialelor modificari asupra integritatii fisierelor, precum si a atacurilor de tip RCE, XSS si URL phishing. 
Shield-scan are 3 moduri de utilizare, si anume: 
<ol>
  <li>Modul scanare continua (-u, -uploads): Presupune lansarea in background a algoritmului de detectie a noilor fisiere incarcate. Initial, sunt calculate hash-urile fisierelor din folderul ce urmeaza a fi monitorizat, urmand mai apoi compararea acestora cu hash-urile recalculate la intervale de timp regulate. Astfel, se pot depista atat noi incarcari in cadrul folderului( hash-ul noului fisier nu se va regasi in lista hash-urilor precalculate) cat si modificari ale fisierelor(cele doua hash-uri    </li>
  <li>Modul verificare integritate (-i, -integrity): Presupune calcularea hash-urilor fisierelor din cadrul unui folder de backup(de incredere) si compararea acestora cu hash-urile fisierelor din folderul pentru care se doreste a se verifica integritatea.</li>
  <li>Modul detectie continut malitios al unui fisier: Presupune scanarea continutului unui fisier dat ca parametru pentru a identifica cuvinte cheie specifice atacurilor de tip Javascript injection, XSS. De asemenea, prin intermediul API-ului Google Safe Browsing, utilitarul detecteaza URL-uri sensibile, care ar putea constitui atacuri de tip phishing.</li>
</ol>

## Instalare

1. Obtine o cheie pentru API-ul Google Safe Browsing: [https://developers.google.com/safe-browsing/v4/get-started](https://developers.google.com/safe-browsing/v4/get-started)
2. Cloneaza local repository-ul
   ```sh
   git clone https://github.com/GabrielStoica/shield-scan.git
   ```
3. Plaseaza cheia obtinuta in fisierul google_safe_browsing.sh
   ```sh
   key="API_KEY_HERE"
   ```
4. Modifica campul clientID
   ```sh
   \"clientId\": \"NUMELE-UTILIZATORULUI\",
   ```
  
## Dependinte & API-uri utilizate

Pentru identificarea URL-urilor potential malitioase, a fost integrat API-ul:
- [Google Safe Browsing][2]

Pentru parsarea fisierelor JSON transmise API-ului Google Safe Browsing, utilitarul foloseste Linux Jq:
- [Linux Jq - JSON Processing][1]

[1]: https://stedolan.github.io/jq/
[2]: https://developers.google.com/safe-browsing/
