# shield-scan

## Descriere utilitar
Utilitarul shield-scan a fost conceput pentru detectia fisierelor noi incarcate in cadrul unui director sensibil, potentialelor modificari asupra integritatii fisierelor, precum si a atacurilor de tip RCE, XSS si URL phishing. 
Shield-scan dispune de urmatoarele moduri de utilizare, si anume: 
<ol>
  <li>Modul scanare continua (-u, -uploads): Presupune lansarea in background a algoritmului de detectie a noilor fisiere incarcate. Initial, sunt calculate hash-urile fisierelor din folderul ce urmeaza a fi monitorizat, urmand mai apoi compararea acestora cu hash-urile recalculate la intervale de timp regulate. Astfel, se pot depista atat noi incarcari in cadrul folderului( hash-ul noului fisier nu se va regasi in lista hash-urilor precalculate) cat si modificari ale fisierelor(cele doua hash-uri    </li>
  <li>Modul verificare integritate (-i, -integrity): Presupune calcularea hash-urilor fisierelor din cadrul unui folder de backup(de incredere) si compararea acestora cu hash-urile fisierelor din folderul pentru care se doreste a se verifica integritatea.</li>
  <li>Modul detectie continut malitios al unui fisier: Presupune scanarea continutului unui fisier dat ca parametru pentru a identifica cuvinte cheie specifice atacurilor de tip Javascript injection, XSS. De asemenea, prin intermediul API-ului Google Safe Browsing, utilitarul detecteaza URL-uri sensibile, care ar putea constitui atacuri de tip phishing.</li>
  <li>Modul detecție fișiere care au suferit modificări în ultimele N zile (-cm, -check_mod):  Presupune scanarea și analizarea fișierelor din cadrul unui director dat ca parametru, din punct de vedere al perioadei de timp care a trecut de la ultima modificare. Utilizatorul, prin intermediul parametrului opțional -mt, poate specifica numărul N de zile.</li>
  <li>Modul scanare prin intermediul regulilor YARA (-y, --yara): Scanează fișierul dat ca parametru utilizând reguli de tip YARA, regăsite în cadrul directorului yara-rules, pentru a putea identifica anumiți indicatori de compromis(IOC-uri) specifici atacurilor întâlnite în cadrul platformelor Wordpress, Joomla, Drupal, dar și atacurilor de tipul XSS, SQL Injection și Cryptojacking.</li>
  <li>Modul verificare extensie fișier ( -e, --extension): Verifică dacă extensia fișierului dat ca parametru este cea reală. Tot procesul este realizat prin intermediul regulilor YARA, încercându-se identificarea octeților magici(primii octeți din cadrul unui fișier), care au diferite valori fixe în funcție de extensia fișierului. Dacă un fișier a fost creat inițial cu extensia .jpg și  apoi redenumit în .png, script-ul va identifica acest lucru și va notifica utilizatorul. Identificarea se realizează cu ajutorul semnăturilor tipurilor de fișiere, disponibile în cadrul folderului file-signatures.</li>
  <li>Opțiunea verbose ( -v, -verbose): Utilitarul poate primi ca și parametru opțional modul verbose, care determină afișarea mai multor detalii și informații în legătură cu fiecare etapă ce urmează a fi executată în cadrul operațiilor de scanare și identificare.</li>
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
5. Modifica permisiunile shield-Scan.sh
   ```sh
   chmod +x shield-Scan.sh
   ```
6. Ruleaza utilitarul in modul -h,--help pentru a incepe:
   ```sh
   ./shield-Scan --help
   ```
## Dependinte & API-uri utilizate

Pentru identificarea URL-urilor potential malitioase, a fost integrat API-ul:
- [Google Safe Browsing][2]

Pentru parsarea fisierelor JSON transmise API-ului Google Safe Browsing, utilitarul foloseste Linux Jq:
- [Linux Jq - JSON Processing][1]

Pentru identificarea indicatorilor de compromis la nivelul fisierelor scanate sunt folosite reguli de tip YARA:
- [Compiling and installing YARA][3]

[1]: https://stedolan.github.io/jq/
[2]: https://developers.google.com/safe-browsing/
[3]: https://yara.readthedocs.io/en/stable/gettingstarted.html

## Help mode
   ```sh
     |\                     /)
 /\_\\__               (_//
|   `>\-`     _._       //`)  ########  ##     ## #### ######## ##       ######### 
 \ /` \\  _.-`:::`-._  //    ##         ##     ##  ##  ##       ##       ##      ##  
  `    \|`    :::    `|/      #######   #########  ##  ######   ##       ##       ##
        |     :::     |             ##  ##     ##  ##  ##       ##       ##      ## 
        |:::::::::::::|      ########   ##     ## #### ######## ######## #########
        |     :::     |    
         \    :::    /                ########  #######  #######  ##     ##
          `-. ::: .-'                ##        ##       ##     ## ###    ##
           //`:::`\\                  #######  ##       ######### ## ##  ## 
          //   '   \\                       ## ##       ##     ## ##  ## ##
         |/         \\               ########   ####### ##     ## ##    ###

        Utilitar conceput pentru detectia modificarilor si analiza integritatii fisierelor
                de configurare din cadrul platformelor de tip CMS: Wordpress, Drupal si
        Joomla, pentru a putea anticipa comportamente malitioase specifice unei game largi de
                        atacuri, printre care: XSS, SQL Injection, Phishing 

                (c) Stoica Gabriel-Marius <marius_gabriel1998@yahoo.com> 
 
Mod de utilizare: ./shield-Scan.sh [-h] OPTIONS {target} 
 
avand semnificatia: 
         -h, --help 
                Ajutor, arata modul de utilizare

         -f, --file
                Specifica fisierul ce urmeaza a fi scanat

         -v, --verbose 
                Activeaza modul afisare explicita, determinand utilitarul sa afiseze 
                informatii intermediare intre operatiile efectuate

         -e, --extension
                Verifica daca extensia fisierului dat ca parametru este cea reala.
                In caz contrat, incearca identificarea extensiei reale

         -u, --uploads [/path/to/directory] 
                Scanaza un director tinta pentru detectia incarcarii noilor fisiere: 
                asteapta ca parametrul calea catre un director 

         -i, --integrity [/path/to/backup/ path/to/actual_dir/] 
                Calculeaza hash-ul fisierelor din folderul de backup si il compara 
                cu hash-ul fisierelor din folderul scanat, pentru a identifica potentiale 
                modificari

         -d, --detect [/path/to/file.txt] 
                Efectueaza scanarea completa a unui fisier dat ca parametru,
                impotriva atacurilor de tip XSS, Javascript code,
                URL-uri de tip phishing
 
         -cm, --check-mod [/path/to/directory/] [-mt N] 
                Efectueaza scanarea completa a unui director dat ca parametru,
                si identifica fisierele care au suferit modificari
                in ultimele N zile

         -y, --yara [PARAMETRU]
                Scaneaza fisierul dat ca parametru utilizand reguli YARA pentru a
                identifica IOC-uri si alte tipuri de atacuri. Suporta urmatoarele
                tipuri de PARAMETRII: wordpress, joomla, drupal, xss, sql, cryptojacking
   ```

