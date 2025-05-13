# LupinOne - HackMyVM (Medium)

![Lupinone.png](Lupinone.png)

## Übersicht

*   **VM:** LupinOne
*   **Plattform:** HackMyVM (https://hackmyvm.eu/machines/machine.php?vm=Lupinone)
*   **Schwierigkeit:** Medium
*   **Autor der VM:** DarkSpirit
*   **Datum des Writeups:** 10. Oktober 2022
*   **Original-Writeup:** https://alientec1908.github.io/Lupinone_HackMyVM_Medium/
*   **Autor:** Ben C.

## Kurzbeschreibung

Das Ziel dieser Challenge war es, Root-Rechte auf der Maschine "LupinOne" zu erlangen. Der initiale Zugriff erfolgte durch das Auffinden einer versteckten Datei (`.mysecret.txt`) in einem über das Web zugänglichen Benutzerverzeichnis (`/~secret/`). Der Inhalt dieser Datei war ein Base58-kodierter, passwortgeschützter privater SSH-Schlüssel. Nach dem Knacken der Passphrase konnte eine SSH-Verbindung als Benutzer `icex64` hergestellt werden. Die erste Rechteausweitung zum Benutzer `arsene` gelang durch Modifizieren einer Python-Systembibliothek (`webbrowser.py`), die von einem Skript importiert wurde, welches `icex64` mittels `sudo` als `arsene` ausführen durfte. Die finale Eskalation zu Root erfolgte durch Ausnutzen einer unsicheren `sudo`-Regel, die `arsene` erlaubte, `pip` als Root auszuführen, was zur Ausführung einer bösartigen `setup.py`-Datei führte.

## Disclaimer / Wichtiger Hinweis

Die in diesem Writeup beschriebenen Techniken und Werkzeuge dienen ausschließlich zu Bildungszwecken im Rahmen von legalen Capture-The-Flag (CTF)-Wettbewerben und Penetrationstests auf Systemen, für die eine ausdrückliche Genehmigung vorliegt. Die Anwendung dieser Methoden auf Systeme ohne Erlaubnis ist illegal. Der Autor übernimmt keine Verantwortung für missbräuchliche Verwendung der hier geteilten Informationen. Handeln Sie stets ethisch und verantwortungsbewusst.

## Verwendete Tools

*   `arp-scan`
*   `ping6`
*   `nmap`
*   `ffuf`
*   `curl`
*   CyberChef (impliziert für Base58-Dekodierung)
*   `ssh2john`
*   `john`
*   `ssh`
*   `find`
*   `nano` / `vi`
*   `os` (Python module)
*   `sudo`
*   `python3.9`
*   `pip`
*   `mktemp`
*   `echo`
*   Standard Linux-Befehle (`sh`, `tty`, `id`, `cd`, `cat`, `ls`)

## Lösungsweg (Zusammenfassung)

Der Angriff auf die Maschine "LupinOne" gliederte sich in folgende Phasen:

1.  **Reconnaissance (IPv4 & IPv6):**
    *   IPv4-Adresse des Ziels (192.168.2.135) mit `arp-scan` identifiziert.
    *   IPv6-Link-Local-Adresse (`fe80::a00:27ff:fe60:64b0%eth0`) mit `ping6` gefunden.
    *   `nmap`-Scans bestätigten offene Ports 22/tcp (SSH) und 80/tcp (HTTP) auf IPv4 und IPv6.

2.  **Web Enumeration (User Dirs & Secrets):**
    *   Mittels `ffuf` wurde das Benutzerverzeichnis `http://192.168.2.135/~secret/` entdeckt.
    *   Ein weiterer `ffuf`-Scan innerhalb dieses Verzeichnisses fand die versteckte Datei `http://192.168.2.135/~secret/.mysecret.txt`.

3.  **Credential Access (Base58 & SSH Key Crack):**
    *   Der Inhalt von `.mysecret.txt` war ein langer Base58-kodierter String.
    *   Nach der Dekodierung (z.B. mit CyberChef) wurde ein passwortgeschützter privater SSH-Schlüssel im OpenSSH-Format enthüllt.
    *   Mittels `ssh2john` wurde der Hash der Passphrase extrahiert und mit `john` und `rockyou.txt` geknackt. Die Passphrase war `P@55w0rd!`.

4.  **Initial Access (SSH als `icex64`):**
    *   Erfolgreicher SSH-Login als Benutzer `icex64` unter Verwendung des privaten Schlüssels und der geknackten Passphrase `P@55w0rd!`.
    *   Die User-Flag (`3mp!r3{I_See_That_You_Manage_To_Get_My_Bunny}`) wurde in `/home/icex64/user.txt` gefunden.

5.  **Privilege Escalation (von `icex64` zu `arsene` via Python Lib Hijack):**
    *   `sudo -l` als `icex64` zeigte, dass der Befehl `/usr/bin/python3.9 /home/arsene/heist.py` als Benutzer `arsene` ohne Passwort ausgeführt werden durfte.
    *   Die System-Python-Bibliothek `/usr/lib/python3.9/webbrowser.py` war für `icex64` beschreibbar.
    *   `os.system("/bin/bash")` wurde am Anfang der `webbrowser.py`-Datei eingefügt.
    *   Durch Ausführen von `sudo -u arsene /usr/bin/python3.9 /home/arsene/heist.py` wurde die modifizierte Bibliothek importiert und eine Shell als Benutzer `arsene` gestartet.

6.  **Privilege Escalation (von `arsene` zu `root` via `sudo pip`):**
    *   `sudo -l` als `arsene` zeigte, dass der Befehl `/usr/bin/pip` als `root` ohne Passwort ausgeführt werden durfte: `(root) NOPASSWD: /usr/bin/pip`.
    *   Ein temporäres Verzeichnis wurde erstellt (`TF=$(mktemp -d)`).
    *   Eine bösartige `setup.py`-Datei wurde in diesem Verzeichnis erstellt, die eine Shell startet (`echo "import os; os.execl('/bin/sh', 'sh', '-c', 'sh <$(tty) >$(tty) 2>$(tty)')" > $TF/setup.py`).
    *   Durch Ausführen von `sudo pip install $TF` wurde die `setup.py` als Root ausgeführt, was zu einer Root-Shell führte.
    *   Die Root-Flag (`3mp!r3{congratulations_you_manage_to_pwn_the_lupin1_box}`) wurde in `/root/root.txt` gefunden.

## Wichtige Schwachstellen und Konzepte

*   **Information Disclosure (Secret in Web Directory):** Ein Base58-kodierter, passwortgeschützter privater SSH-Schlüssel wurde in einer versteckten Datei in einem öffentlich zugänglichen Benutzerverzeichnis gefunden.
*   **Schwache SSH-Key-Passphrase:** Die Passphrase des privaten SSH-Schlüssels (`P@55w0rd!`) konnte leicht mit einem Wörterbuchangriff geknackt werden.
*   **Unsichere Dateiberechtigungen (Python System Library Hijacking):** Eine System-Python-Bibliothek war für einen unprivilegierten Benutzer beschreibbar, was das Einschleusen von Code ermöglichte, der dann von einem Prozess mit höheren Rechten (hier: `sudo -u arsene`) ausgeführt wurde.
*   **Unsichere `sudo`-Regeln:**
    *   `icex64` durfte ein Python-Skript als `arsene` ausführen.
    *   `arsene` durfte `pip` als `root` ohne Passwort ausführen, was eine bekannte Methode zur Privilegieneskalation darstellt (GTFOBins).
*   **User Directory Enumeration (`~user`):** Auffinden von Benutzerverzeichnissen über die Tilde-Notation auf dem Webserver.

## Flags

*   **User Flag (`/home/icex64/user.txt`):** `3mp!r3{I_See_That_You_Manage_To_Get_My_Bunny}`
*   **Root Flag (`/root/root.txt`):** `3mp!r3{congratulations_you_manage_to_pwn_the_lupin1_box}`

## Tags

`HackMyVM`, `LupinOne`, `Medium`, `Information Disclosure`, `Base58`, `SSH Key Cracking`, `Python Library Hijacking`, `sudo Exploit`, `pip Exploit`, `GTFOBins`, `Linux`, `Web`, `Privilege Escalation`
