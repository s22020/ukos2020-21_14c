##### Copyright 2015 Tomasz Idzikowski
##### Przedmiot: UKOS
##### Skrypt: Wprowadzenie do podstaw PowerShell-a
#####
##### Żeby uruchomić jakikolwiek skrypt w PowerShell-u to domyślnie musi on być podpisany przez Microsoft
##### Ale można to przełączyć i w rzeczywistości praktycznie każdy tak robi bo inaczej nie da się używać PowerShell-a
##### Także, jak będziesz miał problem z uruchomieniem tego skryptu to uruchom powłokę PowerShell-a z uprawnieniami Admina
##### W pisz poniższe polecenie a następnie je zatwierdź (będzie dodatkowe pytanie o przełączenie)
#####
##### Poniższa linijka została już na stacjach w laboratorium wykonana. Nie należy jej uruchamiać w laboratorium.
##### Bo wymaga to uprawnień administratora.
#####
##### PS C:\Users\user> Set-ExecutionPlicy Bypass
##### Odpowiedz "T" lub "Y" (nie wiem jak to będzie wyglądać na polskim windowsie)
#####
##### Wtedy jak to będzie już przełączone to jako zwykły użytkownik będziesz mógł sobie uruchamiać swoje skrypty
#####
##### Zanim zaczniesz czytać i wykonywać dalej instrukcje, które zawarłem poniżej zwróć uwagę na to jak to jest napisane
##### Wszystko to co możesz bez problemu uruchomić ma przed sobą sam znak "#####" a po nim NIE MA spacji. Jeśli jest spacja
##### to jest to komentarz tak jak ten tu. W linii 25 masz coś co można uruchomić.
#####
#####
#####
##### Gdybyś potrzebował pomocy z dowolnym poleceniem by zobaczyć jaką ma składnię to pomoc używa się tak:
#####Get-Help Get-ExecutionPolicy
#####
##### A żeby zobaczyć przykłady użycia:
#####Get-Help Get-ExecutionPolicy -Examples
> Przykladowe przyklady uzycia z Get-Help:
```
PS> Unblock-File -Path .\Start-ActivityTracker.ps1
```

> Można też określić ExecutionPolicy jaki zakres obejmuje:
```
 Get-Help Get-ExecutionPolicy -Examples

NAME
    Get-ExecutionPolicy

SYNOPSIS
    Gets the execution policies for the current session.


    ------------ Example 1: Get all execution policies ------------

    Get-ExecutionPolicy -List

    Scope          ExecutionPolicy
    -----          ---------------
    MachinePolicy  Undefined
    UserPolicy     Undefined
    Process        Undefined
    CurrentUser    AllSigned
    LocalMachine   Undefined
```
#####
##### Komendy w PS (powershellu) mają pewną stałą konwencję nazewniczą. Jest to: Czasownik-NaCzymMaOperować
##### Np. Get-ExecutionPolicy, Set-ExecutionPolicy, Find-Module, Add-User, Create-Item itd...
##### Nazwa zawsze jest zbudowana w ten sam sposób.
##### Także aby zobaczyć jaki masz "ExecutionPolicy" robisz "Get-ExecutionPolicy" i dostaniesz informację
#####
##### PS ma wiele modułów, które są domyślnie zainstalowane ale nie uruchomione i trzeba je na żądanie ładować.
##### Ale najpierw trzeba wiedzieć co można załadować
#####
##### Poniższa linia zwróci Tobie wszystkie dostepne w danej chwili moduły. Może się chwilę wykonywać bo najpierw musi zebrać listę.
#####Get-Module -ListAvailable
#####
#####
#####
##### INFO: Poniższa sekcja została przygotowana na Windows 10. Na Win 7 niektóre dane są niedostępne.
#####
##### To co zwróci powyższe polecenie to lista/kolekcja, którą można przetworzyć.
##### Powiedzmy, że chcemy wyszukać tylko te moduły, których wersja jest większa lub równa 2.0 a wszystkie inne nie.
##### Wtedy korzysta się z "Where-Object" lub jego skrótu "?"


> Aliasy do Where-Object:
```
PS C:\> Get-Alias | ? {$_.Definition -Like "*Where*"}

CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Alias           ? -> Where-Object
Alias           where -> Where-Object
```
##### Znak "|" to potok (pipeline), który uruchamia kolejne polecenie na danych wyjściowych z poprzedniego polecenia
##### Jeśli podaje się kolekcję/listę/tablicę to poszczególne elementy tej kolecji po znaku | są widoczne jako "$_"
##### To taka specjalna zmienna, która jest automatycznie tworzona przez powershell'a kiedy się operuje na kolekcjach.
#####
##### Poniższa linia zwróci tylko te moduły, których wersja jest >= 2.0.0.0
#####Get-Module -ListAvailable | ? {$_.Version -ge "2.0.0.0"}
#####
##### Moduły mogą mieć wiele poleceń (to co jest w kolumnie ExportedCommands wyświetlone po przecinku)
##### A my byśmy chcieli mieć listę wszystkich poleceń w tych modułach po przefiltrowaniu wersji powyżej.
#####
##### Tak jak "?" jest skrótem na Where-Object, tak "%" jest skrótem na While-Object czyli pętlę
##### Poniższa linia wyświetli wszystkie polecenia (cmdlet - "Komandlety") w dostępnych modułach, których wersja >= 2.0.0.0
#####Get-Module -ListAvailable | ? {$_.Version -ge "2.0.0.0"} | % {Get-Command -Module $_.Name}
#####
##### Teraz byśmy chcieli jeszcze wyświetlić wszystkie te, które mają w nazwie "Add-" lub "Get-"
#####Get-Module -ListAvailable | ? {$_.Version -ge "2.0.0.0"} | % {Get-Command -Module $_.Name} | ? {($_.Name -like "Add-*") -or ($_.Name -like "Get-*")}
#####
##### A teraz byśmy chcieli je wypisać w postaci tabelki graficznej otworzonej w nowym okienku
#####Get-Module -ListAvailable | ? {$_.Version -ge "2.0.0.0"} | % {Get-Command -Module $_.Name} | ? {($_.Name -like "Add-*") -or ($_.Name -like "Get-*")} | Out-GridView
> Zwraca tabelke, po ktorej dalej mozna filtrowac komendy
##### albo do pliku
#####$nazwaPliku = "mojaNazwaPliku.txt"
#####Get-Module -ListAvailable | ? {$_.Version -ge "2.0.0.0"} | % {Get-Command -Module $_.Name} | ? {($_.Name -like "Add-*") -or ($_.Name -like "Get-*")} | Out-File $env:TEMP\$nazwaPliku
#####
##### albo nic z tym nie robić tylko by się przetworzyło ale nie wypisywało
#####Get-Module -ListAvailable | ? {$_.Version -ge "2.0.0.0"} | % {Get-Command -Module $_.Name} | ? {($_.Name -like "Add-*") -or ($_.Name -like "Get-*")} | Out-Null
> Out-Null to taki windowsowy /dev/null
#####
#####
#####
#####
#####
#####
##### Dobrze, to listy już mamy opanowane. To teraz w końcu byśmy chcieli załadować jakiś moduł np. BitsTransfer (do zarządzania przesyłaniem danych w tle)
#####Import-Module BitsTransfer
#####
##### można też użyć aliasu na Import-Module w formie:
#####ipmo BitsTransfer
```
PS C:\> Get-Alias | ? {$_.Definition -like "*import*"}                                                                  
CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Alias           ipal -> Import-Alias
Alias           ipcsv -> Import-Csv
Alias           ipmo -> Import-Module
Alias           ipsn -> Import-PSSession
```
#####
##### Wylistujmy wszystkie komendy w tym module
#####Get-Command -Module BitsTransfer
#####
##### Ok. To teraz postarajmy się użyć tego cuda do pobrania jakiegoś dużego pliku by było widać proces ściągania.
##### Ściągnijmy obraz maszyny wirtualnej do javy.
##### INFO: Obrazy używane na zajęciach są dostępne po zalogowaniu pod adresem:
##### INFO: http://szuflandia.pjwstk.edu.pl/pub/
##### INFO: Logowanie przez login i hasło do konta studenckiego
#####
##### Zapisz sobie swoje dane logowania (w bezpieczny sposób) do zmiennej by nie wpisywać ich za każdym razem
##### INFO: Do następnego zadania proszę wpisać username w formacie: sXXXXX@pjwstk.edu.pl
#####$cred = Get-Credential
#####
##### Teraz rozpocznij przesyłać plik
##### Takie przesyłanie pliku może trwać długo.
#####Start-BitsTransfer -Source http://szuflandia.pjwstk.edu.pl/pub/repo/java/lubuntu_13_04_v02.zip -Destination D:\ -Credential $cred -Authentication Negotiate
```
PS C:\> ipmo BitsTransfer
PS C:\> $cred = Get-Credential
cmdlet Get-Credential at command pipeline position 1
Supply values for the following parameters:
Credential                                                                                          
PS C:\> Start-BitsTransfer -Source https://cdimage.kali.org/kali-2020.4/kali-linux-2020.4-installer-netinst-i386.iso -Destination C:\Users\Zuza -Credential $cred -Authentication Negotiate
```
> Pojawil sie niebieski pasek sciagania, do sciagniecia pliku wcale nie potrzeba bylo credentiali, ale PowerShell sie tym nie przejal
#####
##### Jeśli chcesz to uczynić w sposób asynchroniczny (czyli taki, który nie blokuje konsoli) to można to zrobić tak
#####$job = Start-BitsTransfer -Source http://szuflandia.pjwstk.edu.pl/pub/repo/java/lubuntu_13_04_v02.zip -Destination D:\ -Credential $cred -Authentication Negotiate -Asynchronous -DisplayName "Moj Bits Transfer"
```
PS C:\> Start-BitsTransfer -Source https://cdimage.kali.org/kali-2020.4/kali-linux-2020.4-installer-netinst-amd64.iso -Destination C:\Users\Zuza -Asynchronous -DisplayName "test"                                                              
JobId                                DisplayName TransferType JobState   OwnerAccount
-----                                ----------- ------------ --------   ------------
19a46f3b-0227-41f7-837f-11dfc1ec136e test        Download     Connecting LAPTOP
```
> Sciaganie asynchroniczne o okreslonej nazwie do wyswietlania
##### By zobaczyć jaki jest stan transferu można użyć takiej komendy.
#####Get-BitsTransfer
```
PS C:\> Get-BitsTransfer | ? {$_.DisplayName -like "test"}                                                              
JobId                                DisplayName TransferType JobState    OwnerAccount
-----                                ----------- ------------ --------    ------------
19a46f3b-0227-41f7-837f-11dfc1ec136e test        Download     Transferred LAPTOP
```
#####
##### Zwrócić uwagę należy na stan w kolumnie JobState. Jeśli będzie tam Transferred to aby ukończyć całość i dostać pobierany plik
##### trzeba jeszcze zakończyć job transferu. Robi się to tak
#####Complete-BitsTransfer -BitsJob $job
```
PS C:\> Get-BitsTransfer | ? {$_.DisplayName -like "test"} | Complete-BitsTransfer
PS C:\> Get-BitsTransfer | ? {$_.DisplayName -like "test"}
PS C:\>
```
##### Teraz plik jest już dostępny w katalogu docelowym
#####
#####
#####
##### Skoro wiemy, że niektóre komendy wykonują się długo, to może byśmy chcieli zmierzyć czas wykonania polecenia.
##### Czasem może się to okazać potrzebne.
#####
##### Do mierzenia czasu służy Measure-Command
#####Measure-Command {Get-ChildItem -Path C:\Windows}
```
PS C:\> Measure-Command {Start-BitsTransfer -Source https://cdimage.kali.org/kali-2020.4/kali-linux-2020.4-installer-netinst-amd64.iso -Destination C:\Users\Zuza -Asynchronous -DisplayName "test"}                                            

Days              : 0
Hours             : 0
Minutes           : 0
Seconds           : 0
Milliseconds      : 34
Ticks             : 340284
TotalDays         : 3,93847222222222E-07
TotalHours        : 9,45233333333333E-06
TotalMinutes      : 0,00056714
TotalSeconds      : 0,0340284
TotalMilliseconds : 34,0284
```
#####
##### I tu też widzisz jak się listuje zawartość katalogu. Ale jest to nie wygodne. Może jest na to alias?
#####Get-Alias | ? {$_.Definition -like "Get-ChildItem"}
#####
> Get-ChildItem - ls w windowsie, nawet ma taki alias
```
PS C:\> Get-Alias | ? {$_.Definition -like "*Get-ChildItem*"}                                                           
CommandType     Name                                               Version    Source
-----------     ----                                               -------    ------
Alias           dir -> Get-ChildItem
Alias           gci -> Get-ChildItem
Alias           ls -> Get-ChildItem
```
##### i co? Widać znajome skróty? Szczególnie w systemach *nix-owych ;-)
##### No to wylistujmy sobie wszystkie pliki i katalogi z katalogu głównego ale z odstępem czasowym.
#####ls C:\ | %{Sleep -Milliseconds 250; return $_} | Format-Table
> Zostały wylistowane pliki i katalogi na dysku C:\ z chwilowym odstępem
```
PS C:\> ls C:\ | %{Sleep -Milliseconds 250; return $_} | Format-Table                                                   

    Directory: C:\


Mode                LastWriteTime         Length Name
----                -------------         ------ ----
d-----       17.05.2020     15:50                $WINDOWS.~BT
d-----       17.05.2020     16:22                ESD
d-----       17.10.2020     10:34                Fraps
d-----       18.10.2020     10:06                old_but_gold
d-r---       11.02.2021     22:46                Program Files
d-r---       11.02.2021     13:04                Program Files (x86)
d-r---       16.10.2020     15:24                Users
da----       13.02.2021     02:51                Windows
```
> W formie listy:
```
PS C:\> ls C:\ | %{Sleep -Milliseconds 250; return $_} | Format-List                                                    

    Directory: C:\



Name           : $WINDOWS.~BT
CreationTime   : 17.05.2020 15:50:46
LastWriteTime  : 17.05.2020 15:50:46
LastAccessTime : 17.05.2020 15:50:46
Mode           : d-----
LinkType       :
Target         : {}

Name           : ESD
CreationTime   : 17.05.2020 15:54:04
LastWriteTime  : 17.05.2020 16:22:18
LastAccessTime : 17.05.2020 16:22:18
Mode           : d-----
LinkType       :
Target         : {}
(...)
```
#####
##### Wyobraź sobie, że teraz ze skryptu PS uruchamiasz wyzwalacz na aparacie po określonym czasie, który
##### z kolei jest dynamicznie wyliczany na postawie np. pobranej z internetu wartości naświetlenia
##### z jakiegoś serwisu www. Odfiltrowana i używana jako wartość. Abstrakcja ale zapewne da się coś takiego zrobić
#####
#####
#####
#####
#####
#####
#####
##### No dobra. Ale PS to nie tylko język do pisania skryptów. To przede wszystkim konsola więc można z niej
##### uruchamiać inne programy. Do tego służy operator wołania "call", który ma postać znaku "&"
#####& C:\Windows\notepad.exe
> Przydaje sie, jak trzeba zapisac sciezke jako string do zmiennej i otworzyc notatnik, np
```
PS C:\> $fpath = "C:\Windows\notepad.exe"  
PS C:\> & $fpath 
```
#####
#####
#####
#####
#####
#####
#####
#####
#####
#####
#####
##### Ok. Było listowanie modułów i komend. A teraz wylistujmy zainstalowane aplikacje/programy.
##### Można się do tego dobrać na 2 sposoby.
##### 1. W rejestrze poszukać
##### 2. Odpytać WMI (Windows Management Instrumentation)
#####
##### 1. Rejestr
##### Informacje o zainstalowanych aplikacjach są przechowywane w:
##### HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
##### PS potrafi "wejść" do rejestru jak na dysk.
##### Ale skoro o tym mowa to sprawdźmy jakie "dyski" są dostępne w PowerShell-u.
#####Get-PSDrive
#####
```
PS C:\> Get-PSDrive                                                                                                     
Name           Used (GB)     Free (GB) Provider      Root                                               CurrentLocation
----           ---------     --------- --------      ----                                               ---------------
Alias                                  Alias
C                 291,02         33,30 FileSystem    C:\
Cert                                   Certificate   \
Env                                    Environment
Function                               Function
HKCU                                   Registry      HKEY_CURRENT_USER
HKLM                                   Registry      HKEY_LOCAL_MACHINE
Variable                               Variable
WSMan
```
##### Widać, że jest ich trochę oraz kilka takich nietypowych. Dwa z nich są odpowiedzialne za rejestr.
##### Resztę na razie pominiemy. Zatem by wejść do rejestru można zrobić tak:
#####
#####cd hklm:\
#####
##### i przeglądać sobie rejestr jak zwykły system plików
#####
#####cd .\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
#####
##### Wylistować sobie jego zawartość przez ls
#####ls
#####
##### ale to spowoduje wyświetlenie sporej ilości tekstu w brzydkiej postaci. Można to trochę zmienić
#####cd HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
#####ls | %{
#####    Get-ItemProperty $_.pspath | Select-Object DisplayName, InstallDate, UninstallString
#####} | Format-Table -AutoSize
#####
```
PS C:\> cd hklm:\
PS HKLM:\> cd .\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\
PS HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\> ls | %{Get-ItemProperty $_.pspath | Select-Object DisplayName,InstallDate,UninstallString } | Format-Table -Autosize 
```
> Ta ostatnia komenda powoduje wylistowanie nazwy, daty instalacji i komendy potrzebnej do odinstalowania programu
##### Zamiast listować na ekran, można by odinstalować korzystając z operatora wołania "&" tak jak wyżej z notatnikiem
##### tylko tutaj będzie to wyglądało tak:
#####(nie uruchamiaj jeśli nie chcesz mieć odinstalowanych wszystkich aplikacji!
#####cd HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall
#####ls | %{
#####    Get-ItemProperty $_.pspath | Select-Object DisplayName, InstallDate, UninstallString
#####} | %{& $_.UninstallString}
#####
#####
#####
#####
#####
#####
#####
#####
##### 2. WMI
##### WMI służy do zarządzania systemem i można z niego wiele ciekawych rzeczy wyciągnąć.
#####Get-WmiObject -Class Win32_Product | Format-Table -AutoSize
> Powoduje wylistowanie wszystkich zainstalowanych aplikacji i programów microsoftu
#####
##### Te numery z przodu są brzydkie, bardzo podobne i zajmują dużo miejsca a nie wnoszą nic ciekawego teraz.
##### Wyeliminujmy je:
#####Get-WmiObject -Class Win32_Product | Select-Object Name, Vendor | Format-Table -AutoSize
#####
##### a jakbyśmy chcieli znaleźć wszystkie pakiety od Microsoftu ?
#####Get-WmiObject -Class Win32_Product | ?{$_.Vendor.toLower() -like "*microsoft*"} | Select-Object Name, Vendor | Format-Table -AutoSize
#####
##### a teraz je odinstalować? (odinstalowywanie zostało osobno dodatkowo zakomentowane)
#####
############### Początek bloku do odkomentowania
#####Get-WmiObject -Class Win32_Product | ?{$_.Vendor.toLower() -like "*microsoft*"} | %{
#####	$wmiProduct = $_
#####    $answer = Read-Host "Uninstall '$($wmiProduct.Name)' [y/n]"
#####    $answer = $answer.ToLower()
#####    switch($answer) {
#####        "y" {
#####            Write-Host -NoNewline -ForegroundColor Red "Removing: "
#####            Write-Host -ForegroundColor White "$($wmiProduct.Name)"
#####            ##### odkomentowanie poniższej lini spowoduje błąd braku uprawnień dla Twojego konta
#####            #####$wmiProduct.Uninstall() ##### ta linia uruchamia deinstalację. Odkomentuj jeśli chcesz odinstalować wszystkie pakiety od Microsoftu. (nie polecam)
#####        }
#####        "n" {Write-Host "Ok. Skipping."}
#####        default {Write-Host -ForegroundColor Red "Unexpected value. Skipping uninstalling it."}
#####    }
#####}
############### Koniec bloku do odkomentowania
```
PS HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\> Write-Host -ForegroundColor Red "Warning"
Warning
```
> Powyzsze Warning wyswietla sie na czerwono
#####
#####
#####
#####
#####
#####
#####
#####
##### Dyski w PS
##### Wspomniałem, że PowerShell ma wiele dysków. Możemy je sobie wylistować poniższą komendą:
#####Get-PSDrive
#####
##### Mamy tu dyski z pojedynczymi literkami. To normalne dyski w windowsie.
##### Dyski HKML i HKCU to dyski dające dostęp do rejestru.
##### Poza tym są jeszcze:
##### - Alias - lista wszystkich zdefiniowanych aliasów w bierzącej sesji. Tam są m.in. ls, dir, ?, %
##### - Cert - magazyn certyfikatów TLS/SSL stosowanych do szyfrowania danych. Głównie połączeń sieciowych ale też i emaili czy podpisywania danych by można było sprawdzić czy treść np. dokumentu nie została zmodyfikowana. Swoją drogą skrypty PowerShell-owe też można podpisać cyfrowo
##### - Env - zmienne środowiskowe w bierzącej sesji.
##### - Function - tu są wszystkie zdefiniowane w bierzącej sesji funkcje, które można uruchomić. Podziałamy na funkcjach za chwilkę.
##### - Variable - zmienne utworzone i dostępne w bierzącej sesji. NIE SĄ to zmienne środowiskowe tylko takie zmienne lokalne.
##### - WSMan - dostęp do całego systemu WMI. Czyli to co powyżej było robione poprzez Get-WmiObject można by było spróbować pobrać z tego dysku
#####
##### Poza tymi dyskami są jeszcze inne, które można sobie dodać/dograć np:
##### - GH - GitHub - tak, można po githubie "chodzić" w PowerShell-u
##### - AD - ActiveDirectory - dodaje dysk dający dostęp do ActiveDirectory
		Dla tych co wiedzą co to jest to otwiera nowe możliwości.
		Dla tych co nie wiedzą jest kolejnym dyskiem.
##### Takie dyski dodaje się przez załadowanie specjalnych modułów, które takie dyski udostępniają.
#####
#####
#####
#####
#####
#####
#####
#####
#####
#####
##### A teraz notyfikacje :-D
##### Część przykładu pobrałem z tej strony:
##### http://www.powertheshell.com/balloontip/
#####
##### Trzeba załadować odpowiednią bibliotekę żeby można było skorzystać z tego cuda
############### Początek bloku do odkomentowania
#####[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
#####
#####$icoPath = Get-Process -id $pid | Select-Object -ExpandProperty Path
#####
#####$myNotification = New-Object System.Windows.Forms.NotifyIcon
#####$myNotification.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($icoPath)
#####$myNotification.BalloonTipIcon = 'Error'
#####$myNotification.BalloonTipText = "Your cat has meowed!" 
#####$myNotification.BalloonTipTitle = "Cat Error"
#####$myNotification.Visible = $True 
#####$myNotification.ShowBalloonTip(10000)
############### Koniec bloku do odkomentowania
#####
#####
#####
##### Ponieważ powyższe wydaje się być trochę mozolne by za każdym razem podawać te same wartości itd...
##### To można zrobić sobie własną funkcję. Uruchomienie jej znajduje się poniżej więc nie trzeba jej komentować
##### bo jak się jej nie wywoła to nic nie zrobi
#####
function GiveMePopup {
    param(
        [Parameter(Mandatory=$true)]
        $Text,
   
        [Parameter(Mandatory=$true)]
        $Title,
   
        [ValidateSet('None', 'Info', 'Warning', 'Error')]
        $Icon = 'Info',

        $Timeout = 10000
    )
    [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
    $icoPath = Get-Process -id $pid | Select-Object -ExpandProperty Path
    $myNotification = New-Object System.Windows.Forms.NotifyIcon
    $myNotification.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($icoPath)
    $myNotification.BalloonTipIcon = $Icon
    $myNotification.BalloonTipText = $Text 
    $myNotification.BalloonTipTitle = $Title
    $myNotification.Visible = $True 
    $myNotification.ShowBalloonTip(1000)
}
#####
##### I teraz można to łatwo wywołać w ten sposób
#####
> Pisanie funkcji w powershellu - wystarczy słowo kluczowe function, w środku funkcji określa się jakie przyjmuje parametry za pomocą param(), można też określić czy są obowiązkowe przez Mandatory=$true/$false
#####GiveMePopup -Text "Your cat has meowed!" -Title "Cat Error" -Icon Error
#####
```
PS HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\> [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")                                                                                                 
PS HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\> function GiveMePopup {
>>     param(
>>         [Parameter(Mandatory=$true)]
>>         $Text,
>>
>>         [Parameter(Mandatory=$true)]
>>         $Title,
>>
>>         [ValidateSet('None', 'Info', 'Warning', 'Error')]
>>         $Icon = 'Info',
>>
>>         $Timeout = 10000
>>     )
>>     [void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
>>     $icoPath = Get-Process -id $pid | Select-Object -ExpandProperty Path
>>     $myNotification = New-Object System.Windows.Forms.NotifyIcon
>>     $myNotification.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($icoPath)
>>     $myNotification.BalloonTipIcon = $Icon
>>     $myNotification.BalloonTipText = $Text
>>     $myNotification.BalloonTipTitle = $Title
>>     $myNotification.Visible = $True
>>     $myNotification.ShowBalloonTip(1000)
>> }         
PS HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\> GiveMePopup -Text "Your cat has meowed!" -Title "Cat Error" -Icon Error
PS HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\>  
PS C:\> GiveMePopup -Text "Your system has been infected with ransomware" -Title "Ransomware alert" -Icon Warning
```
##### Albo wielokrotnie:
For($i = 1; $i -le 10; $i++) {
    GiveMePopup -Text "WTF-second passed!" -Title "WTF Notification" -Icon Info
}
#####
##### Można też wiele wierszy pokazać ale max 4
#####GiveMePopup -Text "Pierwszy wiersz`nDrugi wiersz`nTrzeci wiersz`nCzwarty wiersz" -Title "Długa informacja" -Icon Info
#####
#####
#####
#####
#####
#####
#####
#####
#####
#####
##### I co? Fajne co nie? :-D
>Tworzenie tablicy
```
PS C:\> $a = @()
PS C:\> $a.GetType()

IsPublic IsSerial Name                                     BaseType
-------- -------- ----                                     --------
True     True     Object[]                                 System.Array
```
> Tablice w PowerShellu sa niemutowalne, wiec nie da sie zmodyfikowac
```
PS C:\> $a.GetHashCode()
64066812
PS C:\> $a += "a"
PS C:\> $a.GetHashCode()
56352607
```
> Te dwa hashcody się między sobą różnią, bo są tworzone nowe tablice 
> Ctrl+Space - wyswietla podpowiedzi
```
PS C:\> $a = @("a","b","c")
PS C:\> $a | ? ($_. -ne "b")
PS C:\> $a | ? {$_ -ne "b"}
a
c
```
> Write-Host - windowsowe echo