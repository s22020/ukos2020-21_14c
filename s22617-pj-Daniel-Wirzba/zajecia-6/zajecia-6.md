# Wprowadzenie do Powershell

### Polecenia i komentarze

Powershell dzieli się na 2 typy:  
Poweshell poniżej wersji 6.0 bazuje na .Net Framework a od 6.0 wzwyż na .Net Core, dzięki czemu jest przenośny (taki Powershell nazywamy Powershell Core)  
Powershell jest językiem i powłoką obiektową, co jest bardzo przydatne podczas filtrowania, szukania po polach itp.

`$PSVersionTable` - zmienna przechowująca m.in. wersję Powershella

Żeby uruchomić jakikolwiek skrypt w PowerShell-u musi on być domyślnie podpisany przez Microsoft.  
Żeby to zmienić należy:  
- uruchomić powłokę PowerShell-a z uprawnieniami Admina  
- i wpisać:  
`Set-ExecutionPolicy Bypass`
oraz potwierdzić odpowiednią literą

Żeby sprawdzić ustawienie dotyczące uruchamiania skryptów należy wpisać:  
`Get-ExecutionPolicy`

`Get-Help Get-ExecutionPolicy` - wyświetla pomoc z poleceniem `Get-ExecutionPolicy` (składnię, aliasy itp. Jeżeli chcemy bardziej rozbudowany podręcznik pomocy musimy to zainstalować manualnie poleceniem np. `Get-Help Set-ExecutionPolicy -Online`

`Get-Help Get-ExecutionPolicy -Examples` - wyświetla przykłady użycia polecenia `Get-ExecutionPolicy`

Zamiast `Get-Help` i innych poleceń możemy używać odpowiedników linuxowych np.  
*Get-Help = man*  
*Get-ChildItem = ls*  
Polecenie `man ls` również zadziała w PowerShellu.

Komendy w PS mają stałą konwencję nazewniczą. Jest to: *Czasownik-NaCzymMaOperować* np.  `Get-ExecutionPolicy`, `Find-Module`, `Create-Item` itd.

PS ma wiele modułów, które są domyślnie zainstalowane, ale nie uruchomione i trzeba je na żądanie załadować.  
`Get-Module` - wyświetli załadowane moduły  
`Get-Module -ListAvailable` - wyświetli listę wszystkich dostępnych do załadowania w danej chwili modułów. Wynikiem tego polecenia jest kolekcja obiektów. Każdy wiersz jest kolejnym obiektem.

Żeby nie czekać na wywołanie polecenia, można zapisać jego wynik do zmiennej:  
`$m = GetModule -ListAvailable`

`$m | Where-Object {$\_.version -ge "2.0"}` - wypisze wszystkie moduły, których wersja jest większa lub równa 2.0.  
*Where-Object* służy do przetwarzania kolejnych elementów (struktur) "tablicy" z polecenia. Znak "?" jest aliasem.  
*$\_* jest zmienną, która odpowiada aktualnie przetwarzanemu wierszowi.

`$m | ? { $_.version -ge "2.0" } | ForEach-Object { Get-Command -Module $_.Name }` - wypisze komendy każdego modułu, którego wersja jest większa lub równa 2.0  
*ForEach-Object* wykonuje operację na każdym elemencie w kolekcji obiektów. Znak "%" jest jego aliasem.

`Get-Command -Module \<Module>` - wyświetla listę poleceń w danym module  
`$m | ? { $\_.version -ge "2.0" } | % { Get-Command -Module $\_.Name }`  
`$m | ? { $\_.version -ge "2.0" } | % { Get-Command -Module $\_.Name } | ? {($\_.Name -like "Add-*") -or ($\_.Name -like "Get-*")}` - wyświetli polecenia, które zaczynają się od "Add-" lub "Get-"  
`$m | ? {$\_.Version -ge "2.0.0.0"} | % {Get-Command -Module $\_.Name} | ? {($\_.Name -like "Add-*") -or ($\_.Name -like "Get-*")} | Out-GridView` - wynik w postaci tabelki graficznej w nowym okienku  
`$m | ? { $\_.version -ge "2.0" } | % { Get-Command -Module $\_.Name } | ? {($\_.Name -like "Add-*") -or ($\_.Name -like "Get-*")} | Out-Null` - wynik nie wypisywany na ekranie  
Aby przekierować wynik polecenia do pliku trzeba użyć OutFile:  
```
$plik = "plik.txt"
$m | ? { $\_.version -ge "2.0" } | % { Get-Command -Module $\_.Name } | ? {($\_.Name -like "Add-*") -or ($\_.Name -like "Get-*")} | Out-File $env:TEMP\$plik
```

`Get-Content $env:TEMP\$plik` - wyświetla zawartość pliku plik.txt  

`Import-Module <module>` - komenda do załadowania modułu (ipmo - alias) np. ipmo BitsTransfer

`Get-Command -Module BitsTransfer` - wylistuje wszystkie komendy w module BitsTransfer

Pobieranie plików z internetu:  
**BitsTransfer** - usługa która ściąga coś w taki sposób, żeby nie przeszkadzała uzytkownikowi (admini często tego używają np. programista coś robi, admin sie loguje na maszyne i patchuje system w międzyczasie, jakaś nieinwazyjna zmiana)
```
ipmo BitsTransfer
$url = "https://jakies_url_plik_do_pobrania"
cd $env:TEMP\folder
Start-BitsTransfer -Source $url -Destination $env:TEMP\folder\
```
Aby pobieranie nie blokowało konsoli, należy użyć opcji -Asynchronous:  
`$j = Start-BitsTransfer -Source $url -Destination $env:TEMP\ukos\ -Asynchronous -DisplayName "moj bits transfer"`  
Aby zobaczyć potem jaki jest stan transferu należy użyć komendy:  
`Get-BitsTransfer` - stan wszystkich transferów  
lub  
`$j` - stan konkretnego transferu  
Aby ukończyć całość i dostać pobierany plik, w kolumnie JobState powinien widnieć stan "Transferred", następnie trzeba zakończyć job transferu poleceniem:  
`Complete-BitsTransfer -BitsJob $j`  
Od tej pory plik jest dostępny w katalogu docelowym.  
Jeżeli teraz wpiszemy `$j` to wyświetlą nam się 4 puste pola, bo ten obiekt już nie istnieje.

`Invoke-WebRequest` - najczęściej spotykane polecenie do pobierania czegoś z internetu. Aliasy: iwr, wget, curl.

Żeby jawnie nie wpisywać hasła, kiedy chcemy coś pobrać albo gdzieś się zalogować, można użyć polecenia:  
`Get-Credential` np.
```
$cred = Get-Credential
$j = Start-BitsTransfer -Source $url -Destination $env:TEMP\ukos\ -Asynchronous -DisplayName "moj bits transfer" -Credential $cred
```
lub  
`$j = Start-BitsTransfer -Source $url -Destination $env:TEMP\ukos\ -Asynchronous -DisplayName "moj bits transfer" -Credential`

`Get-Credential -UserName hm -Message "podaj haslo"` - przydatna integracja pomiędzy terminalem a interfejsem graficznym

Do mierzenie czasu trwania wykonywania się komendy służy:  
`Measure-Command {Get-ChildItem -Path C:\Windows}`  
`$(Measure-Command { Get-ChildItem c:\windows }).Milliseconds` - dostęp do pola bezpośrednio, bo mamy dostęp do obiektów - o niebo lepsze niż pracowanie na samym tekście


`Get-Alias` - wypisze dostępne aliasy  
`Get-Alias | ? {$\_.Definition -like "Get-ChildItem"}`

Uwagi:  
Przy pisaniu skryptów lepiej używac pełnych nazw poleceń.

Wylistowanie wszystkich plików i katalogów z katalogu głównego z odstępem czasowym:  
`ls C:\ | %{Sleep -Milliseconds 250; return $_} | Format-Table`  
*return $\_* - zwraca cały wpis

Uruchamianie innych programów z poziomu konsoli:
```
C:\Windows\notepad.exe
& C:\Windows\notepad.exe
& - operator wołania "call"
$n = "C:\Windows\notepad.exe"
& $n
```

`get-ChildItem` - listuje cokolwiek znajduje się pod daną ścieżką

Powershell ma dostęp do rejestru.  
`get-psdrive` - komenda, która zwróci dostępne dyski
```
cd hklm:\
ls
cd system
ls
```
Można po tym nawigować jak po zwykłych katalogach

`cd .\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall` - tu znajdują się informacje jak odinstalować programy  
`ls` - wyświetli sporą ilość tekstu w brzydkiej postaci  
1 kolumna, początek wiersza, jeden wpis, jeden item  
Można to wylistować inaczej, w bardziej przystępnej postaci:  
```
ls | %{
    Get-ItemProperty $_.pspath | Select-Object DisplayName, InstallDate, UninstallString
} | Format-Table -AutoSize
```
Jeśli chcemy odinstalować wszystkie aplikacje zamiast *Format-Table -Autosize* należy wpisać: 
*%{& $_.UninstallString}*

Komunikat "Czy na pewno chcesz coś uruchomić jako administrator" pojawia się tylko dlatego, że mamy włączone **UAC - User Account Control**. Najlepiej zostawić to na domyślnym ;3  
**WMI (Windows Management Instrumentation)** - mechanizm służący do zarządzania systemem (lokalnie i przez sieć).

Wyświetlanie pakietów:  
`Get-WmiObject -Class Win32\_Product | Format-Table -AutoSize`  
lub  
`Get-WmiObject -Class Win32\_Product | Select-Object Name, Vendor | Format-Table -AutoSize`

Wyświetlanie wszystkich pakietów od Microsoftu:  
`Get-WmiObject -Class Win32\_Product | ? {$_.Vendor.toLower() -like "*microsoft*" } | Select-Object Name, Vendor | Format-Table -Autosize`

UWAGA:  
Visual Studio - na czystym systemie instalowało ponad 300 pakietów. Jak sie odinstalowywało to 299 pakietów nie zostawało odinstalowywanych. Robiło się skrypty, żeby te śmieci usuwały.

Odinstalowywanie pakietów:
```
### Początek bloku do odkomentowania
#Get-WmiObject -Class Win32_Product | ?{$_.Vendor.toLower() -like "*microsoft*"} | %{
#	$wmiProduct = $_
#    $answer = Read-Host "Uninstall '$($wmiProduct.Name)' [y/n]"
#    $answer = $answer.ToLower()
#    switch($answer) {
#        "y" {
#            Write-Host -NoNewline -ForegroundColor Red "Removing: "
#            Write-Host -ForegroundColor White "$($wmiProduct.Name)"
#            # odkomentowanie poniższej lini spowoduje błąd braku uprawnień dla Twojego konta
#            #$wmiProduct.Uninstall() # ta linia uruchamia deinstalację. Odkomentuj jeśli chcesz odinstalować wszystkie pakiety od Microsoftu. (nie polecam)
#        }
#        "n" {Write-Host "Ok. Skipping."}
#        default {Write-Host -ForegroundColor Red "Unexpected value. Skipping uninstalling it."}
#    }
#}
### Koniec bloku do odkomentowania
```

**Dyski w PS**

`Get-PSDrive` - polecenie listujące dyski  
**HKML** i **HKCU** to dyski dające dostęp do rejestru  
**Alias** - lista wszystkich zdefiniowanych aliasów w bieżącej sesji. Są tam m.in. *ls, dir, ?, %*  
**WSMan** - dostęp do WMI - to co powyżej było robione poprzez `Get-WmiObject` można by było spróbować pobrać z tego dysku  
**Env** - zmienne środowiskowe w bieżącej sesji  
**Variable** - zmienne utworzone i dostępne w bieżącej sesji  
**Function** - wszystkie załadowane funkcje  
**Cert** - magazyn certyfikatów TLS/SSL stosowanych do szyfrowania danych. Głównie połączeń sieciowych ale też i emaili czy podpisywania danych by można było sprawdzić czy treść np. dokumentu nie została zmodyfikowana.  

Dyski można sobie jeszcze doinstalować np. GH (GitHub)  
`find-module *github*` - poszuka w internecie na specjalnym rejestrze modułów, które są ogólne dostępne modułów z "github" w nazwie
```
install-module GithubFS -Scope CurrentUser
ipmo
get-psdrive
ipmo GithubFS
get-psdrive
cd gh:\
```
`ls` - nie zadziała - trzeba jeszcze skonfigurować, wygenerować token z GitHuba, wstawić zmienną. Więcej szczegółów w internecie.

**Notyfikacje**
```
### Początek bloku do odkomentowania
#[void] [System.Reflection.Assembly]::LoadWithPartialName("System.Windows.Forms")
#
#$icoPath = Get-Process -id $pid | Select-Object -ExpandProperty Path
#
#$myNotification = New-Object System.Windows.Forms.NotifyIcon
#$myNotification.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($icoPath)
#$myNotification.BalloonTipIcon = 'Error'
#$myNotification.BalloonTipText = "Your cat has meowed!" 
#$myNotification.BalloonTipTitle = "Cat Error"
#$myNotification.Visible = $True 
#$myNotification.ShowBalloonTip(10000)
### Koniec bloku do odkomentowania
```

**Mniej mozolny sposób:**
```
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
```
Przykładowe wywołania powyższej funkcji:  
`GiveMePopup -Text "Your cat has meowed!" -Title "Cat Error" -Icon Error`  
lub
```
For($i = 1; $i -le 10; $i++) {
    GiveMePopup -Text "WTF-second passed!" -Title "WTF Notification" -Icon Info
}
```
Można również pokazać wiele wierszy naraz (maksymalnie 4):  
`GiveMePopup -Text "Pierwszy wiersz`nDrugi wiersz`nTrzeci wiersz`nCzwarty wiersz" -Title "Długa informacja" -Icon Info`

UWAGI:  
Można sobie również w powiadomieniu wyświetlić obrazek (poczytaj w internecie)  
http://www.powertheshell.com/balloontip/
