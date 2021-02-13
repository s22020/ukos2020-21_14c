# Prawa dostępu

### ZADANIA:

**1. Utworzyć we własnym katalogu domowym niedużą strukturę podkatalogów i plików tekstowych. Przydzielić różne prawa dostępu, następnie spróbować wejść do katalogów domowych innych uczestników zajęć i sprawdzić, które z obiektów są tam dla nas dostępne (i w jakim sensie). Spróbować utworzyć własny plik w cudzym katalogu ("kukułcze jajko") oraz spróbować usunąć cudzy plik we własnym katalogu (co można zaobserwować ?). Wypróbować powyższe operacje:
	-  w trybie tekstowym,
	- przy użyciu programu Midnight Commander (mc),
	- przy użyciu graficznego interfejsu użytkownika.**

Katalogi posiadają uprawnienia 755, pliki zaś 644.
`chmod g+w dir` dodajemy bit zapisu dla grupy dla katalogu dir, aby ktoś mógł zostawić tam "kukułcze jajo". Polecenie `ls -al` pozwoli nam dowiedzieć się, kto ten plik utworzył (kto jest jego właścicielem). Na tym etapie tylko właściciel pliku i root może zmieniać te uprawnienia. Możemy jednak go usunąć.

**2. W utworzonej na swoim koncie strukturze podkatalogów przeprowadzić eksperymenty:
	- usuwając wszelkie prawa dostępu do katalogu bieżącego;
	- usuwając wszelkie prawa dostępu dostępu do katalogu nadrzędnego (nadkatalogu).
W jakich przypadkach możemy wykonać wtedy polecenie** *cd* **? W jakich przypadkach możemy wykonac polecenie** *chmod* **? Czy możemy bezpośrednio przeskoczyc do katalogu ABC/XYZ, jeśli nie mamy prawa wstępu do ABC, ale mamy do XYZ ?**
```
mkdir -p a/b
cd a/b
touch p
ls -al
chmod 000 .
```
`ls -al` brak dostępu. W przypadku `cat p` to samo. `chmod 755 .` tutaj również brak dostępu. Jak odbierzemy uprawnienia do katalogu nadrzędnego to zamkniemy się w katalogu w jakim się znajdujemy. Żeby wyjść musimy użyć ścieżki absolutnej albo poprosić o pomoc z zewnątrz.

**3. W zespołach 2- lub 3-osobowych wypróbować możliwość komunikacji przez współdzielony plik: na jednym z kont w zespole utworzyć pusty plik i przydzielić odpowiednie prawa dostępu (do pliku i do katalogu domowego). Wpisywać i odczytywać komunikaty przy użyciu poleceń:**
`echo treść_komunikatu > plik`
`cat plik`
**Sprawdzić, jaki skutek powoduje zamiana operatora > na operator >> w poleceniu echo. Uruchum także drugi terminal i wykonaj w nim komendę** `tail -f plik` **i powtórz powyższe ćwiczenie w pierwszym terminalu (komunikacja za pomocą pliku).**

`chmod g+w plik` dodajemy bit zapisu dla grupy dla pliku plik, aby ktoś mógł go edytować.
`tail -f plik` wyświetlamy ostanie wiersze pliku, aby widzieć czy coś jest do niego dopisywane (przez innego użytkownika). W tym momencie utworzyliśmy mini chat.\
`chmod g-w .` abyśmy później nie mieli niespodzianek\
">" z poleceniem echo nadpisuje/tworzy plik ze wskazaną w poleceniu zawartością\
">>" dopisuje do pliku określoną przez nas w poleceniu zawartość

**Znaleźć w swoim katalogu domowym podkatalog** *public_html* **(jeśli go nie ma, to utworzyć. Umieścić w nim plik o nazwie** *strona.html* **i następującej zawartości:**
```
<HTML>
<BODY>
<H1>To jest moja strona domowa</H1>
</BODY>
</HTML>
```

**Sprawdzić, jakie są minimalne prawa dostępu, które trzeba przydzielić do:\
	- katalogu domowego;\
	- katalogu** `public_html`;\
	- **pliku** *strona.html* **, aby zawartość pliku była widoczna w przeglądarce internetowej pod adresem** *http://szuflandia.pjwstk.edu.pl/~nazwa_konta/strona.html*

Dla katalogu domowego, bit x dla innych użytkowników, aby wejść do katalogu
Dla *public_html*, bit r i x dla innych użytkowników, aby wejść do katalogu i wyświetlić jego zawartość (plik strona.html)
Dla *strona.html*: bit r dla innych użytkowników, aby wyświetlić zawartość pliku

UWAGI:\
Na maszynie wirtualnej działało, na mojej głównej przeglądarce witryna była nieosiągalna :(


### ZADANIA C.D
**W opisie bash'a (man) przeczytać opis polecenia wewnętrznego umask i wypróbować jego działanie sprawdzając, a następnie zmieniając swoją maskę trybu pliku i tworząc za każdym razem nowe pliki (przy uzyciu polecenia** `touch plik`**), a później sprawdzając uzyskane prawa dostępu do nich (polecenie ls -l). Jaka operacja logiczna na bitach domyślnych praw dostępu oraz maski jest wykonywalna?**

umask (user mask) - polecenie interfejsu POSIX, które odpowiada za ograniczanie praw dostępu do plików.

W przypadku plików uprawnienia domyślne są na poziomie 664, bo domyślnie dla plików systemu z jądrem Linux nie dają prawa executre przy tworzeniu, tak więc pomimo ustawionej maski pliki domyślne mają uprawnienia 664.
