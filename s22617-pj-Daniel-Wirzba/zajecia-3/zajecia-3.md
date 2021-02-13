# PROCESY I STRUMIENIE
### ZADANIA



**1. Program** *ps* **służy do wyświetlania listy procesów. Zobacz co sie stanie jeśli wpiszemy w terminalu:**

`ps a` - wyświetla wszystkie procesy użytkownika  
`ps -a` - wyświetla wszystkie procesy nie podłączone do żadnego terminala i procesy poza liderami sesji  
`ps x` - wyświetla wszystkie procesy, których jest się właścicielem lub wyświetlenie wszystkich procesów, jeśli użyte razem z opcją a  
`ps aux` - wyświetla wszystkie procesy tak jak w przypadku opcji a i x, a także właścicieli procesów  

**Jak myślisz, co oznacza znak zapytania w kolumnie numer 2? Nie wiesz? Zapytaj prowadzącego, albo przeczytaj manual.**

Znak "?" w kolumnie TTY oznacza, że proces nie jest podpięty do żadnego terminala.

**Wyświetl wszystkie procesy bash.**  
`pc -C bash`  
`ps -C cmdlist` - selects the processes whose executable name is given in *cmdlist*  
**Wyświetl wszystkie procesy należące do użytkownika root.**  
`ps -U root -u root u`


DODATKOWE UWAGI:  
ps -e jest identyczne z ps -A  
BSD - odmiana systemu operacyjnego Unix.  

**2.1 Uruchom wybrany przez Ciebie edytor tekstowy za pomocą menu "start" (menu aplikacji).
2.2. Zobacz, jaki ma on PID - przyda się do tego komenda ps
2.3 Wydaj komendę kill w taki sposób, aby ten edytor się wyłączył. Zobacz czy to działa. Uwaga - niektóre programy przechwytują sygnały i mogą je częściowo blokować. Jeśli program nie wyłącza się, to zobacz jaka jest jego reakcja. Zobacz czy możesz wysłać do niego SIGKILL (zerknij man).**

`kill PID`

**2.4 Zobacz działanie komendy** `killall shell`  
`killall shell` - proces shell nie został znaleziony

**2.5 Zobacz czy kill zadziała dla dowolnego procesu**  
Poleceniem `kill` nie możemy zabić procesów, które do nas nie należą (chyba, że jesteśmy rootem ofc)


DODATKOWE UWAGI:  
SIGTERM (15) - zamknięcie procesu poprawnie  
SIGKILL (9) - UNICESTWIENIE procesu  


**3.1 Uruchamiamy komendę** *cat* **bez parametrów.  
3.2 Wciśnij Ctrl+C i zobacz co się stanie**  
Ctrl+C - zabija proces sygnałem SIGINT

**3.3. Wydaj komendę** *cat > wynik1.txt* **; wpisz tekst "witaj" bez wciskania klawisza Enter; wciśnij Ctrl+C; zobacz co się znalazło w pliku** *wynik1.txt*
Plik wynik1.txt jest pusty

**3.4 Wydaj komendę** *cat > wynik2.txt* **; wpisz tekst "witaj" bez wciskania klawisza Enter; wciśnij Ctrl+D (możliwe, że będzie trzeba wcisnąć to dwa razy); zobacz co się znalazło w pliku** *wynik2.txt*  
Plik *wynik2.txt* zawiera wpisany tekst

DODATKOWE UWAGI:  
CTRL+D - zakończenie strumienia wejściowego

**4. Wpisz komendę** `gimp`**; w terminalu, w którym się to uruchomiło wciśnij Ctrl+Z; spróbuj coś wyklkiać w gimpe ;)**

CTRL+Z - zatrzymanie procesu i przeniesienie go w tło  
`bg` - służy do uruchomienia zatrzymanego procesu w tle  
`fg` - służy do przeniesienia procesu na pierwszy plan  
`jobs` - wyświetla listy zadań przeniesionych do tła  
```
gimp &
gedit &
geany &
```
Znak "&" umieszczony na końcu instrukcji nakazuje wykonanie go w tle

