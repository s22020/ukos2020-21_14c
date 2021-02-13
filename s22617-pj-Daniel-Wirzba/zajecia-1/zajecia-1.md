# Linux - Wstęp do Konsoli

### ZADANIA:

**1. Uruchom terminal**\
**2. Wyświetl zawartość aktualnego katalogu**\
`ls -al`\
**3. Sprawdź gdzie aktualnie się znajdujesz. Porównaj to z tym co możesz zobaczyć w interfejsie graficznym**\
`pwd`\
**4. Przejdź do katalogu Pulpit za pomocą ścieżki względnej**\
`cd ./Desktop`\
**5. Sprawdź gdzie jesteś**\
`pwd`\
**6. Wyświetl zawartość bieżącego katalogu**\
`ls`\
**7. Zobacz, czy przechodząc do tego katalogu w sposób graficzny (wyklikać) otrzymamy to samo?**\
W konsoli możemy wypisać wszystkie pliki, te ukryte również (ls -al), w interfejsie graficznym defaultowo wyświetlają nam się zwykłe pliki i liczba ukrytych plików\
**8. Wyświetl zawartość swojego katalogu domowego bez przechodzenia do niego (ls z odpowiednim parametrem)**\
`ls ~`\
**9. Przejdź do katalogu Obrazy w twoim katalogu domowym za pomocą ścieżki względnej**\
`cd ../Pictures`\
**10. Sprawdź gdzie jesteś**\
`pwd`\
**11 Zobacz do jakiego katalogu przejdziesz za pomocą ścieżki ././././././**\
`cd ././././././`\
Znajdziemy się w katalogu bieżącym, gdyż za pomocą `./` operujemy na bieżącym katalogu\
**12. Przejdź do swojego katalogu domowego za pomocą ścieżki bezwzględnej**\
`cd /home/ubuntu`\
**13. Zobacz co się stanie jak wpiszesz komendę 'cd /root'. Jak już to zrobisz, zastanów się co się stało. Proponuję także zapytać prowadzącego**\
*"permission denied"* - uprawnienia do katalogu (np. read) nie obejmują konta ubuntu\
**14. Zobacz, co się stanie, jeśli wciśniesz kombinację klawiszy: Ctrl+Alt+F1**\
Przechodzimy do nowej wirtualnej konsoli nr 1

### ZADANIA C.D.:
**Korzystając z komend** *cd* **oraz** *mkdir* **stwórz następujące drzewo katalogów w swoim katalofu domowym (w dowolnym podkatalogu, albo bezpośrednio w ~):**
```
cd ~
mkdir -p ukos/{katalog/{katalog2,katalog3},klamka}
```
**W katalogu** *ukos/klamka* **stwórz pliki** *zajęcia2.txt zajęcia2.log inny.txt nowy.txt*
```
cd ukos/klamka
touch zajecia2.txt zajecia2.log inny.txt nowy.txt
```
**Za pomocą jednego polecenia** *mkdir* **stwórz w katalogu ukos następujący katalog:** *ukos/to/jest/dluga/nazwa*\
`mkdir -p ukos/to/jest/dluga/nazwa`\
**następnie umieść w katalogu** *ukos/to/jest/dluga/nazwa* **plik** *dane.txt* **:**\
`touch ukos/to/jest/dluga/nazwa/dane.txt`\
**Usuń z katalogu** *ukos/klamka* **wszystkie pliki z rozszerzeniem** *txt* **:**\
`rm \*.txt`\
**Usuń katalog** *ukos/katalog/katalog2* **:**\
`rm -r katalog/katalog2`\
**Usuń cały katalog** *klamka* **za pomocą jednego polecenia:**\
`rm -r klamka`

FINI :)
