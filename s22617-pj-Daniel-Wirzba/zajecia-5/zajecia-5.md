# Edytory programistyczne - start

### ZADANIA

**Utwórz plik o nazwie program.c za pomocą polecenia** `touch`, **a dopiero później go otwórz w aktualnym testowanym edytorze. Wpisz taką zawartość. Juz na początku zaobserwujesz pewne ciekawe zjawiska (w zależności od edytora). Polecam sprawdzić: nano, vi, mcedit, geany oraz atom (o ile jest) lub jedit**
```
#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	for (i = 0; i < 10; i++)
	{
		printf("+----------------------------------------------+\n");
		printf("|                                              |\n");
		printf("|                  Liczę: %d                   |\n");
		printf("|                                              |\n");
		printf("+----------------------------------------------+\n");
	}
	return 0;
}
```
**Jakie masz obserwacje? Czy działo się coś "ciekawego" po wciśnięciu klawisza Enter? Po wpisaniu nawiasu? Czy coś się dzieje z kolorami?**  
**W niektórych edytorach można wykorzystać uzupełnianie składni. Zobacz co sie stanie po wciśnięciu Ctrl+Spacja po wpisaniu pierwszych znaków komendy (na przykład printf) (na pewno to działa w edytrze Geany)**

W nano spacje/taby są kolorowe do wprowadzenia kolejnego znaku. Podświetlanie składni, słów kluczowych itp.

W vi również jest podświetlanie składni, słów kluczowych. Po wciskaniu enter przy tworzeniu instrukcji warunkowej kursor automatycznie jest ustawiany z wcięciem w nowej linii.

W mcedit jest graficzna, symboliczna reprezentacja znaku tabulacji (<---->), zmienia się kolor tła, nie ma limitu na ciąg znaków w jednej linii (albo jest całkiem długi), również podświetlane są słowa kluczowe, ponadto, można klikać myszką na interfejsie na dole.

Geany posiada prawdziwy graficzny interfejs, podpowiada i uzupełnia składnię, można nawigować myszką po pliku.

Atom oraz jedit domyślnie nie były zainstalowane na maszynie.

**Teraz zamień pionowe kreski na znaki hash # i zapisz jako nowy plik o nazwie nowy.c**  
**Wykonaj taką komendę w terminalu:**  
`diff nowy.c program.c`  
**A teraz jeszcze:**  
`diff -y nowy.c program.c`  
**To jest program do porównywania plików. Pozwala na wyświetlenie informacji o zmianach, w tym informację o tym na których liniach coś zostało zmienione.**

