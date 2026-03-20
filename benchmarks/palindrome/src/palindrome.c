// CADET's first C program (versione libc standard, vulnerabile)

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define HI "\nWelcome to Palindrome Finder\n\n"
#define ASK "\tPlease enter a possible palindrome: "
#define YES "\t\tYes, that's a palindrome!\n\n"
#define NO "\t\tNope, that's not a palindrome\n\n"
#define EASTEREGG "\n\nEASTER EGG!\n\n"

int check();

int main(int argc, char *argv[]) {
    int r;

    printf("%s", HI);

    while (1) {
        printf("%s", ASK);
        r = check();
        if (r == -1) {
            break;
        } else if (r == 0) {
            printf("%s", NO);
        } else {
            printf("%s", YES);
        }
    }
    return 0;
}

int check() {
    int len = -1;
    int i;
    int pal = 1;
    char string[64];

    // inizializza il buffer
    memset(string, 0, sizeof(string));

#ifdef PATCHED_1
    // versione sicura: legge al massimo 64 byte
    if (!fgets(string, sizeof(string), stdin))
        return -1;
#else
    // versione vulnerabile: legge fino a 128 byte in un buffer da 64
    if (!fgets(string, 128, stdin))
        return -1;
#endif

    // calcola la lunghezza (tolto il newline)
    for (i = 0; string[i] != '\0'; i++) {
        len++;
    }

    int steps = len;
    if (len % 2 == 1) {
        steps--;
    }

    for (i = 0; i <= steps / 2; i++) {
        if (string[i] != string[len - 1 - i]) {
            pal = 0;
        }
    }

    if (string[0] == '^') {
        printf("%s", EASTEREGG);
    }

    return pal;
}
