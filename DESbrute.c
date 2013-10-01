#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <crypt.h>
#include <string.h>

/*
 * This program should attempt to crack the DES encryption by brute (exhaustive) force.
 * The program can also be used to implement a dictionary search by including the file
 * <usr/share/dict/linux.words> or another dictionary as the second param.
 * The first param should be the passwords to be cracked,
 * the second param should be the words we want to compare with to find a match.
 * Compile with gcc -std=c99 -Wall -Werror -pedantic -o "name" name.c -lcrypt
 * @author Scott Pearson
 * @version 1.0
*/
int main(int argc, char *argv[]) {
	// If there has been two arguments supplied then continue, else return with error.
	if(argc == 3) {
 		FILE *fp;
 		FILE *fp2;
		FILE *fp3;
 		char line[BUFSIZ];
 		char line2[BUFSIZ];
 		char salt[3];
 		char linenum = 0;
 		int matchcount = 0;

 		fp = fopen(argv[1], "r");
 		fp2 = fopen(argv[2], "r");
		fp3 = fopen("crackpass.txt", "w"); 

		// If the passwords provided is not a valid file then return with error.
 		if(fp == NULL) {
 			fprintf(stderr, "Program %s: ERROR %s is not valid\n", argv[0], argv[1]);
 			exit(EXIT_FAILURE);
 		}

 		// If the comparison provided is not a valid file then return with error.
 		if(fp2 == NULL) {
 			fprintf(stderr, "Program %s: ERROR %s is not valid\n", argv[0], argv[2]);
 			exit(EXIT_FAILURE);
 		}

                printf("working....\n");

 		while(fgets(line, sizeof(line), fp)) {
 			linenum++;
 			strncpy(line, line, 14);
 			line[13] = '\0';
 			strncpy(salt, line, 3);
 			salt[2] = '\0';
 			while(fgets(line2, sizeof(line2), fp2)) {
 				strncpy(line2, line2, 4);
                int i = 0;
   				while(line2[i] != '\n' && line2[i] != '\r' && line2[i] != '\0') {
					i++;
				}
                line2[i] = '\0';
				i = 0;
 				char *guess = crypt(line2, salt);

 				// If the is a match write out the details in output file.
 				if(strncmp(guess, line, 13) == 0) {
 					fprintf(fp3, "MATCH password is %s from linenum %d: %s\n", line2, linenum, line);
 					matchcount++;
 				}
 			}
 			fclose(fp2);
 			fp2 = fopen(argv[2], "r");
 		}

 		fclose(fp);
 		fclose(fp2);
		fclose(fp3);
		printf("This program found %d matches from %d passwords, please check crackpass.txt\n", matchcount, linenum);
 		exit(EXIT_SUCCESS);
 	}
 	else {
 		fprintf(stderr, "Program %s: ERROR no passwords provided\n", argv[0]);
 		fprintf(stderr, "Usage: [passwords...] [comparison...]\n");
 		exit(EXIT_FAILURE);
 	}
 	return 0;
}
