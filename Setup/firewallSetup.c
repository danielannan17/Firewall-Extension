#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include<signal.h>
#include <unistd.h>


int checkLine(char* line) {
	char* port = strtok(line, " ");
	if (!port) {
		fprintf(stderr, "ERROR: Ill-formed file");
		return -1;
	}

	char* file = strtok(NULL, " ");
	if (!file) {
		fprintf(stderr, "ERROR: Ill-formed file");
		return -1;
	}

	struct stat st;
	int p = atoi(port);
	if (p < 1 || p > 65535) {
		fprintf(stderr, "ERROR: Ill-formed file");
		return -1;
	}
	stat(file,&st);
	if (S_ISREG(st.st_mode) && access(file,X_OK) < 0) {
		fprintf(stderr, "ERROR: Cannot execute file");		
		return -1;
	}
	return 0;
}



int main(int argc, char *argv[]) {

	char buffer[1024];
	FILE* fp;
	int x;

   	if (argc == 2 && strcmp(argv[1],"L") == 0) {
		fp = fopen("/proc/firewallExtension", "r");
		if (!fp) {
			return -1;
		}
		fread(NULL,1,1,fp);
		fclose(fp);
		
    } else if (argc == 3 && strcmp(argv[1],"W") == 0) {
		FILE* rules = fopen(argv[2], "r");
		if (rules == NULL) {
			return -1;
		}

		while (fgets(buffer,1024,rules)) {
			if (checkLine(buffer) < 0) {
				fclose(rules);
				return -1;
			}
			memset(buffer, 0, 1024);
		}
		rewind(rules);
		x = open("/proc/firewallExtension", O_WRONLY);
		if (!x) {
			fclose(rules);
			return -1;
		}
		write(x,"-c",2);
		while (fgets(buffer,1024,rules)) {
			write(x,buffer,strlen(buffer)-1);
			memset(buffer, 0, 1024);
		}
		close(x);
		fclose(rules);
	}
	return 0;
}



