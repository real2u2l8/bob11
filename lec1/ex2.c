#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

void spawn_shell(){
	printf("There you are!\n");
	setregid(getegid(), getegid());
	execl("/bin/bash", "bash", NULL);
}

int main(){
	char buf[512];
	printf("What is your password?\n");
	scanf("%s", buf);
	if(strcmp(buf, "Password") == 0){
		printf("Correct!\n");
		spawn_shell();
	}
	else{
		printf("Wrong password!\n");
	}
	return 0;
}


