#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

int print_number(int num){	
	printf("Your number is %d.\n", num);
	return 0;
}

int main(){	
	int number = 0;
	printf("Tell me your favorite number:\n");
	scanf("%d", &number);
	print_number(number);
	return 0;
}
