#include<stdlib.h>
#include<stdlib.h>

int main(){
	unsigned int v0=time(0);
	srand(v0);
	int r=rand()%5+48;
	printf("%c",r);
}
