#include <stdio.h>
#include <unistd.h>
#include<string.h>
#include<stdlib.h>
#include <time.h>

char strmagic[32];
unsigned char random_bytes[8];

void setupbuf()
{
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
}

void win(){
	system("cat flag.txt");
}

void Time_Freeze(){
	printf("Pause time, enter to continue:");
	getchar();
	printf("\033[1A\033[K");
} 

void Elementary_Magic(){
	char strnum[20];
	long long int num;
	long long int rd; 
	long long int result;
	long long int time1;
	int temp =time(0);
	printf("%d\n", temp);
	srand(temp);
	rd = rand();//1
	Time_Freeze();
	time1= (int)time(0);//2
	
	printf("Shout out the magic number sequence!\n");
	read(0, strnum, 20);
	num = atoll(strnum);//3
	
	result= (long long int)num^rd^time1;
	
//	printf("Result = %lld\n", result);
	
	if(result!=0xdeadbeefdeadc0de) {
		printf("What the hell are you shouting? It's disappointing~\n");
		exit(0); 
	}
} 


void Advanced_Magic(){
	char strnum[20];
	long long int num;
	long long int result;
	long long int timerd;
	long long int randval = 0;
	
	int fd = open("/dev/urandom", 0);
	if (fd == -1) {
		perror("open");
		exit(1);
	}
	
	read(fd, random_bytes, 8);
	for (int i = 1; i <= 8; i++) {
		randval = (randval << 8) + random_bytes[8-i];
	}
//	printf("The random bytes are: %s\n", random_bytes);
	printf("Scream your advanced magic!\n");
    int c;
    while ((c = getchar()) != '\n' && c != EOF);
	read(0, strmagic, 32);
	printf("\033[1A\033[K");
	puts(strmagic);//1
	

	Time_Freeze();
	srand(time(0));
	timerd= rand();//2

	printf("Shout out the magic number sequence!");
	read(0, strnum, 20);
	num = atoll(strnum);//3

//	printf("prgram rd = %lld\n", timerd);
//	printf("randval = %llx\n", randval);
//	printf("num = %lld\n", num);
	
	result= (long long int)randval^timerd^num;
	
//	printf("Result = %llx\n", result);
	
	if(result!=0xdeadbeefdeadc0de) {
		printf("What the hell are you shouting? It's disappointing~\n");
		exit(0); 
	}
	printf("It's admirable, you are the lord of ****!\n");
	
} 

int main(){
	setupbuf();
	printf("================================Elementary_Magic================================\n");
	Elementary_Magic();
	system("clear");
	printf("================================Advanced_Magic================================\n");
	Advanced_Magic(32, 8);
	win(); 
	return 0;
}
