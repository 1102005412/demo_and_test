#include<string.h>
#include<stdio.h>
int main()
{
	const char *p = "leiang";
	int ret = strcmp(p,NULL);
	printf("strcmp(p,NULL)=%d",ret);
	return 0;
}
