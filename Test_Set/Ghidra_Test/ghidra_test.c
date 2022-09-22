#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <sys/ioctl.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

struct struct_test 
{ 
   char test1[50]; 
   char test2[100]; 
   char test3[50]; 
   char test4[20]; 
   int test5; 
};

int global_test; 
char global_test2;
void test1_no_par();
void test2_one_par(int par1);
void test3_two_par(int par1, int par2);
void test4_two_par_ptr(char *par1, char *par2);
void test5_seven_par(int par1, int par2, char *par3, char *par4, char *par5, char *par6, char *par7);
void test6_one_par_call(int par1);
void test7_two_par_call(char *par1, int par2);
void test8_seven_par_call(int par1, int par2, char *par3, char *par4, char *par5, char *par6, char *par7);
void test9_struct_init(struct struct_test *);
void test10_struct_uninit(struct struct_test *);
void test11_struct_by_value(struct struct_test struct1);
void test12_casting(char charpar, int ipar, float fpar);

int main() 
{
    int ipar1 = 10;
	int ipar2 = 20;
	int ipar3 = 30;
	float fpar1 = 10.1;
	char charpar1 = 'a';
	char cpar1[] = {"Hello World"};
	char cpar2[50] = {"abcdefghijklmnopqrstuvwxyz"};
	char cpar3[] = {"123456789"};
	char cpar4[] = {"test test test"}; 
	char cpar5[] = {"as;lfjaslkdfnalkfhaslk"};
	struct struct_test struct1 = {"", "", "", "", 0};
	struct struct_test struct2;
	struct struct_test struct3 = {"TEST TEST", "TEST TEST", "TEST TEST", "TEST TEST", 4};

	test1_no_par();
	test2_one_par(ipar1);
	test3_two_par(ipar1, ipar2);
	test4_two_par_ptr(cpar1, cpar2);
	test5_seven_par(ipar1, ipar2, cpar1, cpar2, cpar3, cpar4, cpar5);
	test6_one_par_call(ipar3);
	test7_two_par_call(cpar1, ipar2);
	test8_seven_par_call(ipar1, ipar2, cpar1, cpar2, cpar3, cpar4, cpar5);
	test9_struct_init(&struct1);
	test10_struct_uninit(&struct2);
	test11_struct_by_value(struct3);
	test12_casting(charpar1, ipar1, fpar1);

}

void test1_no_par()
{
	char cpar1[] = {"Hello test1"};
	printf("%s\n", cpar1);
}

void test2_one_par(int par1)
{
	int lvar = 2;
	int total = 0;
	total = lvar + par1;
}

void test3_two_par(int par1, int par2)
{
	global_test = par1 + par2;
}

void test4_two_par_ptr(char *par1, char *par2)
{
	global_test2 = par1[0];
	global_test2 = par2[0];
}

void test5_seven_par(int par1, int par2, char *par3, char *par4, char *par5, char *par6, char *par7)
{
	int lvar1 = par1;
	int lvar2 = par2;
	char lvar3 = par3[0];
	char lvar4 = par4[0];
	char lvar5 = par5[0];
	char lvar6 = par6[0];
	char lvar7 = par7[0];
}

void test6_one_par_call(int par1)
{
	int total = par1 + 5;
	printf("%i\n", total);
}

void test7_two_par_call(char *par1, int par2)
{
	char lvar1 = par1[0];
        int lvar2 = par2;
	printf("%c %i\n", lvar1, lvar2);
}

void test8_seven_par_call(int par1, int par2, char *par3, char *par4, char *par5, char *par6, char *par7)
{
	int lvar1 = par1;
	int lvar2 = par2;
	char lvar3 = par3[0];
	char lvar4 = par4[0];
	char lvar5 = par5[0];
	char lvar6 = par6[0];
	char lvar7 = par7[0];
	printf("%i %i %s %s %s %s %s", lvar1, lvar2, par3, par4, par5, par6, par7);
}

void test9_struct_init(struct struct_test *struct1)
{
	printf("%s", struct1->test1);
	printf("%s", struct1->test2);
	printf("%s", struct1->test3);
	printf("%s", struct1->test4);
	printf("%d", struct1->test5);
	strcpy(struct1->test1, struct1->test2);
}

void test10_struct_uninit(struct struct_test *struct1)
{
	printf("%s", struct1->test1);
	printf("%s", struct1->test2);
	printf("%s", struct1->test3);
	printf("%s", struct1->test4);
	printf("%d", struct1->test5);
	strcpy(struct1->test4, struct1->test3);
}

void test11_struct_by_value(struct struct_test struct1)
{
	printf("%s", struct1.test1);
	printf("%s", struct1.test2);
	printf("%s", struct1.test3);
	printf("%s", struct1.test4);
	printf("%d", struct1.test5);
	strcpy(struct1.test1, struct1.test2);
}

void test12_casting(char charpar, int ipar, float fpar)
{
	char local_str1[10];
	char local_str2[20];
	int local_int1 = (int)fpar;
	int local_int2 = (int)charpar;
	char local_char = (char)ipar;
	float local_float = (float)ipar;
	global_test2 = (int)fpar;
	printf("%d", local_int1);
	printf("%d", local_int2);
	printf("%c", local_char);
	printf("%f", local_float);
	strcpy(local_str1, local_str2);
	strncpy(local_str1, local_str2 ,(int)charpar);
	strncpy(local_str1, local_str2 ,(int)fpar);

}