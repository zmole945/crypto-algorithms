
//Testing data from SM3 Standards
//http://www.oscca.gov.cn/News/201012/News_1199.htm 
// Sample 1
// Input:"abc"  
// Output:66c7f0f4 62eeedd9 d1f2d46b dc10e4e2 4167c487 5cf2f7a2 297da02b 8f4ba8e0

// Sample 2 
// Input:"abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd"
// Outpuf:debe9ff9 2275b8a1 38604889 c18e5a4d 6fdb70e5 387e5765 293dcba3 9c0c5732

#include <string.h>
#include <stdio.h>
#include "sm3.h"

static void test1(void);
static void test2(void);
static void test_msg(void);

int main( int argc, char *argv[] )
{
    test1();

    test2();

    test_msg();

    //getch();	//VS2008
}

static void test1(void)
{
    int i;
    unsigned char input[] = "abc";
    unsigned char output[32];
    int ilen = 3;

    printf("Message:\n");
    printf("%s\n",input);

    sm3_alg(input, ilen, output);

    printf("Hash:\n   ");
    for(i=0; i<32; i++)
    {
        printf("%02x",output[i]);
        if (((i+1) % 4 ) == 0) printf(" ");
    }
    printf("\n");

}

static void test2(void)
{
    unsigned char *input = "abc";
    int ilen = 3;
    unsigned char output[32];
    int i;
    sm3_ctx_t ctx;

    printf("Message:\n");
    for(i=0; i < 16; i++)
        printf("abcd");
    printf("\n");

    sm3_init( &ctx );
    for(i=0; i < 16; i++)
        sm3_update( &ctx, "abcd", 4 );
    sm3_final( &ctx, output );
    memset( &ctx, 0, sizeof( sm3_ctx_t ) );

    printf("Hash:\n   ");
    for(i=0; i<32; i++)
    {
        printf("%02x",output[i]);
        if (((i+1) % 4 ) == 0) printf(" ");
    }
    printf("\n");
}

static void test_msg(void)
{
    unsigned char msg[] = "message digest";
    unsigned char output[32];
    int i;

    printf("Message:\n");
    printf("%s\n", msg);

    sm3_alg(msg, strlen(msg), output);
    printf("Hash:\n   ");
    for(i=0; i<32; i++)
    {
        printf("%02x",output[i]);
        if (((i+1) % 4 ) == 0) printf(" ");
    }
    printf("\n");
}

