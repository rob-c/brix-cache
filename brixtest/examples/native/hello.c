#include <stdio.h>

#ifndef BRIX_ANSWER
#define BRIX_ANSWER 0
#endif

int main(void)
{
    printf("brixtest C answer=%d\n", BRIX_ANSWER);
    return BRIX_ANSWER == 42 ? 0 : 1;
}
