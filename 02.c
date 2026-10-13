#include <stdio.h>

/*
 * Part 2: Missing Range Checking
 *
 * The function copies elements into a fixed-size array
 * without checking whether count exceeds its capacity.
 *
 * If count > 5, an out-of-bounds write occurs,
 * potentially corrupting memory.
 */

void noRangeCheck(const int *src, int count)
{
    int buffer[5];

    // Vulnerability: count is not validated against buffer size.
    for (int i = 0; i < count; i++) {
        buffer[i] = src[i];
    }

    for (int i = 0; i < count; i++) {
        printf("buffer[%d] = %d\n", i, buffer[i]);
    }
}

int main(void)
{
    int data[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

    // Normal execution
    noRangeCheck(data, 5);

    // Vulnerable case: uncomment for testing.
    // noRangeCheck(data, 10);

    return 0;
}