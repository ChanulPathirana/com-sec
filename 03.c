
#include <stdio.h>
#include <string.h>

/*
 * Part 3: Variable Overflow
 *
 * This example simulates a buffer overflow affecting
 * another variable stored immediately after it.
 */

void variableOverflow(void)
{
    struct {
        char buffer[8];
        char status[8];
    } data = {"", "SAFE"};

    char input[] = "ABCDEFGHIJKL";

    printf("Before overflow: %s\n", data.status);

    /*
     * Unsafe logical operation:
     * Copies more than 8 bytes into the buffer region.
     * The extra bytes overwrite the adjacent status field.
     *
     * The complete write stays inside the structure,
     * making this a controlled demonstration.
     */
    memcpy(data.buffer, input, sizeof(input));

    printf("After overflow: %.8s\n", data.status);
}

int main(void)
{
    variableOverflow();
    return 0;
}
