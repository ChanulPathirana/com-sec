
#include <stdio.h>
#include <string.h>

/*
 * Part 4: Pointer Exploitation
 *
 * A function pointer stores the address of a function.
 * If an attacker can modify this pointer, they may
 * redirect execution to an unintended function.
 */

void normalFunction(void)
{
    printf("Normal function executed.\n");
}

void unauthorizedFunction(void)
{
    printf("Unauthorized function executed!\n");
}

void pointerExploitation(void)
{
    // Function pointer initially points to normalFunction.
    void (*functionPointer)(void) = normalFunction;

    printf("Before pointer modification:\n");
    functionPointer();

    /*
     * Simulated pointer exploitation:
     * The function pointer is modified to point to
     * a different function.
     *
     * In a real vulnerability, memory corruption
     * could cause an unintended pointer overwrite.
     */
    functionPointer = unauthorizedFunction;

    printf("After pointer modification:\n");
    functionPointer();
}

int main(void)
{
    pointerExploitation();
    return 0;
}
