
#include <stdio.h>
#include <string.h>

/*
 * CS3053 - Program Vulnerabilities (Part 1)
 *
 * Demonstrations:
 * 1. Stack Smashing
 * 2. Missing Range Checking
 * 3. Variable Overflow
 * 4. Pointer Exploitation
 */


/* ==========================================
   Part 1: Stack Smashing
   ========================================== */

/*
 * strcpy() does not check the destination buffer size.
 * If input is longer than 9 characters, including the
 * null terminator requires more than 10 bytes.
 * This causes a stack buffer overflow.
 */
void vulnerable_func(const char *input)
{
    char buffer[10];

    // Vulnerability: copying without checking buffer capacity.
    strcpy(buffer, input);

    printf("Vulnerable buffer: %s\n", buffer);
}

/* Safe alternative with bounds checking. */
void safe_func(const char *input)
{
    char buffer[10];

    snprintf(buffer, sizeof(buffer), "%s", input);

    printf("Safe buffer: %s\n", buffer);
}


/* ==========================================
   Part 2: Missing Range Checking
   ========================================== */

/*
 * The function copies count elements into a fixed array.
 * It does not verify that count is within the buffer size.
 * If count > 5, memory outside the array is accessed.
 */
void noRangeCheck(const int *src, int count)
{
    int buffer[5];

    // Vulnerability: count is not checked against capacity.
    for (int i = 0; i < count; i++) {
        buffer[i] = src[i];
    }

    for (int i = 0; i < count; i++) {
        printf("buffer[%d] = %d\n", i, buffer[i]);
    }
}


/* ==========================================
   Part 3: Variable Overflow
   ========================================== */

/*
 * Demonstrates how copying too many bytes into one
 * field can overwrite another field in the same structure.
 *
 * The structure provides a predictable field order.
 * The copy remains inside the complete structure,
 * making this a controlled simulation.
 */
void variableOverflow(void)
{
    struct {
        char buffer[8];
        char status[8];
    } data = {"", "SAFE"};

    const char input[] = "ABCDEFGHIJKL";

    printf("Before overflow: %s\n", data.status);

    /*
     * Copies 13 bytes, including the null terminator.
     * The first 8 bytes fill buffer.
     * The remaining bytes overwrite the status field.
     */
    memcpy(data.buffer, input, sizeof(input));

    printf("After overflow: %.8s\n", data.status);
}


/* ==========================================
   Part 4: Pointer Exploitation
   ========================================== */

/*
 * A function pointer stores the address of a function.
 * If memory corruption changes the pointer, execution
 * may be redirected to an unintended function.
 *
 * This example simulates pointer hijacking by explicitly
 * changing the function pointer.
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
    void (*functionPointer)(void) = normalFunction;

    printf("Before pointer modification:\n");
    functionPointer();

    // Simulated function pointer hijacking.
    functionPointer = unauthorizedFunction;

    printf("After pointer modification:\n");
    functionPointer();
}


/* ==========================================
   Main Function
   ========================================== */

int main(void)
{
    printf("===== Part 1: Stack Smashing =====\n");

    // Short input avoids triggering the actual overflow.
    vulnerable_func("Hello");
    safe_func("Hello");


    printf("\n===== Part 2: Missing Range Checking =====\n");

    int data[10] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};

    // Valid count: prints the first five values.
    noRangeCheck(data, 5);

    // Unsafe example for separate AddressSanitizer testing:
    // noRangeCheck(data, 10);


    printf("\n===== Part 3: Variable Overflow =====\n");

    variableOverflow();


    printf("\n===== Part 4: Pointer Exploitation =====\n");

    pointerExploitation();

    return 0;
}
