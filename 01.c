#include <stdio.h>
#include <string.h>

/*
 * Part 1: Stack Smashing
 *
 * This function contains a stack buffer overflow vulnerability.
 * strcpy() does not verify the destination buffer size.
 * An input longer than 9 characters (plus '\0') will
 * write outside the allocated buffer.
 */
void vulnerable_func(const char *input)
{
    char buffer[10];

    // Unsafe: no bounds checking
    strcpy(buffer, input);

    printf("Vulnerable buffer: %s\n", buffer);
}

/*
 * Safe implementation using bounds checking.
 * Only 9 characters can be copied into the buffer,
 * leaving one byte for the null terminator.
 */
void safe_func(const char *input)
{
    char buffer[10];

    snprintf(buffer, sizeof(buffer), "%s", input);

    printf("Safe buffer: %s\n", buffer);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }

    /*
     * Use short input to execute both functions safely.
     * A longer input can cause stack smashing in vulnerable_func().
     */
    vulnerable_func(argv[1]);
    safe_func(argv[1]);

    return 0;
}