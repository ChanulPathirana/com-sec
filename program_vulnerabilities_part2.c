#include <stdio.h>
#include <string.h>
#include <stdint.h>

/*
 * CS3053 - Continuous Assessment: Program Vulnerabilities - Part 2
 * Techniques: Canary, Bounds Checking, Tagging
 * Each example uses defined C behavior and can run normally.
 */

/* 1. CANARY: A sentinel can detect an overwrite of adjacent data.
 * The structure fixes field order. This demonstrates the idea without
 * causing an out-of-bounds write or relying on compiler stack layout.
 * Real stack canaries should be supplied by compiler stack protection.
 */
void canary_demo(void)
{
    struct {
        char buffer[8];
        uint32_t canary;
    } frame = {{0}, UINT32_C(0xDEADBEEF)};

    const char input[] = "ABCDEFGHIJK";
    const uint32_t expected = UINT32_C(0xDEADBEEF);

    printf("1. Canary\n");
    /* Simulate an unchecked write crossing the buffer field but staying
       within the allocated structure, so the demonstration is defined. */
    memcpy(frame.buffer, input, sizeof(input));
    if (frame.canary != expected)
        printf("Canary changed: adjacent memory corruption detected.\n");
    else
        printf("Canary intact.\n");
}

/* 2. BOUNDS CHECKING: Only copy input that fits, including '\0'. */
void bounds_check_demo(const char *input)
{
    char buffer[10];
    printf("2. Bounds checking\n");
    if (strlen(input) >= sizeof(buffer)) {
        printf("Input rejected: too long for buffer.\n");
        return;
    }
    strcpy(buffer, input); /* Safe after the explicit length check. */
    printf("Accepted input: %s\n", buffer);
}

/* 3. TAGGING: Associate a data item with a type tag and check it
 * before interpreting the stored value. This helps avoid type confusion.
 * Tagging is a separate mitigation idea; it does not automatically
 * stop buffer overflows or replace bounds checking.
 */
typedef enum { TAG_INTEGER, TAG_TEXT } ValueTag;
typedef struct {
    ValueTag tag;
    union {
        int integer;
        char text[16];
    } value;
} TaggedValue;

void print_integer(const TaggedValue *item)
{
    if (item->tag != TAG_INTEGER) {
        printf("3. Tagging: rejected incorrect data type.\n");
        return;
    }
    printf("3. Tagging: integer value = %d\n", item->value.integer);
}

int main(void)
{
    canary_demo();
    bounds_check_demo("TooLongFor10Bytes");
    bounds_check_demo("Hello");

    TaggedValue item = { .tag = TAG_TEXT, .value.text = "Hello" };
    print_integer(&item); /* Reject incompatible access. */
    item.tag = TAG_INTEGER;
    item.value.integer = 42;
    print_integer(&item); /* Accepted because tag matches. */
    return 0;
}
