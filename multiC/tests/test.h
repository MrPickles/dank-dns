#ifndef TEST_H
#define TEST_H

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_RESET   "\x1b[0m"

/*
 * Print test results. The first parameter is a string that summarizes the test.
 * The second parameter is the boolean that should be true.
 */
void print_state(char *name, int val);

/*
 * Prints the test title.
 */
void print_section(char *title);

#endif

