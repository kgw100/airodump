#pragma once

#include <unistd.h>
#include <stdint.h>
#include <string>

void usage();
void tohex(const u_char * in, size_t insz, char * out, size_t outsz);
char *Fromint_Toascii(int asciiNumber);
