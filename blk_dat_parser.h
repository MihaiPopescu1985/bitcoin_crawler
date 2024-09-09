#ifndef BLK_DAT_PARSER
#define BLK_DAT_PARSER

#include <sqlite3.h>
#include <stdio.h>

int parse_dat_file(FILE *dat_file, sqlite3 *database, char *log_level);

#endif