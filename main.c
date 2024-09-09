#include "blk_dat_parser.h"
#include <sqlite3.h>

int main(int argc, char **argv) {
    // Database
    sqlite3 *db;
    if (sqlite3_open("../db/bitcoin.db", &db))
    {
        fprintf(stderr, "Can't open database: %s\n", sqlite3_errmsg(db));
        sqlite3_close(db);
        return(1);
    }

    // Read the file
    FILE *dat_file = fopen(argv[2], "rb");
    if (dat_file == NULL) {
        perror("dat file could not be opened\n");
        sqlite3_close(db);
        return 1;
    }

    // Parse the file
    printf("Start parsing %s\n", argv[2]);
    char *log_level = (argc < 4) ? "none" : argv[3];

    int result = parse_dat_file(dat_file, db, log_level);

    // Conclude
    sqlite3_close(db);
    if(result == 0) printf("Parsing was successful.\n");
    else printf("Parsing failed. Error code %d\n", result);

    return result;
}
