#include "blk_dat_parser.h"

int main(int argc, char **argv) {
    // Read the file
    FILE *dat_file = fopen(argv[2], "rb");
    if (dat_file == NULL) {
        fprintf(stderr, "Dat file could not be opened\n");
        return 1;
    }

    int result = parse_dat_file(dat_file);
    fclose(dat_file);

    if(result != 0) fprintf(stderr, "Parsing failed. Error code %d\n", result);
    return result;
}
