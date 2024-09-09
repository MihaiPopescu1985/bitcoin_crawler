#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <stdbool.h>

#include "blk_dat_parser.h"

#define NEXT_TOKEN getc(dat_file)

enum log
{
    NONE,
    INFO,
    DEBUG
};

enum log BLK_PARSER_LOG = NONE;


// Block header
const uint8_t HEADER_MAX_SIZE = 80;
uint8_t BLOCK_HEADER[80];
uint8_t HEADER_INDEX = 0;
unsigned char *BLOCK_HASH = NULL;

uint8_t BLOCK_MAGIC_NUMBER[4] = {0xF9, 0xBE, 0xB4, 0xD9};
uint32_t BLOCK_SIZE = 0;
uint8_t BLOCK_VERSION[4] = {0, 0, 0, 0};
uint8_t BLOCK_PREV_BLOCK[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
uint8_t BLOCK_MERKLE_ROOT[32] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
uint8_t BLOCK_TIME[4] = {0, 0, 0, 0};
uint8_t BLOCK_BITS[4] = {0, 0, 0, 0};
uint8_t BLOCK_NONCE[4] = {0, 0, 0, 0};

uint64_t TRANSACTION_COUNT;

// Block transactions
uint8_t *TRANSACTION = NULL;
unsigned char *TX_HASH = NULL;

size_t TX_SIZE = 0;
size_t TX_CAP = 0;

uint64_t TX_IN_COUNT = 0;

uint64_t SCRIPT_SIG_SIZE = 0;
uint8_t *SCRIPT_SIG = NULL;

uint64_t TX_OUT_COUNT = 0;

uint64_t AMOUNT;
uint64_t PUB_KEY_SIZE = 0;
uint8_t *SCRIPT_PUB_KEY = NULL;
uint32_t TX_LOCKTIME = 0;

// DB
sqlite3 *DB;


// Helper functions
void reset()
{
    if (SCRIPT_PUB_KEY != NULL) free(SCRIPT_PUB_KEY);
    if (SCRIPT_SIG != NULL) free(SCRIPT_SIG);
    if (TRANSACTION != NULL) free(TRANSACTION);
    if (TX_HASH != NULL) free(TX_HASH);
    if (BLOCK_HASH != NULL) free(BLOCK_HASH);
}

uint8_t* get_current_position(FILE *dat_file)
{
    long int current_pos = ftell(dat_file);
    unsigned long size = sizeof(long);

    uint8_t *array = (uint8_t *) malloc(size * sizeof(uint8_t));
    
    for (size_t i = 0; i < size; i++)
    {
        array[size-i-1] = (uint8_t)(current_pos >> (8 * i));
    }
    return array;
}

void set_log_level(char *level, enum log *log)
{
    if (strcmp(level, "info") == 0) *log = INFO;
    else if (strcmp(level, "debug") == 0) *log = DEBUG;
    else *log = NONE;
}

void log_debug_bytes(uint8_t *bytes, size_t length, char message[])
{
    printf("[DEBUG] %s", message);
    for (size_t i = 0; i < length; i++)
    {
        printf("%02X", bytes[i]);
    }
    printf("\n");
}

void log_debug_uint_32(uint32_t number, char message[])
{
    uint8_t *bytes = 
            (uint8_t *) malloc(sizeof(number) * sizeof(uint8_t));
    for (size_t i = 0; i < sizeof(number); ++i)
    {
        bytes[i] = (uint8_t)((number >> (8 * i)) & 0xFF);
    }
    log_debug_bytes(bytes, (size_t) sizeof(number), message);
    free(bytes);
}

void log_debug_uint_64(uint64_t number, char message[])
{
    uint8_t *bytes = 
            (uint8_t *) malloc(sizeof(number) * sizeof(uint8_t));
    for (size_t i = 0; i < sizeof(number); ++i)
    {
        bytes[i] = (uint8_t)(number >> (8 * i));
    }
    log_debug_bytes(bytes, (size_t) sizeof(number), message);
    free(bytes);
}

void log_info_bytes(uint8_t *bytes, size_t length, char message[])
{
    printf("[INFO] %s", message);
    for (size_t i = 0; i < length; i++)
    {
        printf("%02X", bytes[i]);
    }
    printf("\n");
}

uint16_t to_big_endian_16(uint8_t first, uint8_t second)
{
    uint16_t result = (uint16_t) first;
    result = result | ((uint16_t) second << 8);

    return result;
}

uint32_t to_big_endian_32(uint8_t first, uint8_t second, uint8_t third, uint8_t fourth)
{
    uint32_t result = (uint32_t) first;
    result = result | ((uint32_t) second << 8);
    result = result | ((uint32_t) third << 16);
    result = result | ((uint32_t) fourth << 24);

    return result;
}

uint64_t to_big_endian_64(uint8_t first, uint8_t second, uint8_t third, uint8_t fourth,
                            uint8_t fifth, uint8_t sixth, uint8_t seventh, uint8_t eigth)
{
    uint64_t result = (uint64_t) first;
    result = result | ((uint64_t) second << 8);
    result = result | ((uint64_t) third << 16);
    result = result | ((uint64_t) fourth << 24);
    result = result | ((uint64_t) fifth << 32);
    result = result | ((uint64_t) sixth << 40);
    result = result | ((uint64_t) seventh << 48);
    result = result | ((uint64_t) eigth << 56);

    return result;
}

uint64_t get_compact_size(FILE *dat_file)
{
    uint64_t size = NEXT_TOKEN;
    if (size < (uint64_t) 253) return size;
    if (size == (uint64_t) 253) {
        uint8_t bytes[2] = { NEXT_TOKEN, NEXT_TOKEN };
        return to_big_endian_16(bytes[0], bytes[1]);
    }
    if (size == (uint64_t) 254) {
        uint8_t bytes[4] = { NEXT_TOKEN, NEXT_TOKEN, NEXT_TOKEN, NEXT_TOKEN };
        return to_big_endian_32(bytes[0], bytes[1], bytes[2], bytes[3]);
    }
    uint8_t bytes[8] = { NEXT_TOKEN, NEXT_TOKEN, NEXT_TOKEN, NEXT_TOKEN, 
                        NEXT_TOKEN, NEXT_TOKEN, NEXT_TOKEN, NEXT_TOKEN };
    return to_big_endian_64(bytes[0], bytes[1], bytes[2], bytes[3], bytes[4],
                            bytes[5], bytes[6], bytes[7]);
}

int reverse_compact_size(uint64_t size)
{
    int amount = 0;
    if (size < 253) amount = 1;
    else if (size < 65536) amount = 3;
    else if (size < 4294967296) amount = 5;
    else amount = 9;
    
    return amount;
}

void get_double_sha256(unsigned char *data, size_t data_len, unsigned char *out_hash) {
    unsigned char hash[32];
    SHA256_CTX sha256;

    SHA256_Init(&sha256);
    SHA256_Update(&sha256, data, data_len);
    SHA256_Final(hash, &sha256);

    SHA256_Init(&sha256);
    SHA256_Update(&sha256, hash, 32);
    SHA256_Final(out_hash, &sha256);

    for (int i = 0; i < 16; ++i)
    {
        unsigned char temp = out_hash[i];
        out_hash[i] = out_hash[31-i];
        out_hash[31-i] = temp;
    }
}

int resize_transaction(size_t amount)
{
    TX_CAP += amount;
    uint8_t *new_transaction = 
        (uint8_t *) realloc(TRANSACTION, TX_CAP * (size_t) sizeof(uint8_t));

    if (new_transaction == NULL)
    {
        perror("Failed to resize TRANSACTION");
        return 3001;
    }

    TRANSACTION = new_transaction;
    return 0;
}

void set_block_hash()
{
    if (BLOCK_HASH != NULL)
    {
        free(BLOCK_HASH);
        BLOCK_HASH = NULL;
    }

    BLOCK_HASH = malloc(SHA256_DIGEST_LENGTH * sizeof(unsigned char));
    get_double_sha256(BLOCK_HEADER, HEADER_INDEX, BLOCK_HASH);
}

// DB functions
int db_insert_block()
{
    sqlite3_stmt *stmt;
    const char *sql = "INSERT OR REPLACE INTO block (hash, time, transaction_count) VALUES (?, ?, ?);";

    int result = sqlite3_prepare_v2(DB, sql, -1, &stmt, NULL);
    if (result != SQLITE_OK)
    {
        fprintf(stderr, "Failed to prepare statement: %s\n", sqlite3_errmsg(DB));
        return result;
    }
    
    result = sqlite3_bind_blob(stmt, 1, BLOCK_HASH, 32, SQLITE_STATIC);
    if (result != SQLITE_OK)
    {
        fprintf(stderr, "Failed to bind BLOCK_HASH: %s\n", sqlite3_errmsg(DB));
        sqlite3_finalize(stmt);
        return result;
    }

    // Convert BLOCK_TIME to an integer
    uint32_t block_time = ((uint32_t)BLOCK_TIME[0]) |
                            ((uint32_t)BLOCK_TIME[1] << 8) |
                            ((uint32_t)BLOCK_TIME[2] << 16) |
                            ((uint32_t)BLOCK_TIME[3] << 24);

    // Bind the BLOCK_TIME to the second placeholder
    result = sqlite3_bind_int(stmt, 2, block_time);
    if (result != SQLITE_OK)
    {
        fprintf(stderr, "Failed to bind BLOCK_TIME: %s\n", sqlite3_errmsg(DB));
        sqlite3_finalize(stmt);
        return result;
    }

    result = sqlite3_bind_int64(stmt, 3, TRANSACTION_COUNT);
    if (result != SQLITE_OK)
    {
        fprintf(stderr, "Failed to bind TRANSACTION_COUNT: %s\n", sqlite3_errmsg(DB));
        sqlite3_finalize(stmt);
        return result;
    }

    result = sqlite3_step(stmt);
    if (result != SQLITE_DONE) fprintf(stderr, "Failed to insert data: %s\n", sqlite3_errmsg(DB));
    
    sqlite3_finalize(stmt);

    return result == SQLITE_DONE ? SQLITE_OK : result;
}

// Header
int parse_magic_bytes(FILE *dat_file)
{
    if (BLK_PARSER_LOG != NONE) log_info_bytes(NULL, 0, "Parsing magic bytes.");

    for (int i = 0; i < 4; ++i)
    {
        uint8_t token = (uint8_t) NEXT_TOKEN;
        if (token != BLOCK_MAGIC_NUMBER[i])
        {
            fprintf(stderr, "Expected %02X byte but found %02X as block magic number.\n", BLOCK_MAGIC_NUMBER[i], token);
            fprintf(stderr, "At byte %ld\n", ftell(dat_file));
            return 1001; // Error code indicating block magic number mismatch
        }
    }
    return 0;
}

void parse_block_size(FILE *dat_file)
{
    if (BLK_PARSER_LOG == INFO) log_info_bytes(NULL, 0, "Parsing block size.");

    uint8_t bytes[4] = {(uint8_t) NEXT_TOKEN, (uint8_t) NEXT_TOKEN,
                           (uint8_t) NEXT_TOKEN, (uint8_t) NEXT_TOKEN};

    BLOCK_SIZE = to_big_endian_32(bytes[0], bytes[1], bytes[2], bytes[3]);
    if (BLK_PARSER_LOG == DEBUG) log_debug_uint_32(BLOCK_SIZE, "Parsed block size: ");
}

void parse_header_version(FILE *dat_file)
{
    if (BLK_PARSER_LOG == INFO) log_info_bytes(NULL, 0, "Parsing header version.");

    for (size_t i = 0; i < 4; ++i)
    {
        BLOCK_VERSION[i] = NEXT_TOKEN;
        BLOCK_HEADER[HEADER_INDEX] = BLOCK_VERSION[i];
        HEADER_INDEX++;
    }
    if (BLK_PARSER_LOG == DEBUG) log_debug_bytes(BLOCK_VERSION, (size_t) 4, "Parsed block version: ");
}

void parse_prev_hash(FILE *dat_file)
{
    if (BLK_PARSER_LOG == INFO) log_info_bytes(NULL, 0, "Parsing previous block hash.");

    for (size_t i = 0; i < 32; ++i)
    {
        BLOCK_PREV_BLOCK[i] = NEXT_TOKEN;
        BLOCK_HEADER[HEADER_INDEX] = BLOCK_PREV_BLOCK[i];
        HEADER_INDEX++;
    }
    if (BLK_PARSER_LOG == DEBUG) log_debug_bytes(BLOCK_PREV_BLOCK, (size_t) 32, "Parsed previous block hash: ");
}

void parse_merkle_root(FILE *dat_file)
{
    if (BLK_PARSER_LOG == INFO) log_info_bytes(NULL, 0, "Parsing the Merkle root.");

    for (size_t i = 0; i < 32; ++i)
    {
        BLOCK_MERKLE_ROOT[i] = NEXT_TOKEN;
        BLOCK_HEADER[HEADER_INDEX] = BLOCK_MERKLE_ROOT[i];
        HEADER_INDEX++;
    }
    if (BLK_PARSER_LOG == DEBUG) log_debug_bytes(BLOCK_MERKLE_ROOT, (size_t) 32, "Parsed the Merkle root: ");
}

void parse_header_timestamp(FILE *dat_file)
{
    if (BLK_PARSER_LOG == INFO) log_info_bytes(NULL, 0, "Parsing the header timestamp.");

    for (size_t i = 0; i < 4; ++i)
    {
        BLOCK_TIME[i] = NEXT_TOKEN;
        BLOCK_HEADER[HEADER_INDEX] = BLOCK_TIME[i];
        HEADER_INDEX++;
    }
    if (BLK_PARSER_LOG == DEBUG) log_debug_bytes(BLOCK_TIME, (size_t) 4, "Parsed the header timestamp: ");
}

void parse_nbytes(FILE *dat_file)
{
    if (BLK_PARSER_LOG == INFO) log_info_bytes(NULL, 0, "Parsing the header bytes.");

    for (size_t i = 0; i < 4; ++i)
    {
        BLOCK_BITS[i] = NEXT_TOKEN;
        BLOCK_HEADER[HEADER_INDEX] = BLOCK_BITS[i];
        HEADER_INDEX++;
    }
    if (BLK_PARSER_LOG == DEBUG) log_debug_bytes(BLOCK_BITS, (size_t) 4, "Parsed the header bytes: ");
}

void parse_nonce(FILE *dat_file)
{
    if (BLK_PARSER_LOG == INFO) log_info_bytes(NULL, 0, "Parsing the header nonce.");

    for (size_t i = 0; i < 4; ++i)
    {
        BLOCK_NONCE[i] = NEXT_TOKEN;
        BLOCK_HEADER[HEADER_INDEX] = BLOCK_NONCE[i];
        HEADER_INDEX++;
    }
    if (BLK_PARSER_LOG == DEBUG) log_debug_bytes(BLOCK_NONCE, (size_t) 4, "Parsed the header nonce: ");
}

int parse_header(FILE *dat_file)
{
    HEADER_INDEX = 0;

    int result = parse_magic_bytes(dat_file);
    if (result != 0) return result;

    parse_block_size(dat_file);

    // Save the current index
    uint64_t position = (uint64_t) ftell(dat_file);

    parse_header_version(dat_file);
    parse_prev_hash(dat_file);
    parse_merkle_root(dat_file);
    parse_header_timestamp(dat_file);
    parse_nbytes(dat_file);
    parse_nonce(dat_file);

    set_block_hash();
    if (BLK_PARSER_LOG == DEBUG) log_debug_bytes(BLOCK_HASH, 
                        (size_t) 32, "Calculated block hash: ");

    // Verify the header parsing
    position += HEADER_MAX_SIZE;
    uint64_t new_position = (uint64_t) ftell(dat_file);

    if (position != new_position)
    {
        fprintf(stderr, "Expected header size %lu but %lu.\n", position, new_position);
        return 1005;
    }
    return 0;
}

// Transactions
void parse_transaction_count(FILE *dat_file)
{
    if (BLK_PARSER_LOG == INFO) log_info_bytes(NULL, 0, "Parsing transaction count.");

    TRANSACTION_COUNT = get_compact_size(dat_file);
    if (BLK_PARSER_LOG == DEBUG) log_debug_uint_64(TRANSACTION_COUNT, "Parsed raw tx count: ");
}

int parse_tx_version(FILE *dat_file)
{
    if (BLK_PARSER_LOG == INFO) log_info_bytes(NULL, 0, 
                        "Parsing tx version.");

    TX_CAP = (size_t) 4;
    TX_SIZE = (size_t) 0;

    if (TRANSACTION != NULL)
    {
        free(TRANSACTION);
        TRANSACTION = NULL;
    }
    TRANSACTION = (uint8_t *) malloc(TX_CAP * sizeof(uint8_t));
    if (TRANSACTION == NULL) return 3002;

    for (size_t i = 0; i < TX_CAP; ++i)
    {
        TRANSACTION[TX_SIZE] = NEXT_TOKEN;
        ++TX_SIZE;
    }
    if (BLK_PARSER_LOG == DEBUG) log_debug_bytes(TRANSACTION, (size_t) 4, "Parsed tx version: ");
    return 0;
}

int parse_input_count(FILE *dat_file, bool *is_witness)
{
    if (BLK_PARSER_LOG == INFO) log_info_bytes(NULL, 0, 
                    "Parsing tx input count.");
    
    TX_IN_COUNT = get_compact_size(dat_file);
    if (TX_IN_COUNT == (uint64_t) 0) // we found the marker
    {
        *is_witness = true;
        NEXT_TOKEN; // skip the flag
        TX_IN_COUNT = get_compact_size(dat_file);
    }

    if (BLK_PARSER_LOG == DEBUG) log_debug_uint_64(TX_IN_COUNT, "Parsed raw tx input count: ");
    size_t amount = (size_t) reverse_compact_size(TX_IN_COUNT);

    int result = resize_transaction(amount);
    if (result != 0) return result;
    
    fseek(dat_file, -amount, SEEK_CUR); // go back

    while (amount > (size_t) 0)
    {
        TRANSACTION[TX_SIZE++] = NEXT_TOKEN;
        --amount;
    }
    return 0;
}

int parse_input_txid(FILE *dat_file)
{
    if (BLK_PARSER_LOG == INFO) log_info_bytes(NULL, 0, 
                    "Parsing tx ID");
    
    uint8_t tx_id[32];
    
    int result = resize_transaction((size_t) 32);
    if (result != 0) return result;

    for (size_t i = 0; i < 32; ++i)
    {
        tx_id[i] = NEXT_TOKEN;
        TRANSACTION[TX_SIZE++] = tx_id[i];
    }
    if (BLK_PARSER_LOG == DEBUG) log_debug_bytes(tx_id, (size_t) 32, "Parsed transaction id: ");
    return 0;
}

int parse_input_vout(FILE *dat_file)
{
    if (BLK_PARSER_LOG == INFO) log_info_bytes(NULL, 0, "Parsing tx input vout");
    uint8_t v_out[4];
    
    int result = resize_transaction((size_t) 4);
    if (result != 0) return result;

    for (int i = 0; i < 4; ++i)
    {
        v_out[i] = NEXT_TOKEN;
        TRANSACTION[TX_SIZE++] = v_out[i];
    }
    if (BLK_PARSER_LOG == DEBUG) log_debug_bytes(v_out, (size_t) 4, "Parsed tx vOut: ");
    return 0;
}

int parse_scriptsig_size(FILE *dat_file)
{
    if (BLK_PARSER_LOG == INFO) log_info_bytes(NULL, 0, "Parsing tx scriptsig size");
    
    SCRIPT_SIG_SIZE = get_compact_size(dat_file);

    if (BLK_PARSER_LOG == DEBUG) log_debug_uint_64(SCRIPT_SIG_SIZE, "Parsed scriptsig size: ");
    size_t amount = (size_t) reverse_compact_size(SCRIPT_SIG_SIZE);

    int result = resize_transaction((size_t) amount);
    if (result != 0) return result;

    fseek(dat_file, -amount, SEEK_CUR); // go back

    while (amount > (size_t) 0)
    {
        TRANSACTION[TX_SIZE++] = NEXT_TOKEN;
        --amount;
    }
    return 0;
}

int parse_scriptsig(FILE *dat_file)
{
    if (BLK_PARSER_LOG == INFO) log_info_bytes(NULL, 0, 
                    "Parsing tx scriptsig");
    
    if (SCRIPT_SIG != NULL)
    {
        free(SCRIPT_SIG);
        SCRIPT_SIG = NULL;
    }

    SCRIPT_SIG = (uint8_t *)malloc(SCRIPT_SIG_SIZE * sizeof(uint8_t));
    if (SCRIPT_SIG == NULL) return 3003; // TODO: verify uniqueness of this number

    int result = resize_transaction((size_t) SCRIPT_SIG_SIZE);
    if (result != 0) return result;

    for (size_t i = 0; i < SCRIPT_SIG_SIZE; ++i)
    {
        SCRIPT_SIG[i] = NEXT_TOKEN;
        TRANSACTION[TX_SIZE++] = SCRIPT_SIG[i];
    }
    if (BLK_PARSER_LOG == DEBUG) log_debug_bytes(SCRIPT_SIG, (size_t) SCRIPT_SIG_SIZE,"Parsed tx scriptsig: ");
    return 0;
}

int parse_input_sequence(FILE *dat_file)
{
    if (BLK_PARSER_LOG == INFO) log_info_bytes(NULL, 0, 
                    "Parsing input sequence");
    
    int result = resize_transaction((size_t) 4);
    if (result != 0) return result;
    
    uint8_t in_seq[4];
    for (size_t i = 0; i < 4; ++i)
    {
        in_seq[i] = NEXT_TOKEN;
        TRANSACTION[TX_SIZE++] = in_seq[i];
    }
    if (BLK_PARSER_LOG == DEBUG) log_debug_bytes(in_seq, (size_t) 4, "Parsed tx in sequence: ");
    return 0;
}

int parse_out_count(FILE *dat_file)
{
    if (BLK_PARSER_LOG == INFO) log_info_bytes(NULL, 0, 
                    "Parsing tx out count");
    
    TX_OUT_COUNT = get_compact_size(dat_file);
    if (BLK_PARSER_LOG == DEBUG) log_debug_uint_64(TX_OUT_COUNT, "Parsed tx out count: ");

    size_t amount = (size_t) reverse_compact_size(TX_OUT_COUNT);
    int result = resize_transaction((size_t) amount);
    if (result != 0) return result;

    fseek(dat_file, -amount, SEEK_CUR); // go back

    while (amount > (size_t) 0)
    {
        TRANSACTION[TX_SIZE++] = NEXT_TOKEN;
        --amount;
    }
    return 0;
}

int parse_amount(FILE *dat_file)
{
    if (BLK_PARSER_LOG == INFO) log_info_bytes(NULL, 0, 
                    "Parsing tx amount");
    
    int result = resize_transaction((size_t) 8);
    if (result != 0) return result;

    uint8_t raw_amount[8];
    for (size_t i = 0; i < (size_t) 8; ++i)
    {
        raw_amount[i] = NEXT_TOKEN;
        TRANSACTION[TX_SIZE++] = raw_amount[i];
    }

    if (BLK_PARSER_LOG == DEBUG) log_debug_bytes(raw_amount, (size_t) 8, "Parsed raw amount: ");
    AMOUNT = to_big_endian_64(raw_amount[0], raw_amount[1], raw_amount[2],
                            raw_amount[3], raw_amount[4], raw_amount[5],
                            raw_amount[6], raw_amount[7]);
    return 0;
}

int parse_pubkey_size(FILE *dat_file)
{
    if (BLK_PARSER_LOG == INFO) log_info_bytes(NULL, 0, "Parsing tx input vout");
    
    PUB_KEY_SIZE = get_compact_size(dat_file);
    if (BLK_PARSER_LOG == DEBUG) log_debug_uint_64(PUB_KEY_SIZE, "Parsed public key size: ");

    size_t amount = (size_t) reverse_compact_size(PUB_KEY_SIZE);
    int result = resize_transaction(amount);
    if (result != 0) return result;

    fseek(dat_file, -amount, SEEK_CUR); // go back

    while (amount > (size_t) 0)
    {
        TRANSACTION[TX_SIZE++] = NEXT_TOKEN;
        --amount;
    }
    return 0;
}

int parse_script_pubkey(FILE *dat_file)
{
    if (BLK_PARSER_LOG == INFO) log_info_bytes(NULL, 0, "Parsing script public key");
    
    if (SCRIPT_PUB_KEY != NULL)
    {
        free(SCRIPT_PUB_KEY);
        SCRIPT_PUB_KEY = NULL;
    }
    SCRIPT_PUB_KEY = (uint8_t *)malloc(PUB_KEY_SIZE * sizeof(uint8_t));
    if (SCRIPT_PUB_KEY == NULL) return 3004; // TODO: verify this number

    int result = resize_transaction((size_t) PUB_KEY_SIZE);
    if (result != 0) return result;

    for (size_t i = 0; i < PUB_KEY_SIZE; ++i)
    {
        SCRIPT_PUB_KEY[i] = NEXT_TOKEN;
        TRANSACTION[TX_SIZE++] = SCRIPT_PUB_KEY[i];
    }
    if (BLK_PARSER_LOG == DEBUG) log_debug_bytes(SCRIPT_PUB_KEY, (size_t) PUB_KEY_SIZE, "Parsed tx script public key: ");
    return 0;
}

int parse_witness(FILE *dat_file)
{
    if (BLK_PARSER_LOG == INFO) log_info_bytes(NULL, 0, "Parsing tx witness");

    // TODO: not doing anything at the moment; must be refactored
    for (size_t in = 0; in < TX_IN_COUNT; in++)
    {
        uint64_t stack_items = get_compact_size(dat_file);
        if (BLK_PARSER_LOG == DEBUG) log_debug_uint_64(stack_items, "Parsed stack items: ");

        for (size_t item = 0; item < stack_items; item++)
        {
            uint64_t size = get_compact_size(dat_file);
            if (BLK_PARSER_LOG == DEBUG) log_debug_uint_64(size, "Parsed stack items size: ");
            uint8_t to_stack[size];

            for (size_t i = 0; i < size; ++i) to_stack[i] = NEXT_TOKEN;
            if (BLK_PARSER_LOG == DEBUG) log_debug_bytes(to_stack, (size_t) size, "Parsed item: ");
        }
    }
    return 0;
}

int parse_lock_time(FILE *dat_file)
{
    if (BLK_PARSER_LOG == INFO) log_info_bytes(NULL, 0, "Parsing tx lock time");

    int result = resize_transaction((size_t) 4);
    if (result != 0) return result;

    uint8_t lock_time[4];

    for (size_t i = 0; i < 4; ++i)
    {
        lock_time[i] = NEXT_TOKEN;
        TRANSACTION[TX_SIZE] = lock_time[i];
        TX_SIZE++;
    }
    if (BLK_PARSER_LOG == DEBUG) log_debug_bytes(lock_time, (size_t) 4, "Parsed tx lock time: ");
    return 0;
}

int parse_transactions(FILE *dat_file)
{
    for (uint64_t tx = 0; tx < TRANSACTION_COUNT; ++tx)
    {
        if (BLK_PARSER_LOG == INFO || BLK_PARSER_LOG == DEBUG) printf("Parsing transaction: %ld\n", tx);
        int result = parse_tx_version(dat_file);
        if (result != 0) return result;

        bool is_witness = false;

        result = parse_input_count(dat_file, &is_witness);
        if (result != 0) return result;

        for (uint64_t tx_in = 0; tx_in < TX_IN_COUNT; ++tx_in)
        {
            result = parse_input_txid(dat_file);
            if (result != 0) return result;

            result = parse_input_vout(dat_file);
            if (result != 0) return result;
            
            result = parse_scriptsig_size(dat_file);
            if (result != 0) return result;

            result = parse_scriptsig(dat_file);
            if (result != 0) return result;

            result = parse_input_sequence(dat_file);
            if (result != 0) return result;
        }
        
        result = parse_out_count(dat_file);
        if (result != 0) return result;

        for (uint64_t tx_out = 0; tx_out < TX_OUT_COUNT; ++tx_out)
        {
            result = parse_amount(dat_file);
            if (result != 0) return result;
            
            result = parse_pubkey_size(dat_file);
            if (result != 0) return result;

            result = parse_script_pubkey(dat_file);
            if (result != 0) return result;
        }

        if (is_witness) {
            result = parse_witness(dat_file);
            if (result != 0) return result;
        }

        result = parse_lock_time(dat_file);
        if (result != 0) return result;

        if (TX_HASH != NULL)
        {
            free(TX_HASH);
            TX_HASH = NULL;
        }
        TX_HASH = malloc(SHA256_DIGEST_LENGTH * sizeof(unsigned char));
        get_double_sha256((unsigned char *) TRANSACTION, TX_SIZE, TX_HASH);

        if (BLK_PARSER_LOG != NONE) log_debug_bytes(TX_HASH, (size_t) 32, "Calculated tx hash: ");
    }
    return 0;
}

int parse_dat_file(FILE *dat_file, sqlite3 *database, char *log_level)
{
    int error_code = 0;
    DB = database;
    set_log_level(log_level, &BLK_PARSER_LOG);

    while (true)
    {
        int next_byte = fgetc(dat_file);
        if (next_byte != EOF) ungetc(next_byte, dat_file);
        else break;

        error_code = parse_header(dat_file);
        if (error_code != 0)
        {
            fprintf(stderr, "Parsing header returned: %d\n", error_code);
            fclose(dat_file);
            return error_code;
        }

        parse_transaction_count(dat_file);
        db_insert_block();

        error_code = parse_transactions(dat_file);
        if (error_code != 0)
        {
            fprintf(stderr, "Parsing transactions returned: %d\n", error_code);
            fclose(dat_file);
            return error_code;
        }
    }
    reset();

    return 0;
}
