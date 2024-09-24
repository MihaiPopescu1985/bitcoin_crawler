#include <string.h>
#include <stdlib.h>
#include <openssl/sha.h>
#include <stdbool.h>

#include "blk_dat_parser.h"
#include "export_debug.h"

#define NEXT_TOKEN getc(dat_file)
#define uchar_p unsigned char *


// Block header
const uint8_t HEADER_MAX_SIZE = 80;
static uint8_t BLOCK_HEADER[80];
static uint8_t HEADER_INDEX = 0;
static uchar_p BLOCK_HASH = NULL;

static uint8_t BLOCK_MAGIC_NUMBER[4] = {0xF9, 0xBE, 0xB4, 0xD9};

// Block transaction count
static uint64_t TRANSACTION_COUNT;

// Block transactions
static uint8_t *TRANSACTION = NULL;
static uchar_p TX_HASH = NULL;

static size_t TX_SIZE = 0;
static size_t TX_CAP = 0;

static uint64_t TX_IN_COUNT = 0;

static uint64_t SCRIPT_SIG_SIZE = 0;
static uint8_t *SCRIPT_SIG = NULL;

static uint64_t TX_OUT_COUNT = 0;
static uint8_t TX_ID[32];
static uint8_t V_OUT[4];

static uint64_t PUB_KEY_SIZE = 0;
static uint8_t *SCRIPT_PUB_KEY = NULL;


// Helper functions
void reset()
{
    if (BLOCK_HASH != NULL) free(BLOCK_HASH);
    if (TRANSACTION != NULL) free(TRANSACTION);
    if (SCRIPT_SIG != NULL) free(SCRIPT_SIG);
    if (SCRIPT_PUB_KEY != NULL) free(SCRIPT_PUB_KEY);
    if (TX_HASH != NULL) free(TX_HASH);
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

void get_double_sha256(uchar_p data, size_t data_len, uchar_p out_hash) {
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
        fprintf(stderr, "Failed to resize TRANSACTION");
        return 1;
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

// Header
int parse_magic_bytes(FILE *dat_file)
{
    for (int i = 0; i < 4; ++i)
    {
        uint8_t token = (uint8_t) NEXT_TOKEN;
        if (token != BLOCK_MAGIC_NUMBER[i])
        {
            fprintf(stderr,
                    "Expected %02X byte but found %02X as block magic number.\n",
                    BLOCK_MAGIC_NUMBER[i],
                    token);
            fprintf(stderr, "At byte %ld\n", ftell(dat_file));
            return 1;
        }
    }
    export_magic_number(BLOCK_MAGIC_NUMBER);
    return 0;
}

void parse_block_size(FILE *dat_file)
{
    uint8_t bytes[4] = {(uint8_t) NEXT_TOKEN, (uint8_t) NEXT_TOKEN,
                        (uint8_t) NEXT_TOKEN, (uint8_t) NEXT_TOKEN};
    export_block_size(bytes);
}

void parse_header_version(FILE *dat_file)
{
    uint8_t block_version[4] = {0, 0, 0, 0};

    for (size_t i = 0; i < 4; ++i)
    {
        block_version[i] = NEXT_TOKEN;
        BLOCK_HEADER[HEADER_INDEX] = block_version[i];
        HEADER_INDEX++;
    }
    export_header_version(block_version);
}

void parse_prev_hash(FILE *dat_file)
{
    uint8_t prev_block[32];;
    for (size_t i = 0; i < 32; ++i)
    {
        prev_block[i] = NEXT_TOKEN;
        BLOCK_HEADER[HEADER_INDEX] = prev_block[i];
        HEADER_INDEX++;
    }
    export_prev_hash(prev_block);
}

void parse_merkle_root(FILE *dat_file)
{
    uint8_t merkle_root[32];
    for (size_t i = 0; i < 32; ++i)
    {
        merkle_root[i] = NEXT_TOKEN;
        BLOCK_HEADER[HEADER_INDEX] = merkle_root[i];
        HEADER_INDEX++;
    }
    export_merkle_root(merkle_root);
}

void parse_header_timestamp(FILE *dat_file)
{
    uint8_t block_time[4];
    for (size_t i = 0; i < 4; ++i)
    {
        block_time[i] = NEXT_TOKEN;
        BLOCK_HEADER[HEADER_INDEX] = block_time[i];
        HEADER_INDEX++;
    }
    export_block_time(block_time);
}

void parse_nbytes(FILE *dat_file)
{
    uint8_t block_bits[4];
    for (size_t i = 0; i < 4; ++i)
    {
        block_bits[i] = NEXT_TOKEN;
        BLOCK_HEADER[HEADER_INDEX] = block_bits[i];
        HEADER_INDEX++;
    }
    export_nbytes(block_bits);
}

void parse_nonce(FILE *dat_file)
{
    uint8_t nonce[4];
    for (size_t i = 0; i < 4; ++i)
    {
        nonce[i] = NEXT_TOKEN;
        BLOCK_HEADER[HEADER_INDEX] = nonce[i];
        HEADER_INDEX++;
    }
    export_nonce(nonce);
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
    export_block_hash(BLOCK_HASH);

    // Verify the header parsing
    position += HEADER_MAX_SIZE;
    uint64_t new_position = (uint64_t) ftell(dat_file);

    if (position != new_position)
    {
        fprintf(stderr,
                "Expected header size %lu but %lu.\n",
                position,
                new_position);
        return 1;
    }
    return 0;
}

// Transactions
void parse_transaction_count(FILE *dat_file)
{
    TRANSACTION_COUNT = get_compact_size(dat_file);
    export_transaction_count(TRANSACTION_COUNT);
}

int parse_tx_version(FILE *dat_file)
{
    TX_CAP = (size_t) 4;
    TX_SIZE = (size_t) 0;

    if (TRANSACTION != NULL)
    {
        free(TRANSACTION);
        TRANSACTION = NULL;
    }
    TRANSACTION = (uint8_t *) malloc(TX_CAP * sizeof(uint8_t));
    if (TRANSACTION == NULL) return 1;

    for (size_t i = 0; i < TX_CAP; ++i)
    {
        TRANSACTION[TX_SIZE] = NEXT_TOKEN;
        ++TX_SIZE;
    }
    export_tx_version(TRANSACTION);

    return 0;
}

int parse_input_count(FILE *dat_file, bool *is_witness)
{
    TX_IN_COUNT = get_compact_size(dat_file);
    if (TX_IN_COUNT == (uint64_t) 0) // we found the marker
    {
        *is_witness = true;
        export_flag((uint8_t) NEXT_TOKEN);

        TX_IN_COUNT = get_compact_size(dat_file);
    }

    export_tx_in_count(TX_IN_COUNT);
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
    int result = resize_transaction((size_t) 32);
    if (result != 0) return result;

    for (size_t i = 0; i < 32; ++i)
    {
        TX_ID[i] = NEXT_TOKEN;
        TRANSACTION[TX_SIZE++] = TX_ID[i];
    }
    export_tx_id(TX_ID);
    return 0;
}

int parse_input_vout(FILE *dat_file)
{
    int result = resize_transaction((size_t) 4);
    if (result != 0) return result;

    for (int i = 0; i < 4; ++i)
    {
        V_OUT[i] = NEXT_TOKEN;
        TRANSACTION[TX_SIZE++] = V_OUT[i];
    }
    export_input_vout(V_OUT);
    return 0;
}

int parse_scriptsig_size(FILE *dat_file)
{
    SCRIPT_SIG_SIZE = get_compact_size(dat_file);

    export_script_sig_size(SCRIPT_SIG_SIZE);
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
    if (SCRIPT_SIG != NULL)
    {
        free(SCRIPT_SIG);
        SCRIPT_SIG = NULL;
    }

    SCRIPT_SIG = (uint8_t *)malloc(SCRIPT_SIG_SIZE * sizeof(uint8_t));
    if (SCRIPT_SIG == NULL) return 1;

    int result = resize_transaction((size_t) SCRIPT_SIG_SIZE);
    if (result != 0) return result;

    for (size_t i = 0; i < SCRIPT_SIG_SIZE; ++i)
    {
        SCRIPT_SIG[i] = NEXT_TOKEN;
        TRANSACTION[TX_SIZE++] = SCRIPT_SIG[i];
    }

    export_script_sig(SCRIPT_SIG);
    return 0;
}

int parse_input_sequence(FILE *dat_file)
{
    int result = resize_transaction((size_t) 4);
    if (result != 0) return result;
    
    uint8_t in_seq[4];
    for (size_t i = 0; i < 4; ++i)
    {
        in_seq[i] = NEXT_TOKEN;
        TRANSACTION[TX_SIZE++] = in_seq[i];
    }

    export_tx_in_sequence(in_seq);
    return 0;
}

int parse_out_count(FILE *dat_file)
{
    TX_OUT_COUNT = get_compact_size(dat_file);
    export_tx_out_count(TX_OUT_COUNT);

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
    int result = resize_transaction((size_t) 8);
    if (result != 0) return result;

    uint8_t raw_amount[8];
    for (size_t i = 0; i < (size_t) 8; ++i)
    {
        raw_amount[i] = NEXT_TOKEN;
        TRANSACTION[TX_SIZE++] = raw_amount[i];
    }

    export_amount(raw_amount);
    return 0;
}

int parse_pubkey_size(FILE *dat_file)
{
    PUB_KEY_SIZE = get_compact_size(dat_file);
    export_pub_key_size(PUB_KEY_SIZE);

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
    if (SCRIPT_PUB_KEY != NULL)
    {
        free(SCRIPT_PUB_KEY);
        SCRIPT_PUB_KEY = NULL;
    }
    SCRIPT_PUB_KEY = (uint8_t *)malloc(PUB_KEY_SIZE * sizeof(uint8_t));
    if (SCRIPT_PUB_KEY == NULL) return 1;

    int result = resize_transaction((size_t) PUB_KEY_SIZE);
    if (result != 0) return result;

    for (size_t i = 0; i < PUB_KEY_SIZE; ++i)
    {
        SCRIPT_PUB_KEY[i] = NEXT_TOKEN;
        TRANSACTION[TX_SIZE++] = SCRIPT_PUB_KEY[i];
    }
    export_script_pub_key(SCRIPT_PUB_KEY);
    return 0;
}

int parse_witness(FILE *dat_file)
{
    for (size_t in = 0; in < TX_IN_COUNT; in++)
    {
        uint64_t stack_items = get_compact_size(dat_file);
        export_stack_items_count(stack_items);

        uint64_t w_size = 0;
        uint64_t w_cap = reverse_compact_size(stack_items);

        fseek(dat_file, -w_cap, SEEK_CUR); // go back
        uint8_t *witness = (uint8_t *) malloc(w_cap * sizeof(uint8_t));

        for (uint64_t i = 0; i < w_cap; ++i)
        {
            witness[w_size++] = NEXT_TOKEN;
        }
        
        for (size_t item = 0; item < stack_items; item++)
        {
            uint64_t size = get_compact_size(dat_file);
            size_t amount = (size_t) reverse_compact_size(size);

            w_cap += size;
            w_cap += (uint64_t) amount;

            uint8_t *new_array = (uint8_t *) realloc(witness, w_cap * (size_t) sizeof(uint8_t));
            witness = new_array;

            fseek(dat_file, -amount, SEEK_CUR);
            while (amount > (size_t) 0)
            {
                witness[w_size++] = NEXT_TOKEN;
                --amount;
            }

            export_stack_item_size(size);
            uint8_t to_stack[size];

            for (size_t i = 0; i < size; ++i)
            {
                to_stack[i] = NEXT_TOKEN;
                witness[w_size++] = to_stack[i];
            }

            export_to_stack(to_stack);
        }
        export_witness(witness, w_cap);
        free(witness);
    }
    return 0;
}

int parse_lock_time(FILE *dat_file)
{
    int result = resize_transaction((size_t) 4);
    if (result != 0) return result;

    uint8_t lock_time[4];

    for (size_t i = 0; i < 4; ++i)
    {
        lock_time[i] = NEXT_TOKEN;
        TRANSACTION[TX_SIZE] = lock_time[i];
        TX_SIZE++;
    }
    export_lock_time(lock_time);
    return 0;
}

int parse_transactions(FILE *dat_file)
{
    for (uint64_t tx = 0; tx < TRANSACTION_COUNT; ++tx)
    {
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
        get_double_sha256((uchar_p) TRANSACTION, TX_SIZE, TX_HASH);

        export_tx_hash(TX_HASH);
    }
    return 0;
}

int parse_dat_file(FILE *dat_file)
{
    int error_code = 0;
    while (true)
    {
        int next_byte = fgetc(dat_file);
        if (next_byte != EOF) ungetc(next_byte, dat_file);
        else break;

        error_code = parse_header(dat_file);
        if (error_code != 0) return error_code;

        parse_transaction_count(dat_file);

        error_code = parse_transactions(dat_file);
        if (error_code != 0) return error_code;
    }
    reset();

    return 0;
}
