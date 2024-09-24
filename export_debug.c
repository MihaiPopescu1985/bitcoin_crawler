#include "export_debug.h"

static uint64_t SCRIPT_SIG_SIZE = 0;
static uint64_t PUB_KEY_SIZE = 0;
static uint64_t ITEM_SIZE = 0;


// Header
void export_magic_number(uint8_t magic_bytes[4])
{
    printf("Parsed magic number: ");
    printf("%02X", magic_bytes[0]);
    printf("%02X", magic_bytes[1]);
    printf("%02X", magic_bytes[2]);
    printf("%02X", magic_bytes[3]);
    printf("\n");
}

void export_block_size(uint8_t block_size[4])
{
    printf("Parsed block size: ");
    printf("%02X", block_size[0]);
    printf("%02X", block_size[1]);
    printf("%02X", block_size[2]);
    printf("%02X", block_size[3]);
    printf("\n");
}

void export_header_version(uint8_t header_version[4])
{
    printf("Parsed header version: ");
    printf("%02X", header_version[0]);
    printf("%02X", header_version[1]);
    printf("%02X", header_version[2]);
    printf("%02X", header_version[3]);
    printf("\n");
}

void export_prev_hash(uint8_t prev_hash[32])
{
    printf("Parsed previous block hash: ");
    for(size_t i = 0; i < 32; ++i)
    {
        printf("%02X", prev_hash[i]);
    }
    printf("\n");
}

void export_merkle_root(uint8_t merkle_root[32])
{
    printf("Parsed merkel root: ");
    for(size_t i = 0; i < 32; ++i)
    {
        printf("%02X", merkle_root[i]);
    }
    printf("\n");
}

void export_block_time(uint8_t block_time[4])
{
    printf("Parsed block time: ");
    printf("%02X", block_time[0]);
    printf("%02X", block_time[1]);
    printf("%02X", block_time[2]);
    printf("%02X", block_time[3]);
    printf("\n");
}

void export_nbytes(uint8_t nbyes[4])
{
    printf("Parsed nbytes: ");
    printf("%02X", nbyes[0]);
    printf("%02X", nbyes[1]);
    printf("%02X", nbyes[2]);
    printf("%02X", nbyes[3]);
    printf("\n");
}

void export_nonce(uint8_t nonce[4])
{
    printf("Parsed nonce: ");
    printf("%02X", nonce[0]);
    printf("%02X", nonce[1]);
    printf("%02X", nonce[2]);
    printf("%02X", nonce[3]);
    printf("\n");
}

void export_block_hash(unsigned char block_hash[32])
{
    printf("Parsed block hash: ");
    for(size_t i = 0; i < 32; ++i)
    {
        printf("%02X", block_hash[i]);
    }
    printf("\n");
}

// Transaction count
void export_transaction_count(uint64_t tx_count)
{
    printf("Parsed transaction count: %ld\n", tx_count);
}

// Transaction
void export_tx_version(uint8_t tx_version[4])
{
    printf("Parsed transaction version: ");
    printf("%02X", tx_version[0]);
    printf("%02X", tx_version[1]);
    printf("%02X", tx_version[2]);
    printf("%02X", tx_version[3]);
    printf("\n");
}

// Transaction input
void export_flag(uint8_t flag)
{
    printf("Parsed flag: %d\n", flag);
}

void export_tx_in_count(uint64_t tx_in_count)
{
    printf("Parsed transaction input count: %ld\n", tx_in_count);
}

void export_tx_id(uint8_t tx_id[32])
{
    printf("Parsed transaction id: ");
    for(size_t i = 0; i < 32; ++i)
    {
        printf("%02X", tx_id[i]);
    }
    printf("\n");
}

void export_input_vout(uint8_t vout[4])
{
    printf("Parsed vout: ");
    printf("%02X", vout[0]);
    printf("%02X", vout[1]);
    printf("%02X", vout[2]);
    printf("%02X", vout[3]);
    printf("\n");
}

void export_script_sig_size(uint64_t script_sig_size)
{
    SCRIPT_SIG_SIZE = script_sig_size;
    printf("Parsed scriptSig size: %ld\n", script_sig_size);
}

void export_script_sig(uint8_t *script_sig)
{
    printf("Parsed script sig: ");
    for(uint64_t i = 0; i < SCRIPT_SIG_SIZE; ++i)
    {
        printf("%02X", script_sig[i]);
    }
    printf("\n");
}

void export_tx_in_sequence(uint8_t tx_in_sequence[4])
{
    printf("Parsed tx in sequence: ");
    printf("%02X", tx_in_sequence[0]);
    printf("%02X", tx_in_sequence[1]);
    printf("%02X", tx_in_sequence[2]);
    printf("%02X", tx_in_sequence[3]);
    printf("\n");
}

// Transaction output
void export_tx_out_count(uint64_t tx_out_count)
{
    printf("Parsed tx out count: %ld\n", tx_out_count);
}

void export_amount(uint8_t amount[8])
{
    printf("Parsed amount: ");
    printf("%02X", amount[0]);
    printf("%02X", amount[1]);
    printf("%02X", amount[2]);
    printf("%02X", amount[3]);
    printf("%02X", amount[4]);
    printf("%02X", amount[5]);
    printf("%02X", amount[6]);
    printf("%02X", amount[7]);
    printf("\n");
}

void export_pub_key_size(uint64_t pub_key_size)
{
    PUB_KEY_SIZE = pub_key_size;
    printf("Parsed public key size: %ld\n", pub_key_size);
}

void export_script_pub_key(uint8_t *script_pub_key)
{
    printf("Parsed script public key size: ");
    for(size_t i = 0; i < PUB_KEY_SIZE; ++i)
    {
        printf("%02X", script_pub_key[i]);
    }
    printf("\n");
}

// Transaction witness
void export_stack_items_count(uint64_t stack_item_count)
{
    printf("Parsed stack item count: %ld\n", stack_item_count);
}

void export_stack_item_size(uint64_t item_size)
{
    ITEM_SIZE = item_size;
    printf("Parsed item size: %ld\n", item_size);
}

void export_to_stack(uint8_t *to_stack)
{
    printf("Parsed to stack: ");
    for(uint64_t i = 0; i < ITEM_SIZE; ++i)
    {
        printf("%02X", to_stack[i]);
    }
    printf("\n");
}

void export_witness(uint8_t *witness, uint64_t witness_size)
{
    printf("Parsed witness: ");
    for(uint64_t i = 0; i < witness_size; ++i)
    {
        printf("%02X", witness[i]);
    }
    printf("\n");
}

void export_lock_time(uint8_t lock_time[4])
{
    printf("Parsed lock time: ");
    printf("%02X", lock_time[0]);
    printf("%02X", lock_time[1]);
    printf("%02X", lock_time[2]);
    printf("%02X", lock_time[3]);
    printf("\n");
}

void export_tx_hash(uint8_t tx_hash[32])
{
    printf("Parsed transaction hash: ");
    for(size_t i = 0; i < 32; ++i)
    {
        printf("%02X", tx_hash[i]);
    }
    printf("\n");
}
