#ifndef EXPORT_DEBUG
#define EXPORT_DEBUG

#include <stdio.h>
#include <stdint.h>

// Header
void export_magic_number(uint8_t magic_bytes[4]);
void export_block_size(uint8_t block_size[4]);
void export_header_version(uint8_t header_version[4]);
void export_prev_hash(uint8_t prev_hash[32]);
void export_merkle_root(uint8_t merkle_root[32]);
void export_block_time(uint8_t block_time[4]);
void export_nbytes(uint8_t nbyes[4]);
void export_nonce(uint8_t nonce[4]);
void export_block_hash(unsigned char block_hash[32]);

// Transaction count
void export_transaction_count(uint64_t tx_count);

// Transaction
void export_tx_version(uint8_t tx_version[4]);

// Transaction input
void export_flag(uint8_t flag);
void export_tx_in_count(uint64_t tx_in_count);
void export_tx_id(uint8_t tx_id[32]);
void export_input_vout(uint8_t vout[4]);
void export_script_sig_size(uint64_t script_sig_size);
void export_script_sig(uint8_t *script_sig);
void export_tx_in_sequence(uint8_t tx_in_sequence[4]);

// Transaction output
void export_tx_out_count(uint64_t tx_out_count);
void export_amount(uint8_t amount[8]);
void export_pub_key_size(uint64_t pub_key_size);
void export_script_pub_key(uint8_t *script_pub_key);

// Transaction witness
void export_stack_items_count(uint64_t stack_items);
void export_stack_item_size(uint64_t size);
void export_to_stack(uint8_t *to_stack);
void export_witness(uint8_t *witness, uint64_t witness_size);

void export_lock_time(uint8_t lock_time[4]);
void export_tx_hash(uint8_t tx_hash[32]);

#endif
