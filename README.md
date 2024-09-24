# bitcoin_crawler
The fastest Bitcoin blockchain parser.

# Dependencies
sudo apt install openssl libssl-dev

# Build
gcc -Wall -o ./build/crawler main.c blk_dat_parser.c export_debug.c -lcrypto

# Run
./build/crawler 1 blk00000.dat
