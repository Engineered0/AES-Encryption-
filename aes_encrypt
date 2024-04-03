#include <stdint.h>
#include <stdio.h>

#define Nk 4 // Number of 32-bit words in the key.
#define Nb 4 // Block size in words (AES-128 uses 4).
#define Nr 10 // Number of rounds in AES-128.

// Global 2D array to store round keys, making them accessible anywhere
uint8_t globalRoundKeys[Nr + 1][16]; // Nr+1 to include the initial cipher key as "round 0"

// Rcon array for AES Key Expansion
static const uint32_t Rcon[11] = {
    0x00000000, // Dummy value not used
    0x01000000, // 1
    0x02000000, // 2
    0x04000000, // 4
    0x08000000, // 8
    0x10000000, // 16
    0x20000000, // 32
    0x40000000, // 64
    0x80000000, // 128
    0x1B000000, // 27 (for x^8, with polynomial reduction)
    0x36000000  // 54 (for x^9, with polynomial reduction)
};

// 2D S-box array
static const uint8_t s_box[16][16] = {
    {0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76},
    {0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0},
    {0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15},
    {0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75},
    {0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e},
    {0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf},
    {0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8},
    {0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2},
    {0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73},
    {0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb},
    {0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79},
    {0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08},
    {0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a},
    {0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84},
    {0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf},
    {0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16}
};

// Function to map a byte to its S-box value
static uint8_t getSBoxValue(uint8_t num) {
    uint8_t row = (num >> 4) & 0x0F;
    uint8_t col = num & 0x0F;
    return s_box[row][col];
}

// SubWord function using the 2D S-box
static uint32_t SubWord(uint32_t word) {
    return (
        (uint32_t)getSBoxValue((word >> 24) & 0xFF) << 24 |
        (uint32_t)getSBoxValue((word >> 16) & 0xFF) << 16 |
        (uint32_t)getSBoxValue((word >> 8) & 0xFF) << 8 |
        (uint32_t)getSBoxValue(word & 0xFF)
    );
}

// Function to perform the RotWord operation
static uint32_t RotWord(uint32_t word) {
    return (word << 8) | (word >> 24);
}

// Function to perform the AddRoundKey step and print the state
void AddRoundKey(uint8_t state[4][4], int round) {
    for (int col = 0; col < Nb; col++) {
        for (int row = 0; row < 4; row++) {
            state[row][col] ^= globalRoundKeys[round][col * 4 + row];
        }
    }
}


// AES key expansion routine adjusted to fill globalRoundKeys
void KeyExpansion(uint8_t key[4][Nk]) {
    uint32_t w[Nb * (Nr + 1)];
    uint32_t temp;
    int i;

    for (i = 0; i < Nk; i++) {
        w[i] = (uint32_t)key[0][i] << 24 | (uint32_t)key[1][i] << 16 | (uint32_t)key[2][i] << 8 | (uint32_t)key[3][i];
    }

    for (i = Nk; i < Nb * (Nr + 1); i++) {
        temp = w[i - 1];
        if (i % Nk == 0) {
            temp = SubWord(RotWord(temp)) ^ Rcon[i / Nk];
        }
        w[i] = w[i - Nk] ^ temp;
    }

    // Populate the globalRoundKeys array directly from w[]
    for (int round = 0; round <= Nr; ++round) {
        for (int j = 0; j < Nb; ++j) {
            uint32_t word = w[round * Nb + j];
            globalRoundKeys[round][j * 4] = (word >> 24) & 0xFF;
            globalRoundKeys[round][j * 4 + 1] = (word >> 16) & 0xFF;
            globalRoundKeys[round][j * 4 + 2] = (word >> 8) & 0xFF;
            globalRoundKeys[round][j * 4 + 3] = word & 0xFF;
        }
    }
}

void SubBytes(uint8_t state[4][4]) {
    for (int row = 0; row < 4; ++row) {
        for (int col = 0; col < 4; ++col) {
            state[row][col] = getSBoxValue(state[row][col]);
        }
    }
}

void ShiftRows(uint8_t state[4][4]) {
    uint8_t temp;
    // Row 0 doesn't shift.

    // Shift row 1 by 1
    temp = state[1][0];
    for (int i = 0; i < 3; i++) {
        state[1][i] = state[1][i + 1];
    }
    state[1][3] = temp;

    // Shift row 2 by 2
    temp = state[2][0];
    state[2][0] = state[2][2];
    state[2][2] = temp;
    temp = state[2][1];
    state[2][1] = state[2][3];
    state[2][3] = temp;

    // Shift row 3 by 3 (or 1 to the right)
    temp = state[3][3];
    for (int i = 3; i > 0; i--) {
        state[3][i] = state[3][i - 1];
    }
    state[3][0] = temp;
}


uint8_t gmul(uint8_t a, uint8_t b) {
    uint8_t p = 0;
    uint8_t hi_bit_set;
    for (int i = 0; i < 8; i++) {
        if (b & 1) {
            p ^= a;
        }
        hi_bit_set = a & 0x80; // Check if the high bit of 'a' is set
        a <<= 1; // Shift 'a' left by 1 bit
        if (hi_bit_set) {
            a ^= 0x1B; /* XOR with the irreducible polynomial x^8 + x^4 + x^3 + x + 1 */
        }
        b >>= 1; // Shift 'b' right by 1 bit
    }
    return p;
}




void MixColumns(uint8_t state[4][4]) {
    uint8_t temp[4];
    for (int i = 0; i < 4; i++) {
        temp[0] = gmul(state[0][i], 0x02) ^ gmul(state[1][i], 0x03) ^ state[2][i] ^ state[3][i];
        temp[1] = state[0][i] ^ gmul(state[1][i], 0x02) ^ gmul(state[2][i], 0x03) ^ state[3][i];
        temp[2] = state[0][i] ^ state[1][i] ^ gmul(state[2][i], 0x02) ^ gmul(state[3][i], 0x03);
        temp[3] = gmul(state[0][i], 0x03) ^ state[1][i] ^ state[2][i] ^ gmul(state[3][i], 0x02);
        
        for (int j = 0; j < 4; j++) {
            state[j][i] = temp[j];
        }
    }
}





void PrintState(uint8_t state[4][4], const char* step, int round) {
    printf("%s after Round %d:\n", step, round);
    for (int row = 0; row < 4; row++) {
        for (int col = 0; col < 4; col++) {
            printf("%02x ", state[row][col]); // Corrected access to state matrix
        }

    }
    printf("\n"); // Extra newline for clarity
}


void PrintAllRoundKeys() {
    printf("All Round Keys:\n");
    for (int round = 0; round <= Nr; ++round) {
        printf("Round %d Key: \n", round);
        for (int i = 0; i < 16; ++i) {
            printf("%02x ", globalRoundKeys[round][i]);
            if ((i + 1) % 4 == 0) printf("\n");
        }
        printf("\n"); // Extra newline for spacing between keys
    }
}

int main() {
    uint8_t key[4][Nk] = {
        {0x1a, 0x0c, 0x24, 0xf2},
        {0x87, 0x54, 0x95, 0xbc},
        {0xb7, 0x08, 0x0e, 0x43},
        {0x92, 0x0f, 0x56, 0x96}
    };
    
    uint8_t plaintext[4][4] = {
        {0x00, 0x00, 0x00, 0x00},
        {0x00, 0x00, 0x00, 0x00},
        {0x00, 0x00, 0x00, 0x00},
        {0x00, 0x00, 0xab, 0xe6}
    };

    KeyExpansion(key); // globalRoundKeys is populated here
    PrintAllRoundKeys();
    // Initial AddRoundKey (Round 0)
    AddRoundKey(plaintext, 0);
    PrintState(plaintext, "AddRoundKey", 0);

    // Rounds 1 to Nr-1
    for (int round = 1; round < Nr; round++) {
        SubBytes(plaintext);
        ShiftRows(plaintext);
        MixColumns(plaintext);
        AddRoundKey(plaintext, round);
        PrintState(plaintext, "Round", round);
    }

    // Final Round (does not include MixColumns)
    SubBytes(plaintext);
    ShiftRows(plaintext);
    AddRoundKey(plaintext, Nr);
    PrintState(plaintext, "Round", Nr);

    // The `plaintext` array now holds the cipher text after the final round

    return 0;
}
