#ifndef AES_HPP
#define AES_HPP
// Encryption part
void AddRoundKey(unsigned char *state, unsigned char *roundKey) {}
void SubBytes(unsigned char *state) {}
void ShiftRows(unsigned char *state) {}
void MixColumns(unsigned char *state) {}
void Round(unsigned char *state, unsigned char *key) {}
void FinalRound(unsigned char *state, unsigned char *key) {}
void AESEncrypt(const char *message, unsigned char *expandedKey,
                unsigned char *encryptedMessage) {}

// Decryption part
void SubRoundKey(unsigned char *state, unsigned char *roundKey) {}
void InverseMixColumns(unsigned char *state) {}
void InitialRound(unsigned char *state, unsigned char *key) {}
void AESDecrypt(const char *encryptedMessage, unsigned char *expandedKey,
                unsigned char *decryptedMessage) {}
#endif AES_HPP
