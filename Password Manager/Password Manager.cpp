#include "aes-master/structures.h"
#include "sqlite3.h"
#include <fstream>
#include <iostream>
#include <string>

class encryption {
public:
  /* Serves as the initial round during encryption
   * AddRoundKey is simply an XOR of a 128-bit block with the 128-bit key.
   */
  void AddRoundKey(unsigned char *state, unsigned char *roundKey) {
    for (int i = 0; i < 16; i++) {
      state[i] ^= roundKey[i];
    }
  }

  /* Perform substitution to each of the 16 bytes
   * Uses S-box as lookup table
   */
  void SubBytes(unsigned char *state) {
    for (int i = 0; i < 16; i++) {
      state[i] = s[state[i]];
    }
  }

  // Shift left, adds diffusion
  void ShiftRows(unsigned char *state) {
    unsigned char tmp[16];

    /* Column 1 */
    tmp[0] = state[0];
    tmp[1] = state[5];
    tmp[2] = state[10];
    tmp[3] = state[15];

    /* Column 2 */
    tmp[4] = state[4];
    tmp[5] = state[9];
    tmp[6] = state[14];
    tmp[7] = state[3];

    /* Column 3 */
    tmp[8] = state[8];
    tmp[9] = state[13];
    tmp[10] = state[2];
    tmp[11] = state[7];

    /* Column 4 */
    tmp[12] = state[12];
    tmp[13] = state[1];
    tmp[14] = state[6];
    tmp[15] = state[11];

    for (int i = 0; i < 16; i++) {
      state[i] = tmp[i];
    }
  }

  /* MixColumns uses mul2, mul3 look-up tables
   * Source of diffusion
   */
  void MixColumns(unsigned char *state) {
    unsigned char tmp[16];

    tmp[0] =
        (unsigned char)mul2[state[0]] ^ mul3[state[1]] ^ state[2] ^ state[3];
    tmp[1] =
        (unsigned char)state[0] ^ mul2[state[1]] ^ mul3[state[2]] ^ state[3];
    tmp[2] =
        (unsigned char)state[0] ^ state[1] ^ mul2[state[2]] ^ mul3[state[3]];
    tmp[3] =
        (unsigned char)mul3[state[0]] ^ state[1] ^ state[2] ^ mul2[state[3]];

    tmp[4] =
        (unsigned char)mul2[state[4]] ^ mul3[state[5]] ^ state[6] ^ state[7];
    tmp[5] =
        (unsigned char)state[4] ^ mul2[state[5]] ^ mul3[state[6]] ^ state[7];
    tmp[6] =
        (unsigned char)state[4] ^ state[5] ^ mul2[state[6]] ^ mul3[state[7]];
    tmp[7] =
        (unsigned char)mul3[state[4]] ^ state[5] ^ state[6] ^ mul2[state[7]];

    tmp[8] =
        (unsigned char)mul2[state[8]] ^ mul3[state[9]] ^ state[10] ^ state[11];
    tmp[9] =
        (unsigned char)state[8] ^ mul2[state[9]] ^ mul3[state[10]] ^ state[11];
    tmp[10] =
        (unsigned char)state[8] ^ state[9] ^ mul2[state[10]] ^ mul3[state[11]];
    tmp[11] =
        (unsigned char)mul3[state[8]] ^ state[9] ^ state[10] ^ mul2[state[11]];

    tmp[12] = (unsigned char)mul2[state[12]] ^ mul3[state[13]] ^ state[14] ^
              state[15];
    tmp[13] = (unsigned char)state[12] ^ mul2[state[13]] ^ mul3[state[14]] ^
              state[15];
    tmp[14] = (unsigned char)state[12] ^ state[13] ^ mul2[state[14]] ^
              mul3[state[15]];
    tmp[15] = (unsigned char)mul3[state[12]] ^ state[13] ^ state[14] ^
              mul2[state[15]];

    for (int i = 0; i < 16; i++) {
      state[i] = tmp[i];
    }
  }

  /* Each round operates on 128 bits at a time
   * The number of rounds is defined in AESEncrypt()
   */
  void Round(unsigned char *state, unsigned char *key) {
    SubBytes(state);
    ShiftRows(state);
    MixColumns(state);
    AddRoundKey(state, key);
  }

  // Same as Round() except it doesn't mix columns
  void FinalRound(unsigned char *state, unsigned char *key) {
    SubBytes(state);
    ShiftRows(state);
    AddRoundKey(state, key);
  }

  /* The AES encryption function
   * Organizes the confusion and diffusion steps into one function
   */
  void AESEncrypt(const char *message, unsigned char *expandedKey,
                  unsigned char *encryptedMessage) {
    unsigned char state[16]; // Stores the first 16 bytes of original message

    for (int i = 0; i < 16; i++) {
      state[i] = message[i];
    }

    int numberOfRounds = 9;

    AddRoundKey(state, expandedKey); // Initial round

    for (int i = 0; i < numberOfRounds; i++) {
      Round(state, expandedKey + (16 * (i + 1)));
    }

    FinalRound(state, expandedKey + 160);

    // Copy encrypted state to buffer
    for (int i = 0; i < 16; i++) {
      encryptedMessage[i] = state[i];
    }
  }
};
class decryption {
public:
  /* Used in Round() and serves as the final round during decryption
   * SubRoundKey is simply an XOR of a 128-bit block with the 128-bit key.
   * So basically does the same as AddRoundKey in the encryption
   */
  void SubRoundKey(unsigned char *state, unsigned char *roundKey) {
    for (int i = 0; i < 16; i++) {
      state[i] ^= roundKey[i];
    }
  }

  /* InverseMixColumns uses mul9, mul11, mul13, mul14 look-up tables
   * Unmixes the columns by reversing the effect of MixColumns in encryption
   */
  void InverseMixColumns(unsigned char *state) {
    unsigned char tmp[16];

    tmp[0] = (unsigned char)mul14[state[0]] ^ mul11[state[1]] ^
             mul13[state[2]] ^ mul9[state[3]];
    tmp[1] = (unsigned char)mul9[state[0]] ^ mul14[state[1]] ^ mul11[state[2]] ^
             mul13[state[3]];
    tmp[2] = (unsigned char)mul13[state[0]] ^ mul9[state[1]] ^ mul14[state[2]] ^
             mul11[state[3]];
    tmp[3] = (unsigned char)mul11[state[0]] ^ mul13[state[1]] ^ mul9[state[2]] ^
             mul14[state[3]];

    tmp[4] = (unsigned char)mul14[state[4]] ^ mul11[state[5]] ^
             mul13[state[6]] ^ mul9[state[7]];
    tmp[5] = (unsigned char)mul9[state[4]] ^ mul14[state[5]] ^ mul11[state[6]] ^
             mul13[state[7]];
    tmp[6] = (unsigned char)mul13[state[4]] ^ mul9[state[5]] ^ mul14[state[6]] ^
             mul11[state[7]];
    tmp[7] = (unsigned char)mul11[state[4]] ^ mul13[state[5]] ^ mul9[state[6]] ^
             mul14[state[7]];

    tmp[8] = (unsigned char)mul14[state[8]] ^ mul11[state[9]] ^
             mul13[state[10]] ^ mul9[state[11]];
    tmp[9] = (unsigned char)mul9[state[8]] ^ mul14[state[9]] ^
             mul11[state[10]] ^ mul13[state[11]];
    tmp[10] = (unsigned char)mul13[state[8]] ^ mul9[state[9]] ^
              mul14[state[10]] ^ mul11[state[11]];
    tmp[11] = (unsigned char)mul11[state[8]] ^ mul13[state[9]] ^
              mul9[state[10]] ^ mul14[state[11]];

    tmp[12] = (unsigned char)mul14[state[12]] ^ mul11[state[13]] ^
              mul13[state[14]] ^ mul9[state[15]];
    tmp[13] = (unsigned char)mul9[state[12]] ^ mul14[state[13]] ^
              mul11[state[14]] ^ mul13[state[15]];
    tmp[14] = (unsigned char)mul13[state[12]] ^ mul9[state[13]] ^
              mul14[state[14]] ^ mul11[state[15]];
    tmp[15] = (unsigned char)mul11[state[12]] ^ mul13[state[13]] ^
              mul9[state[14]] ^ mul14[state[15]];

    for (int i = 0; i < 16; i++) {
      state[i] = tmp[i];
    }
  }

  // Shifts rows right (rather than left) for decryption
  void ShiftRows(unsigned char *state) {
    unsigned char tmp[16];

    /* Column 1 */
    tmp[0] = state[0];
    tmp[1] = state[13];
    tmp[2] = state[10];
    tmp[3] = state[7];

    /* Column 2 */
    tmp[4] = state[4];
    tmp[5] = state[1];
    tmp[6] = state[14];
    tmp[7] = state[11];

    /* Column 3 */
    tmp[8] = state[8];
    tmp[9] = state[5];
    tmp[10] = state[2];
    tmp[11] = state[15];

    /* Column 4 */
    tmp[12] = state[12];
    tmp[13] = state[9];
    tmp[14] = state[6];
    tmp[15] = state[3];

    for (int i = 0; i < 16; i++) {
      state[i] = tmp[i];
    }
  }

  /* Perform substitution to each of the 16 bytes
   * Uses inverse S-box as lookup table
   */
  void SubBytes(unsigned char *state) {
    for (int i = 0; i < 16;
         i++) { // Perform substitution to each of the 16 bytes
      state[i] = inv_s[state[i]];
    }
  }

  /* Each round operates on 128 bits at a time
   * The number of rounds is defined in AESDecrypt()
   * Not surprisingly, the steps are the encryption steps but reversed
   */
  void Round(unsigned char *state, unsigned char *key) {
    SubRoundKey(state, key);
    InverseMixColumns(state);
    ShiftRows(state);
    SubBytes(state);
  }

  // Same as Round() but no InverseMixColumns
  void InitialRound(unsigned char *state, unsigned char *key) {
    SubRoundKey(state, key);
    ShiftRows(state);
    SubBytes(state);
  }

  /* The AES decryption function
   * Organizes all the decryption steps into one function
   */
  void AESDecrypt(const char *encryptedMessage, unsigned char *expandedKey,
                  unsigned char *decryptedMessage) {
    unsigned char state[16]; // Stores the first 16 bytes of encrypted message

    for (int i = 0; i < 16; i++) {
      state[i] = encryptedMessage[i];
    }

    InitialRound(state, expandedKey + 160);

    int numberOfRounds = 9;

    for (int i = 8; i >= 0; i--) {
      Round(state, expandedKey + (16 * (i + 1)));
    }

    SubRoundKey(state, expandedKey); // Final round

    // Copy decrypted state to buffer
    for (int i = 0; i < 16; i++) {
      decryptedMessage[i] = state[i];
    }
  }
};

int main(int argc, char **argv) {
  sqlite3 *db = 0; // DB
  sqlite3_stmt *stmt = nullptr;
  char *err = 0;
  const char *data = "Callback function called";
  char *zErrMsg = 0;
  const char *sql;
  // openning DB
  if (sqlite3_open("my_cosy_database.db", &db))
    std::cout << stderr << "������ ��������/�������� ��: " << sqlite3_errmsg(db)
              << std::endl;
  // SQL execute
  else {
    switch (*argv[1]) {
    case 's': {
      std::ifstream keyfile("aes-master\\keyfile.txt", std::ios::binary);
      std::string keystring;
      std::getline(keyfile, keystring);
      unsigned char *key = new unsigned char[strlen(keystring.c_str()) + 1];

      memcpy(key, keystring.c_str(), strlen(keystring.c_str()));
      sql = _strdup("CREATE TABLE IF NOT EXISTS Passwords(SOURCE TEXT NOT "
                    "NULL, LOGIN TEXT,PASSWORD TEXT );");
      if (sqlite3_exec(db, sql, 0, 0, &err)) {
        std::cout << stderr << "������ SQL: " << err << std::endl;

        sqlite3_free(err);
      }
      const char *source = argv[2];
      const char *login = argv[3];
      std::string password;
      std::cin >> password;
      unsigned char *encryptedpass =
          new unsigned char[strlen(password.c_str()) + 1];

      encryption encrypt;
      encrypt.AESEncrypt(password.c_str(), key, encryptedpass);
      std::string sqstring = "INSERT INTO Passwords "
                             "('Source','Login','Password') VALUES (@0,@1,@2);";

      sql = sqstring.c_str();
      sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
      sqlite3_bind_text(stmt, 1, source, -1, 0);
      sqlite3_bind_text(stmt, 2, login, -1, 0);
      const char *temppass = reinterpret_cast<const char *>(encryptedpass);
      sqlite3_bind_text(stmt, 3, temppass, -1, 0);
      sqlite3_step(stmt);
      // Closing DB
      sqlite3_close(db);
      sqlite3_finalize(stmt);
    } break;

    case 'l': {
      const char *source = argv[2];
      std::ifstream keyfile("aes-master\\keyfile.txt", std::ios::binary);
      std::string keystring;
      std::getline(keyfile, keystring);

      unsigned char *key = new unsigned char[strlen(keystring.c_str()) + 1];

      memcpy(key, keystring.c_str(), strlen(keystring.c_str()) + 1);
      std::string sqstring = "SELECT * from Passwords WHERE SOURCE = @0;";
      sql = sqstring.c_str();
      sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
      int print = sqlite3_bind_text(stmt, 1, source, -1, 0);
      while ((print = sqlite3_step(stmt)) == SQLITE_ROW) {
        std::cout << "Login: " << sqlite3_column_text(stmt, 1) << std::endl;

        const unsigned char *encryptedpass = sqlite3_column_text(stmt, 2);
        unsigned char *decryptedpass = new unsigned char[strlen(
            reinterpret_cast<const char *>(encryptedpass))];
        std::string temppass =
            std::string(reinterpret_cast<const char *>(encryptedpass));

        decryption decrypt;
        decrypt.AESDecrypt(temppass.c_str(), key, decryptedpass);
        std::cout << "Password: " << decryptedpass
                  << "\nand encrypted: " << encryptedpass << std::endl;
        std::cout << std::endl;
      }
      // Closing DB

      sqlite3_close(db);
      sqlite3_finalize(stmt);
    } break;
    default:
      return 0;
      break;
    }
    /*   std::cout << "Has " << argc << " arguements" << std::endl;
       for (int i = 0; i < argc; i++) {
             std::cout << argv[i] << std::endl;
       }*/
    return 0;
  }
}
