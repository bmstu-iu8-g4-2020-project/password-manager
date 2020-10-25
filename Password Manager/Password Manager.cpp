#include "sqlite3.h"
#include <fstream>
#include <iostream>
#include <string>
#include "aes.hpp"


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

      AESEncrypt(password.c_str(), key, encryptedpass);
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

        AESDecrypt(temppass.c_str(), key, decryptedpass);
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
