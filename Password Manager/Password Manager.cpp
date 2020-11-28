#include "Third-party\\AES\\AES.h"
#include "Third-party\\Sqlite3\\sqlite3.h"
#include <fstream>
#include <iostream>
#include <string>
#pragma warning(disable : 4996)

void save(char **argv, sqlite3 *db, sqlite3_stmt *stmt,
          char *err) // Code related to saving (name for a place, name for
                     // login, password) into a database
{
  // Opening key
  std::ifstream keyfile("keyfile", std::ios::binary);
  std::string keystring;
  std::getline(keyfile, keystring);
  unsigned char *key = new unsigned char[strlen(keystring.c_str()) + 1];

  memcpy(key, keystring.c_str(), strlen(keystring.c_str()));
  // Creating a table if it doesn't exist already
  const char *sql =
      _strdup("CREATE TABLE IF NOT EXISTS Passwords(SOURCE TEXT NOT "
              "NULL, LOGIN TEXT,PASSWORD TEXT );");

  if (sqlite3_exec(db, sql, 0, 0, &err)) { // In case of error, we exit
    std::cout << stderr << "Error SQL: " << err << std::endl;

    sqlite3_free(err);
  } else {
    const char *source = argv[2];
    const char *login = argv[3];
    std::string password;
    std::cin >> password;
    // Prepairing password for encryption

    unsigned char *encryptedpass = new unsigned char[strlen(
        password.c_str())]; // char* for encrypted password

    unsigned char *temppas = new unsigned char[strlen(password.c_str()) +
                                               1]; // Copy of original password

    strcpy((char *)temppas, password.c_str()); // Copying original password

    // Encryption process
    unsigned int outlen = 0;

    AES encryp;
    encryptedpass = encryp.EncryptECB(temppas, strlen((char *)temppas) + 1, key,
                                      outlen); // Encrypting password
    cout << encryptedpass << endl;

    // Creting a string for execution
    std::string sqstring =
        "INSERT INTO Passwords "
        "('Source', 'Login', 'Password') VALUES (@0, @1, @2);";

    sql = sqstring.c_str();
    sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, source, -1, 0);
    sqlite3_bind_text(stmt, 2, login, -1, 0);
    sqlite3_bind_text(stmt, 3, (const char *)encryptedpass, -1, 0);
    sqlite3_step(stmt); // Entering data to database
    // Closing DB
    sqlite3_close(db);
    sqlite3_finalize(stmt);
  }
};

void print(unsigned char *key, sqlite3 *db, sqlite3_stmt *stmt,
           const char *source)
// Code related to printing out entire table for (name for a place)
{
  int print = sqlite3_bind_text(stmt, 1, source, -1, 0);
  while ((print = sqlite3_step(stmt)) == SQLITE_ROW) {

    std::cout << "Login: " << sqlite3_column_text(stmt, 1)
              << std::endl; // Printing login

    // Prepairing password for decryption

    const unsigned char *encryptedpass = sqlite3_column_text(
        stmt, 2); // Reading encrypted password from database

    unsigned char *encryptemp =
        new unsigned char[strlen((char *)encryptedpass)]; // Copy for decryption

    memcpy(encryptemp, encryptedpass,
           strlen((char *)encryptedpass)); // Copying encrypted password

    unsigned char *decryptedpass = new unsigned char[strlen(
        (char *)encryptedpass)]; // char* for decrypted password

    // Decryption process
    AES decryp;
    decryptedpass =
        decryp.DecryptECB(encryptemp, strlen((char *)encryptedpass) + 1, key);

    cout << decryptedpass << endl; // Printing password
  }
  sqlite3_close(db);
  sqlite3_finalize(stmt); // Closing DB
};

void load(
    char **argv, sqlite3 *db, sqlite3_stmt *stmt,
    char *err) //  Code related to loading ( name for
               // login, password) from a database via given (name for a place)
{
  const char *source = argv[2];
  std::ifstream keyfile("keyfile", std::ios::binary); // Loads a key in binary
  std::string keystring;
  std::getline(keyfile, keystring); // Loading key

  unsigned char *key = new unsigned char[strlen(keystring.c_str()) + 1];

  memcpy(key, keystring.c_str(), strlen(keystring.c_str()) + 1); // Copying key

  std::string sqstring = "SELECT * from Passwords WHERE SOURCE = @0;";
  const char *sql = sqstring.c_str();
  sqlite3_prepare_v2(db, sql, -1, &stmt, NULL); // Opening database

  print(key, db, stmt,
        source); // Printing (name of login, password) and closing database
};

int main(int argc, char **argv) {
  /*First arguement [s or l]
  [s] needs extra arguements (name for a place, name for login)
  [s] saves (name for a place, name for login, password) to database. Password
  gets encrypted. [l] needs extra arguements (name for a place)

  [l] loads (name for a login, password) from database onto a screen. Password
  gets decrypted.
  [l] will load all names related to (name for a place)*/

  sqlite3 *db = 0; // DB
  sqlite3_stmt *stmt = nullptr;
  char *err = 0;
  const char *data = "Callback function called";
  char *zErrMsg = 0;
  const char *sql;
  // Openning DB
  if (sqlite3_open("my_cosy_database.db", &db))
    std::cout << stderr << "Error with openning DB: " << sqlite3_errmsg(db)
              << std::endl;
  // SQL execute
  else {
    if (argc > 1) {
      switch (*argv[1]) {
      case 's': {
        // saving (name for a place, name for login, password) to database.
        save(argv, db, stmt, err);
      } break;
      case 'l': {
        // loading (name for a login, password) from database.
        load(argv, db, stmt, err);
      } break;
      default:
        return 0;
        break;
      }
    } else {
      std::cout << "No arguements given." << std::endl;
    }
    // Part of code used for checking arguements
    /*   std::cout << "Has " << argc << " arguements" << std::endl;
       for (int i = 0; i < argc; i++) {
                     std::cout << argv[i] << std::endl;
       }*/
    return 0;
  }
}
