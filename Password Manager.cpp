#include "Third-party\\AES\\AES.h"
#include "Third-party\\Sqlite3\\sqlite3.h"
#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <fstream>
#include <iostream>
#include <msxml.h>
#include <stdio.h>
#include <string>
#include <tchar.h>
#include <vector>
#include <winuser.h>

#pragma warning(disable : 4996)

unsigned char *toEncrypt(std::string word,
                         unsigned char *key) // Encryption of strings
{
  unsigned char *encryptedword =
      new unsigned char[strlen(word.c_str())]; // char* for encrypted password

  unsigned char *tempword =
      new unsigned char[strlen(word.c_str()) + 1]; // Copy of original password

  strcpy((char *)tempword, word.c_str()); // Copying original password

  // Encryption process
  unsigned int outlen = 0;

  AES encryp;
  encryptedword = encryp.EncryptECB(tempword, strlen((char *)tempword) + 1, key,
                                    outlen); // Encrypting password
  return encryptedword;
}
unsigned char *toEncrypt(std::vector<char> word,
                         unsigned char *key) // Encryption of vector<char>
{
  unsigned char *encryptedword =
      new unsigned char[word.size()]; // char* for encrypted password

  unsigned char *tempword =
      new unsigned char[word.size() + 1]; // Copy of original password
  for (size_t i = 0; i < word.size(); i++) {
    tempword[i] = word[i];
  }

  // Encryption process
  unsigned int outlen = 0;

  AES encryp;
  encryptedword = encryp.EncryptECB(tempword, strlen((char *)tempword) + 1, key,
                                    outlen); // Encrypting password
  return encryptedword;
}
unsigned char *
toDecrypt(const unsigned char *encryptedword,
          unsigned char *key) // Decryption of const unsigned char* (used only
                              // when we get data out of DB)
{

  unsigned char *encryptemp =
      new unsigned char[strlen((char *)encryptedword)]; // Copy for decryption

  memcpy(encryptemp, encryptedword,
         strlen((char *)encryptedword)); // Copying encrypted password

  unsigned char *decryptedword = new unsigned char[strlen(
      (char *)encryptedword)]; // char* for decrypted password

  // Decryption process
  AES decryp;
  decryptedword =
      decryp.DecryptECB(encryptemp, strlen((char *)encryptedword) + 1, key);
  return decryptedword;
}

void save(std::vector<char *> data, sqlite3 *db, sqlite3_stmt *stmt,
          char *err) // Code related to saving (name for a place, name for
                     // login, password) into a database
{
  // Opening key
  std::ifstream keyfile("keyfile", std::ios::binary);
  std::string keystring;
  std::getline(keyfile, keystring);
  unsigned char *key = new unsigned char[strlen(keystring.c_str()) + 1];

  memcpy(key, keystring.c_str(), strlen(keystring.c_str()) + 1);
  // Creating a table if it doesn't exist already
  const char *sql =
      _strdup("CREATE TABLE IF NOT EXISTS Passwords(SOURCE TEXT NOT "
              "NULL, LOGIN TEXT,PASSWORD TEXT, DATE TEXT);");

  if (sqlite3_exec(db, sql, 0, 0, &err)) { // In case of error, we exit
    std::cout << stderr << "Error SQL: " << err << std::endl;

    sqlite3_free(err);
  } else {
    const char *source = data[0];
    const char *login = data[1];
    std::string password;
    std::cout << "Please write [password]: ";
    std::cin >> password;
    // Prepairing password for encryption

    unsigned char *encryptedpass = toEncrypt(password, key);

    cout << encryptedpass << endl;

    // Creting a string for execution
    std::string sqstring =
        "INSERT INTO Passwords "
        "('Source', 'Login', 'Password', 'Date') VALUES (@0, @1, @2, @3);";
    // current date/time based on current system
    time_t now = time(0);

    // convert now to string form
    const char *dt = ctime(&now);

    sql = sqstring.c_str();
    sqlite3_prepare_v2(db, sql, -1, &stmt, NULL);
    sqlite3_bind_text(stmt, 1, source, -1, 0);
    sqlite3_bind_text(stmt, 2, login, -1, 0);
    sqlite3_bind_text(stmt, 3, (const char *)encryptedpass, -1, 0);
    sqlite3_bind_text(stmt, 4, dt, -1, 0);
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

    unsigned char *decryptedpass = new unsigned char[strlen(
        (char *)encryptedpass)]; // char* for decrypted password

    // Decryption process
    AES decryp;
    decryptedpass = toDecrypt(encryptedpass, key);

    cout << decryptedpass << endl; // Printing password
    std::cout << "Date: " << sqlite3_column_text(stmt, 3) << std::endl;
  }
  sqlite3_close(db);
  sqlite3_finalize(stmt); // Closing DB
};

void printHidden(unsigned char *key, sqlite3 *db, sqlite3_stmt *stmt,
                 const char *source)
// Code related to printing out entire table for (name for a place)
{
  int print = sqlite3_bind_text(stmt, 1, source, -1, 0);
  while ((print = sqlite3_step(stmt)) == SQLITE_ROW) {

    std::cout << "Login: " << sqlite3_column_text(stmt, 1)
              << std::endl; // Printing login

    const unsigned char *encryptedpass = sqlite3_column_text(
        stmt, 2); // Reading encrypted password from database

    unsigned char *decryptedpass = toDecrypt(encryptedpass, key);
    unsigned char *hiddenPass =
        new unsigned char[strlen((char *)decryptedpass) + (rand() % 5)];

    for (size_t i = 0; i < strlen((char *)hiddenPass); i++) {
      hiddenPass[i] = '*';
    }
    std::cout << "Password (Hidden): " << hiddenPass
              << endl; // Printing password
    std::cout << "Date: " << sqlite3_column_text(stmt, 3) << std::endl;
  }
  sqlite3_close(db);
  sqlite3_finalize(stmt); // Closing DB
};

void load(std::vector<char *> data, sqlite3 *db, sqlite3_stmt *stmt,
          char *err) //  Code related to loading ( name for
                     // login, password) from a database via given (name for
                     // a place)
{
  std::ifstream keyfile("keyfile",
                        std::ios::binary); // Loads a key in binary
  std::string keystring;
  std::getline(keyfile, keystring); // Loading key

  unsigned char *key = new unsigned char[strlen(keystring.c_str()) + 1];

  memcpy(key, keystring.c_str(),
         strlen(keystring.c_str()) + 1); // Copying key

  unsigned char *source = (unsigned char *)data[0];
  std::string sqstring = "SELECT * from Passwords WHERE SOURCE = @0;";

  const char *sql = sqstring.c_str();
  sqlite3_prepare_v2(db, sql, -1, &stmt, NULL); // Opening database

  print(key, db, stmt,
        (const char *)source); // Printing (name of login, password) and
                               // closing database
};

void hidden(std::vector<char *> data, sqlite3 *db, sqlite3_stmt *stmt,
            char *err) //  Code related to loading ( name for
                       // login) (password but hidden [Instead shows ***
                       // with random amount of symbols])from a database via
                       // given (name for a place)
{
  std::ifstream keyfile("keyfile",
                        std::ios::binary); // Loads a key in binary
  std::string keystring;
  std::getline(keyfile, keystring); // Loading key

  unsigned char *key = new unsigned char[strlen(keystring.c_str()) + 1];

  memcpy(key, keystring.c_str(),
         strlen(keystring.c_str()) + 1); // Copying key

  unsigned char *source = (unsigned char *)data[0];
  std::string sqstring = "SELECT * from Passwords WHERE SOURCE = @0;";

  const char *sql = sqstring.c_str();
  sqlite3_prepare_v2(db, sql, -1, &stmt, NULL); // Opening database

  printHidden(key, db, stmt,
              (const char *)source); // Printing (name of login, password)
                                     // and closing database
};

void toClipboard(const char *&s) { // Code related to copying to Clipboard
                                   // (currently doesn't work)
  OpenClipboard(0);
  EmptyClipboard();
  HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, strlen(s));
  if (!hg) {
    CloseClipboard();
    return;
  }
  memcpy(GlobalLock(hg), s, strlen(s));
  GlobalUnlock(hg);
  SetClipboardData(CF_TEXT, hg);
  CloseClipboard();
  GlobalFree(hg);
}
void copy(
    std::vector<char *> data, sqlite3 *db, sqlite3_stmt *stmt,
    char *err) // Code related to prepairing data to be copied to Clipboard
{

  std::ifstream keyfile("keyfile",
                        std::ios::binary); // Loads a key in binary
  std::string keystring;
  std::getline(keyfile, keystring); // Loading key

  unsigned char *key = new unsigned char[strlen(keystring.c_str()) + 1];

  memcpy(key, keystring.c_str(),
         strlen(keystring.c_str()) + 1); // Copying key

  std::string sqstring =
      "SELECT PASSWORD from Passwords WHERE SOURCE = @0, LOGIN = @1;";
  const char *sql = sqstring.c_str();
  sqlite3_prepare_v2(db, sql, -1, &stmt, NULL); // Opening database
  sqlite3_bind_text(stmt, 1, data[0], -1, 0);
  int print = sqlite3_bind_text(stmt, 2, data[1], -1, 0);
  while ((print = sqlite3_step(stmt)) == SQLITE_ROW) {

    // Prepairing password for decryption

    const unsigned char *encryptedpass = sqlite3_column_text(
        stmt, 2); // Reading encrypted password from database

    unsigned char *decryptedpass =
        toDecrypt(encryptedpass, key); // char* for decrypted password

    // Decryption process
    toClipboard((const char *&)decryptedpass);
  }
  sqlite3_close(db);
  sqlite3_finalize(stmt); // Closing DB
};

void loadDate() // Loads last date from file
{
  std::ifstream datefile("datefile.txt");
  std::string date;
  getline(datefile, date);
  std::cout << "Last entry was at: " << date << std::endl;
  datefile.close();
};

void saveDate() // Saves current date, overrides old one
{
  std::ofstream datefile("datefile.txt");

  // current date/time based on current system
  time_t now = time(0);

  // convert now to string form
  char *dt = ctime(&now);
  datefile << dt << "\n";
};

int main(int argc, char **argv) {
  loadDate(); // Showing last entry
  saveDate(); // Saving current entry
  char command;
  std::vector<std::string> names(2);
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
  else { // Changed to commands in console
    std::cout << "Write a command." << std::endl
              << "s = saves[name for a place, name for login, "
                 "password] to database."
              << std::endl
              << "l = loads [name for a login, password] "
                 "from database. "
              << std::endl
              << "h = loads [name for a login, password (hidden, only "
                 "shows ***)] "
                 "from database."
              << std::endl
              << "c = copy [password] via given [name for a place,name for "
                 "a login]"
              << std::endl
              << "e = exits program" << std::endl;

    std::cin >> command;

    while (command != 'e') {
      switch (command) {
      case 's': {
        // saving (name for a place, name for login, password) to database.
        std::cout << "Please write [name for a place]: ";
        std::cin >> names[0];
        std::cout << "Please write [name for a login]: ";
        std::cin >> names[1];
        std::vector<char *> tempnames(2);
        tempnames.resize(names.size(), nullptr);
        std::transform(
            std::begin(names), std::end(names), std::begin(tempnames),
            [&](const std::string &str) { return (char *)str.c_str(); });
        save(tempnames, db, stmt, err);
      } break;
      case 'l': {
        // loading (name for a login, password) from database.
        std::cout << "Please write [name for a place]: ";
        std::cin >> names[0];
        std::vector<char *> tempnames(2);
        tempnames.resize(names.size(), nullptr);
        std::transform(
            std::begin(names), std::end(names), std::begin(tempnames),
            [&](const std::string &str) { return (char *)str.c_str(); });
        load(tempnames, db, stmt, err);
      } break;
      case 'h': {
        // Loading (name of a login) (password but hidden [Instead shows ***
        // with random amount of symbols]) from database.
        std::cout << "Please write [name for a place]: ";
        std::cin >> names[0];
        std::vector<char *> tempnames(2);
        tempnames.resize(names.size(), nullptr);
        std::transform(
            std::begin(names), std::end(names), std::begin(tempnames),
            [&](const std::string &str) { return (char *)str.c_str(); });
        hidden(tempnames, db, stmt, err);
        break;
      }
      case 'c': {
        // Copying (password) via given (name for a place, name for login)
        std::cout << "Please write [name for a place]: ";
        std::cin >> names[0];
        std::cout << "Please write [name for a login]: ";
        std::cin >> names[1];
        std::vector<char *> tempnames(2);
        tempnames.resize(names.size(), nullptr);
        std::transform(
            std::begin(names), std::end(names), std::begin(tempnames),
            [&](const std::string &str) { return (char *)str.c_str(); });
        copy(tempnames, db, stmt, err);
        std::cout << "Copied" << std::endl;
        break;
      }
      case 'e': {
        return 0;
        break;
      }
      default:
        std::cout << "Wrong command, exiting..." << std::endl;
        return 0;
        break;
      }
      std::cout << "Please, write another command." << std::endl;
      cin >> command;
    }
    return 0;
  }
}
