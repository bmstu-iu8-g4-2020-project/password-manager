#include "sqlite3.h"
#include <fstream>
#include <iostream>
#include <string>

int main(int argc, char **argv) {
  sqlite3 *db = 0; // хэндл объекта соединение к БД
  sqlite3_stmt *stmt = nullptr;
  char *err = 0;

  // открываем соединение
  if (sqlite3_open("my_cosy_database.db", &db))
    std::cout << stderr << "Ошибка открытия/создания БД: " << sqlite3_errmsg(db)
              << std::endl;
  // выполняем SQL
  else {
    switch (*argv[1]) {
    case 's': {
      char *sql = _strdup("CREATE TABLE Passwords(") + *argv[2] +
                  *_strdup("NAME TEXT NOT NULL,ID INT PRIMARY KEY NOT "
                           "NULL);");
      if (sqlite3_exec(db, sql, 0, 0, &err)) {
        std::cout << stderr << "Ошибка SQL: " << err << std::endl;

        sqlite3_free(err);
      }
      // закрываем соединение
      sqlite3_close(db);
      sqlite3_finalize(stmt);
    } break;
    case 'l':
      break;
    default:
      return 0;
      break;
    }
    std::cout << "Has " << argc << " arguements" << std::endl;
    for (int i = 0; i < argc; i++) {
      std::cout << argv[i] << std::endl;
    }
    return 0;
  }
}
