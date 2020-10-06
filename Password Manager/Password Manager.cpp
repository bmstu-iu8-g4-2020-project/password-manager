#include "sqlite3.h"
#include <fstream>
#include <iostream>
#include <string>

int callback(void* NotUsed, int argc, char** argv, char** azColName) {
	for (size_t i = 1; i < argc; i++) {
		std::cout << azColName[i] << ": " << argv[i] << std::endl;
	}
	std::cout << std::endl;
	return 0;
}

int main(int argc, char** argv) {
	sqlite3* db = 0; // хэндл объекта соединение к БД
	sqlite3_stmt* stmt = nullptr;
	char* err = 0;
	const char* data = "Callback function called";
	char* zErrMsg = 0;
	const char* sql;
	// открываем соединение
	if (sqlite3_open("my_cosy_database.db", &db))
		std::cout << stderr << "Ошибка открытия/создания БД: " << sqlite3_errmsg(db)
		<< std::endl;
	// выполняем SQL
	else {
		switch (*argv[1]) {
		case 's': {
			sql = _strdup("CREATE TABLE IF NOT EXISTS Passwords(SOURCE TEXT NOT NULL, LOGIN TEXT,PASSWORD TEXT );");
			if (sqlite3_exec(db, sql, 0, 0, &err)) {
				std::cout << stderr << "Ошибка SQL: " << err << std::endl;

				sqlite3_free(err);
			}
			std::string arg = argv[2];
			std::string arg1 = argv[3];
			std::string password;
			std::cin >> password;
			std::string sqstring = "INSERT INTO Passwords VALUES('" + arg + "','" + arg1 + "','" + password + "');";

			sql = sqstring.c_str();

			if (sqlite3_exec(db, sql, 0, 0, &err)) {
				std::cout << stderr << "Ошибка SQL: " << err << std::endl;

				sqlite3_free(err);
			}
			// закрываем соединение
			sqlite3_close(db);
			sqlite3_finalize(stmt);
		} break;
		case 'l': {
			std::string arg = argv[2];
			std::string sqstring = "SELECT * from Passwords WHERE SOURCE = '" + arg +"';";
			sql = sqstring.c_str();
			if (sqlite3_exec(db, sql, callback, (void*)data, &zErrMsg)) {
				std::cout << stderr << "Ошибка SQL: " << err << std::endl;;
				sqlite3_free(err);
			}
		} break;
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
