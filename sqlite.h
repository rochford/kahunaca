/*
* Copyright (c) 2014 Timothy Rochford
*
* This product includes software developed by the OpenSSL Project
* for use in the OpenSSL Toolkit (http://www.openssl.org/)
*/
/*    This file is part of Kahuna CA.

    Kahuna CA is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Kahuna CA is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with Kahuna CA.  If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef DATABASE_H
#define DATABASE_H

#include <sqlite3.h>

int
create_tables(sqlite3 *db, char* errorMsg);

int
insert_cert(sqlite3 *db,
            char* errorMsg,
            const char* serial,
            const char* subject,
            const char* issuer,
            const char* pkcs12);

int
revoke_cert(sqlite3 *db,
            const char* timestamp,
            const char* serial);

int
update_serial(sqlite3 *db, const char* serial);

int
update_crl_number(sqlite3 *db,
                  char* errorMsg,
                  const char* crl_number);

sqlite3_stmt*
get_revoked(sqlite3 *db, char* errorMsg);

void
get_revoked_item(sqlite3_stmt *stmt,
                 char** serial,
                 char** timestamp);

int
insert_crl(sqlite3 *db,
           char* errorMsg,
           const char* serial,
           const char* data);

#endif // DATABASE_H
