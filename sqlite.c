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

#include <stdlib.h>
#include <string.h> // strlen
#include "sqlite.h"
#include "sqlconstants.h"

sqlite3_stmt * get_revoked(sqlite3 *db, char* errorMsg)
{
    sqlite3_stmt *stmt = NULL;

    int rc = sqlite3_prepare_v2(db, KCA_SQL_SELECT_REVOKED_CERTS, -1, &stmt, NULL);
    return rc == 0 ? stmt : NULL;
}

void get_revoked_item(sqlite3_stmt *stmt, char** serial, char** timestamp)
{
    *serial = (char *)sqlite3_column_text(stmt,0);
    *timestamp = (char *)sqlite3_column_text(stmt,1);
//    char* subject = (char *)sqlite3_column_text(stmt,1);
}

int create_tables(sqlite3 *db, char* errorMsg)
{
    int rc = sqlite3_exec(db, KCA_SQL_TABLES, NULL, 0, &errorMsg);
    return rc;
}

int update_serial(sqlite3 *db,
                  const char* serial)
{
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
                                KCA_SQL_UPDATE_SERIAL_NUMBER,
                                strlen(KCA_SQL_UPDATE_SERIAL_NUMBER),
                                &stmt,
                                NULL);
    if (SQLITE_OK == rc)
    {
        sqlite3_bind_text(stmt,1,serial,strlen(serial),NULL);
        sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
    return rc;
}

int update_crl_number(sqlite3 *db,
                      char* errorMsg,
                      const char* crl_number)
{
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
                                KCA_SQL_UPDATE_CRL_NUMBER,
                                strlen(KCA_SQL_UPDATE_CRL_NUMBER),
                                &stmt,
                                NULL);
    if (SQLITE_OK == rc)
    {
        sqlite3_bind_text(stmt,1,crl_number,strlen(crl_number),NULL);
        sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
    return rc;
}

int insert_cert(sqlite3 *db,
                char* errorMsg,
                const char* serial,
                const char* subject,
                const char* issuer,
                const char* pkcs12)
{
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db, KCA_SQL_INSERT_CERT, strlen(KCA_SQL_INSERT_CERT), &stmt, NULL);
    if (SQLITE_OK == rc)
    {
        sqlite3_bind_text(stmt,1,serial,strlen(serial),NULL);
        sqlite3_bind_text(stmt,2,subject,strlen(subject),NULL);
        sqlite3_bind_text(stmt,3,issuer,strlen(issuer),NULL);
        sqlite3_bind_text(stmt,4,pkcs12,strlen(pkcs12),NULL);
        sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
    return rc;
}

int revoke_cert(sqlite3 *db,
                const char* timestamp,
                const char* serial)
{
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
                                KCA_SQL_REVOKE_CERT,
                                strlen(KCA_SQL_REVOKE_CERT),
                                &stmt,
                                NULL);
    if (SQLITE_OK == rc)
    {
        sqlite3_bind_text(stmt,1,timestamp,strlen(timestamp),NULL);
        sqlite3_bind_text(stmt,2,serial,strlen(serial),NULL);
        sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
    return rc;
}

int insert_crl(sqlite3 *db,
               char* errorMsg,
               const char* serial,
               const  char* data)
{
    sqlite3_stmt *stmt = NULL;
    int rc = sqlite3_prepare_v2(db,
                                KCA_SQL_INSERT_CRL,
                                strlen(KCA_SQL_INSERT_CRL),
                                &stmt,
                                NULL);
    if (SQLITE_OK == rc)
    {
        sqlite3_bind_text(stmt,1,serial,strlen(serial),NULL);
        sqlite3_bind_text(stmt,2,data,strlen(data),NULL);
        sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
    return rc;
}
