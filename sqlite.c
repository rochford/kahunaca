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
//#include <stdio.h>
#include "sqlite.h"
#include "sqlconstants.h"

sqlite3_stmt * get_revoked(sqlite3 *db, char* errorMsg)
{
    sqlite3_stmt *select_stmt = NULL;

    int rc = sqlite3_prepare_v2(db, KCA_SQL_SELECT_REVOKED_CERTS, -1, &select_stmt, NULL);
    return rc == 0 ? select_stmt : NULL;
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

int update_serial(sqlite3 *db, char* serial)
{
    sqlite3_stmt *select_stmt = NULL;
    char* output = sqlite3_mprintf(KCA_SQL_UPDATE_SERIAL_NUMBER, serial);

    int rc = sqlite3_prepare_v2(db, output, -1, &select_stmt, NULL);
    if (SQLITE_OK == rc)
    {
        sqlite3_step(select_stmt);
    }
    sqlite3_free(output);
    return rc;
}

int update_crl_number(sqlite3 *db, char* errorMsg, char* crl_number)
{
    sqlite3_stmt *select_stmt = NULL;
    char* output = sqlite3_mprintf(KCA_SQL_UPDATE_CRLNUMBER, crl_number);

    int rc = sqlite3_prepare_v2(db, output, -1, &select_stmt, NULL);
    if (SQLITE_OK == rc)
    {
        sqlite3_step(select_stmt);
    }
    sqlite3_free(output);
    return rc;
}

int setup_cert_meta_data(sqlite3 *db, char* errorMsg)
{
    char* output = sqlite3_mprintf(KCA_SQL_UPDATE_SERIAL_AND_CRL, '1', '1');
    int rc = sqlite3_exec(db, output, NULL, 0, &errorMsg);
    sqlite3_free(output);
    return rc;
}

int insert_cert(sqlite3 *db, char* errorMsg, char* serial, char* subject, char* issuer, char* pkcs12)
{
    char* output = sqlite3_mprintf(KCA_SQL_INSERT_CERT, serial, subject, issuer, pkcs12 );
    int rc = sqlite3_exec(db, output, NULL, 0, &errorMsg);
    sqlite3_free(output);
    return rc;
}

int revoke_cert(sqlite3 *db, char* timestamp, char* serial)
{
    sqlite3_stmt *select_stmt = NULL;
    char* output = sqlite3_mprintf(KCA_SQL_REVOKE_CERT, timestamp, serial);

    int rc = sqlite3_prepare_v2(db, output, -1, &select_stmt, NULL);
    if (SQLITE_OK == rc)
    {
        sqlite3_step(select_stmt);
    }
    sqlite3_free(output);
    return rc;
}

int insert_crl(sqlite3 *db, char* errorMsg, char* serial, char* data)
{
    char* output = sqlite3_mprintf(KCA_SQL_INSERT_CRL, serial, data);
    int rc = sqlite3_exec(db, output, NULL, 0, &errorMsg);
    sqlite3_free(output);
    return rc;
}
