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

#include <time.h>

#include "utils.h"

BIGNUM getNextSerialNumber(sqlite3 *db)
{
    BIGNUM one;
    BN_init(&one);
    BN_one(&one);

    sqlite3_stmt *select_stmt = NULL;

    char* sql = "SELECT SERIAL_NUMBER FROM CERT_META_DATA;";
    int rc = sqlite3_prepare_v2(db, sql, -1, &select_stmt, NULL);

    BIGNUM *num = NULL;
    if (SQLITE_OK == rc)
    {
        int res = sqlite3_step(select_stmt);
        if (res == SQLITE_ROW) {
            char *serial = (char*)sqlite3_column_text(select_stmt, 0);
            res = sqlite3_step(select_stmt);
            serialNumberStringToBigNum(serial, &num);
            BN_add(num, num, &one);
            return *num;
        }
    }
    return one;
}

int serialNumberStringToBigNum(char* text, BIGNUM **result)
{
    int r = BN_dec2bn(result,text);
    return r;
}

char* serialNumberBigNumToString(BIGNUM serial)
{
    return BN_bn2dec(&serial);
}

void printBigNum(BIGNUM n)
{
    char * serialStr = BN_bn2dec(&n);
    OPENSSL_free(serialStr);
}

char* timeNow()
{
    time_t current_time;

    current_time = time(NULL);
    struct tm *gmt = gmtime(&current_time);

    char* c_time_string = (char*)malloc(15);
    strftime(c_time_string, 14, "%y%m%d%H%M%SZ",gmt);
    return c_time_string;
}
