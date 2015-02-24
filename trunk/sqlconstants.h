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

#ifndef SQLCONSTANTS_H
#define SQLCONSTANTS_H

char *KCA_SQL_TABLES =
"CREATE TABLE IF NOT EXISTS CERT_META_DATA(" \
"   SERIAL_NUMBER     TEXT NOT NULL,"\
"   CRL_NUMBER        TEXT NOT NULL" \
");"\
""\
"CREATE TABLE IF NOT EXISTS CRL("  \
"   CRL_NUMBER     TEXT PRIMARY KEY," \
"   DATA           TEXT" \
");"\
""\
"CREATE TABLE IF NOT EXISTS CERTIFICATES("  \
"   SERIAL_NUMBER     TEXT PRIMARY KEY NOT NULL," \
"   SUBJECT           TEXT    NOT NULL," \
"   ISSUER            TEXT    NOT NULL," \
"   STATUS            INTEGER NOT NULL DEFAULT 1," \
"   REVOKED_TIMESTAMP TEXT," \
"   PKCS12            TEXT " \
");"\
"INSERT INTO CERT_META_DATA(SERIAL_NUMBER,CRL_NUMBER)" \
"SELECT '33', '44'" \
"WHERE NOT EXISTS(SELECT 1 FROM CERT_META_DATA);";

char* KCA_SQL_INSERT_CERT =
"INSERT INTO CERTIFICATES VALUES(?,?,?,1,0,?);";

char* KCA_SQL_REVOKE_CERT =
"UPDATE CERTIFICATES SET REVOKED_TIMESTAMP = ?, STATUS = 3 WHERE SERIAL_NUMBER = ?;";

char* KCA_SQL_UPDATE_SERIAL_NUMBER =
"UPDATE CERT_META_DATA SET SERIAL_NUMBER= ?;";

char* KCA_SQL_UPDATE_CRL_NUMBER =
"UPDATE CERT_META_DATA SET CRL_NUMBER= ?;";

char* KCA_SQL_SELECT_REVOKED_CERTS =
"SELECT SERIAl_NUMBER, REVOKED_TIMESTAMP from CERTIFICATES where STATUS = 3;";

char* KCA_SQL_INSERT_CRL =
"INSERT OR REPLACE INTO CRL VALUES(?,?);";

#endif // SQLCONSTANTS_H
