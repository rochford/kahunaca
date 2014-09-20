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

#ifndef CRL_H
#define CRL_H

#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/bn.h>

#include <sqlite3.h>

void
crlWriteToFile(BIO *err, X509_CRL *crl, char *fn);

char*
crlWriteToText(BIO *err, X509_CRL *crl);

X509_REVOKED *
makeRevoked(sqlite3* db,
            BIO* err,
            char* serialNumber,
            char* timestamp);

X509_CRL *
createCRL(BIO *err,
          X509* cert,
          EVP_PKEY* cakey);

int
crlSign(BIO *err, EVP_PKEY *cakey, X509_CRL *crl);

void
add_revoked_certs(sqlite3 *db,
                  BIO *err,
                  char* zErrMsg,
                  X509_CRL* crl);
void
crlToDatabase(sqlite3 *db,
              BIO* err,
              char *errorMsg,
              X509_CRL *crl);

#endif // CRL_H
