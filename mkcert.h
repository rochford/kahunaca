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

#ifndef MKCERT_H
#define MKCERT_H

#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pkcs12.h>
#include <openssl/bn.h>

#include <sqlite3.h>

void
create_cert(BIO* bio_err,
            sqlite3 *db,
            char *zErrMsg,
            BIGNUM ser,
            const char* cname,
            BIO *caRootCertBIO,
            X509 *cacert,
            EVP_PKEY *cakey);

EVP_PKEY*
load_key(BIO *err,
         const char *file,
         int format,
         const char *pass,
         const char *key_descrip);

X509*
load_cert(BIO *err,
          const char *file,
          int format,
          const char *cert_descrip);

int
mkcert(BIO *bio,
       X509 **x509p,
       EVP_PKEY **pkeyp,
       X509 *cacert,
       EVP_PKEY **cakey,
       int bits,
       BIGNUM* serial,
       const char* cname,
       int days);

int
add_ext(X509 *cert, int nid, char *value);

void
pkcs12WriteToFile(BIO *err, PKCS12 *pkcs12, char *fn);

#endif // MKCERT_H
