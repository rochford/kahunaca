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

#include <openssl/bn.h>

#include "mkcert.h"
#include "crl.h"
#include "sqlite.h"
#include "utils.h"
#include "certs.h"

int main(int argc, char **argv)
{
    int usage = 0;
    sqlite3 *db;
    char *zErrMsg = 0;

    int rc = sqlite3_open("test.db", &db);

    create_tables(db, zErrMsg);
    BIGNUM ser = getNextSerialNumber(db);

    SSLeay_add_all_algorithms();
    ERR_load_crypto_strings();
    CRYPTO_mem_ctrl(CRYPTO_MEM_CHECK_ON);

    BIO *bio_err = BIO_new_fp(stdout, BIO_NOCLOSE);

    if (argc != 2) {
        BIO_printf(bio_err, "usage: ./kahuna_ca common_name\n");
        BIO_printf(bio_err, "usage: ./kahuna_ca (revoke) serial\n");
        BIO_printf(bio_err, "usage: ./kahuna_ca crl\n");

        BIO_free(bio_err);
        return(0);
    }

    BIO *caRootCertBIO = BIO_new_mem_buf((void*)rootCaCert, -1);
    BIO *cacertBIO = BIO_new_mem_buf((void*)myCaCert, -1);
    BIO *cakeyBIO = BIO_new_mem_buf((void*)myCaKey, -1);

    const char* cname = "";
    if (atoi(argv[1]) > 0)
        usage = 1;
    else if (0==strcmp(argv[1], "crl"))
    {
        usage = 2;
    }
    else
    {
        usage = 0;
        cname = argv[1];
    }

    // CA cert & key
    EVP_PKEY *cakey=NULL;
    X509 *cacert=NULL;
    cakey=PEM_read_bio_PrivateKey(cakeyBIO,NULL, NULL, NULL);
    cacert = PEM_read_bio_X509(cacertBIO, NULL, 0, NULL);

    switch(usage)
    {
    case 0: // create cert
        create_cert(bio_err, db, zErrMsg, ser, cname, caRootCertBIO, cacert, cakey);
        break;
    case 1: // revoke
    {
        char* c_time_string = timeNow();

        X509_REVOKED* rev = makeRevoked(db,bio_err,argv[1], c_time_string);
        free(c_time_string);
        if (rev)
            X509_REVOKED_free(rev);
    }
        break;
    case 2: // crl
    {
        X509_CRL* crl = createCRL(bio_err, cacert, cakey);

        add_revoked_certs(db, bio_err, zErrMsg, crl);

        /* Now sort the CRL */
        X509_CRL_sort(crl);

        /* Sign it! */
        crlSign(bio_err, cakey, crl);

//        crlWriteToText(bio_err, crl);
        crlWriteToFile(bio_err, crl, "crl.crl");
        crlToDatabase(db,
                      bio_err,
                      zErrMsg,
                      crl);


        X509_CRL_free(crl);
    }
        break;
    }

clean_up:
    X509_free(cacert);
    EVP_PKEY_free(cakey);

    BIO_free_all(cakeyBIO);
    BIO_free_all(cacertBIO);
    BIO_free_all(caRootCertBIO);
    CRYPTO_cleanup_all_ex_data();

    CRYPTO_mem_leaks(bio_err);
    BIO_free(bio_err);

    return(0);
}
