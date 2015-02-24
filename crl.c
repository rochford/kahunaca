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

#include <string.h>
#include <sqlite3.h>

#include "crl.h"
#include "sqlite.h"

X509_REVOKED *
makeRevoked(sqlite3 *db, BIO *err, const char *serialNumber, const char* timestamp)
{
    revoke_cert(db, timestamp, serialNumber);

    X509_REVOKED *r = X509_REVOKED_new();
    BIGNUM *bn = NULL;
    ASN1_ENUMERATED *rtmp = NULL;

    if (!r)
    {
        BIO_printf(err, "Unable to create an "
                   "X509_REVOKED object");
        return NULL;
    }

    if (BN_hex2bn(&bn, serialNumber))
    {
        ASN1_INTEGER *ser = BN_to_ASN1_INTEGER(bn, NULL);
        if (ser)
        {
            X509_REVOKED_set_serialNumber(r, ser);
            ASN1_INTEGER_free(ser);
        }
        BN_free(bn);
    }
    else
    {
        BIO_printf(err, "makeRevoked: Unable to parse"
                   " serial number");
        goto out;
    }

    ASN1_TIME *tm = NULL;

    tm = ASN1_UTCTIME_new();
    if (!tm)
    {
        BIO_printf(err, "Unable to create an ASN1_UTCTIME object");
    }
    //X509_gmtime_adj(tm,0);
    ASN1_UTCTIME_set_string(tm, timestamp);
    if (!X509_REVOKED_set_revocationDate(r, tm))
    {
        BIO_printf(err, "makeRevoked: Unable to "
                   "set revocation date");
        goto out;
    }

    ASN1_TIME_free(tm);

    return r;
out:
    if (tm)
        ASN1_TIME_free(tm);
    if (rtmp)
        ASN1_ENUMERATED_free(rtmp);
    if (bn)
        BN_free(bn);
    if (r)
        X509_REVOKED_free(r);
    return NULL;
}

int
crlSign(BIO *err, EVP_PKEY *cakey, X509_CRL *crl)
{
    int rv = 0;
    const EVP_MD *digest = EVP_sha1();

    if (X509_CRL_sign(crl, cakey, digest) != 0)
        rv = 1;
    else
        BIO_printf(err, "Unable to sign the CRL "
                   "using the supplied key");
    return rv;
}

void
crlToDatabase(sqlite3 *db,
              BIO* err,
              char *errorMsg,
              X509_CRL *crl)
{
    ASN1_INTEGER *crlnum;
    crlnum = X509_CRL_get_ext_d2i(crl, NID_crl_number,
                      NULL, NULL);

    char* buff = crlWriteToText(err, crl);
    insert_crl(db, errorMsg, "42", buff);
    if (crlnum)
    {
        ASN1_INTEGER_free(crlnum);
    }
    free(buff);
}

char*
crlWriteToText(BIO *err, X509_CRL *crl)
{
    BUF_MEM *bptr;

    if (!crl)
    {
        BIO_printf(err, "No CRL object to write!");
        return;
    }

    BIO *out = BIO_new(BIO_s_mem());
    if (!out)
    {
        BIO_printf(err, "Unable to create a BIO");
        BIO_free_all(out);
        return;
    }
    PEM_write_bio_X509_CRL(out, crl);

    BIO_get_mem_ptr(out, &bptr);

    char *buff = (char *)malloc(bptr->length);
    memcpy(buff, bptr->data, bptr->length-1);
    buff[bptr->length-1] = 0;

    BIO_free_all(out);
// client to call this    free(buff);
    return buff;
}

void
crlWriteToFile(BIO *err, X509_CRL *crl, char *fn)
{
    if (!crl || !fn)
    {
        if (!crl)
            BIO_printf(err, "No CRL object to write!");
        else
            BIO_printf(err, "No filename supplied!");
        return;
    }

    BIO *out = BIO_new(BIO_s_file());
    if (!out)
    {
        BIO_printf(err, "Unable to create a BIO");
        return;
    }

    if (BIO_write_filename(out, fn) == 1)
    {
        if ((PEM_write_bio_X509_CRL(out, crl)) == 0)
            BIO_printf(err, "Unable to write the CRL");
    }

    BIO_free_all(out);
}

void add_revoked_certs(sqlite3 *db, BIO *err, char* zErrMsg, X509_CRL* crl)
{
    // get a list of serial_numbers
    sqlite3_stmt *stmt = get_revoked(db, zErrMsg);

    int rc = sqlite3_step(stmt);
    while(rc == SQLITE_ROW)
    {
        char* serial = NULL;
        char* timestamp = NULL;

        get_revoked_item(stmt, &serial, &timestamp);
        printf("add_revoked_certs serial:%s, timestamp:%s\n", serial, timestamp);
        X509_REVOKED* rev = makeRevoked(db,err,serial, timestamp);
        if (rev)
        {
            X509_CRL_add0_revoked(crl, rev);
        }
        rc = sqlite3_step(stmt);
    }
    sqlite3_finalize(stmt);
}

X509_CRL *
createCRL(BIO *err, X509 *cert, EVP_PKEY *cakey)
{
    X509_CRL *crl = NULL;
    ASN1_TIME *tm = NULL;

    if (!cert || !cakey)
    {
        BIO_printf(err, "createCRL requires both "
                   "an X509 cert pointer and an RSA key pointer");
        return NULL;
    }

    crl = X509_CRL_new();
    if (!crl) {
        BIO_printf(err, "Unable to create an X509_CRL object");
        return NULL;
    }
    if (!X509_CRL_set_version(crl, 1))
    {
        BIO_printf(err, "Unable to set CRL version!");
        goto out;
    }

    tm = ASN1_TIME_new();
    if (!tm)
    {
        BIO_printf(err, "Unable to create an ASN1_TIME object");
        goto out;
    }
    X509_gmtime_adj(tm, 0);
    X509_CRL_set_lastUpdate(crl, tm);

    ASN1_INTEGER *tmpser = ASN1_INTEGER_new();
    if (tmpser)
    {
        ASN1_INTEGER_set(tmpser, 1L);
        X509_CRL_add1_ext_i2d(crl, NID_crl_number, tmpser, 0, 0);
        ASN1_INTEGER_free(tmpser);
    }
    X509_gmtime_adj(tm, 60*60*24); // valid for 1 day
    X509_CRL_set_nextUpdate(crl, tm);

    if (!X509_CRL_set_issuer_name(crl, X509_get_subject_name(cert)))
    {
        BIO_printf(err, "Unable to set the issuer "
                   "name for the new CRL");
        goto out;
    }

    ASN1_TIME_free(tm);
    return crl;

out:
    if (tm)
        ASN1_TIME_free(tm);
    if (crl)
        X509_CRL_free(crl);
    return NULL;
}

