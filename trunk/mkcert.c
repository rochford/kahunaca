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

#include "mkcert.h"
#include "sqlite.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define FORMAT_UNDEF    0
#define FORMAT_ASN1     1
#define FORMAT_TEXT     2
#define FORMAT_PEM      3
#define FORMAT_NETSCAPE 4
#define FORMAT_PKCS12   5

void create_cert(BIO* bio_err,
                 sqlite3 *db,
                 char *zErrMsg,
                 BIGNUM ser,
                 const char* cname,
                 BIO *caRootCertBIO,
                 X509 *cacert,
                 EVP_PKEY *cakey)
{
    // client cert & key
    X509 *x509=NULL;
    EVP_PKEY *pkey=NULL;

    // Root CA CERT
    X509 *rootCert=NULL;

    PKCS12 *p12 = NULL;
    STACK_OF(X509) *certs=NULL;

    rootCert = PEM_read_bio_X509(caRootCertBIO, NULL, 0, NULL);

    // output something
    // RSA_print_fp(stdout,cakey->pkey.rsa,0);
    // X509_print_fp(stdout,cacert);
    //    X509_print_fp(stdout,x509);

    // create pkcs#12 bundle.
    certs = sk_X509_new_null();
    sk_X509_push(certs, cacert);
    sk_X509_push(certs, rootCert);

    mkcert(bio_err, &x509, &pkey, cacert, &cakey,1024, &ser, cname, 365*10);

    char* issuer = X509_NAME_oneline(X509_get_subject_name(cacert), 0, 0);
    char* subj = X509_NAME_oneline(X509_get_subject_name(x509), 0, 0);
    char* serialStr = serialNumberBigNumToString(ser);

    sk_X509_push(certs, x509);
    p12 = PKCS12_create("test", "My Certificate", pkey, x509, certs, 0,0,0,0,0);
    if (!p12) {
        ERR_print_errors (bio_err);
        return;
    }

    BIO *in = BIO_new(BIO_s_mem());

    BIO* b64 = BIO_new(BIO_f_base64());
    in = BIO_push(b64, in);
    int err = i2d_PKCS12_bio(in, p12);
    BIO_flush(b64);

    // write it to file
//    pkcs12WriteToFile(bio_err, p12, cname);

    BUF_MEM *bptr;

    BIO_get_mem_ptr(b64, &bptr);

    char *buff = (char *)malloc( 8096 /* bptr->length */);
    memcpy(buff, bptr->data, bptr->length-1);
    buff[bptr->length-1] = 0;

    printf("PKCS #12 %d:\n", bptr->length);
    printf("%s\n",buff);

    insert_cert(db, zErrMsg, serialStr, subj, issuer, buff);

    update_serial(db, serialStr);

    free(buff);

    OPENSSL_free(subj);
    OPENSSL_free(issuer);

    PKCS12_free(p12);
    //    X509_free(x509);
    //    EVP_PKEY_free(pkey);
    BIO_free_all(b64);
}

EVP_PKEY *load_key(BIO *err,
                   const char *file,
                   int format,
                   const char *pass,
                   const char *key_descrip)
{
    BIO *key=NULL;
    EVP_PKEY *pkey=NULL;

    if (file == NULL)
    {
        BIO_printf(err,"no keyfile specified\n");
        goto end;
    }

    key=BIO_new(BIO_s_file());
    if (key == NULL)
    {
        ERR_print_errors(err);
        goto end;
    }
    if (file == NULL)
    {
        BIO_set_fp(key,stdin,BIO_NOCLOSE);
    }
    else
        if (BIO_read_filename(key,file) <= 0)
        {
            BIO_printf(err, "Error opening %s %s\n",
                       key_descrip, file);
            ERR_print_errors(err);
            goto end;
        }
    if (format == FORMAT_PEM)
    {
        pkey=PEM_read_bio_PrivateKey(key,NULL,
                                     NULL, NULL);
    }
    else
    {
        BIO_printf(err,"bad input format specified for key file\n");
        goto end;
    }
end:
    if (key != NULL) BIO_free(key);
    if (pkey == NULL)
    {
        BIO_printf(err,"unable to load %s\n", key_descrip);
        ERR_print_errors(err);
    }
    return(pkey);
}

X509 *load_cert(BIO *err,
                const char *file,
                int format,
                const char *cert_descrip)
{
    X509 *x=NULL;
    BIO *cert;

    if ((cert=BIO_new(BIO_s_file())) == NULL)
    {
        ERR_print_errors(err);
        goto end;
    }

    if (file == NULL)
    {
        BIO_set_fp(cert,stdin,BIO_NOCLOSE);
    }
    else
    {
        if (BIO_read_filename(cert,file) <= 0)
        {
            BIO_printf(err, "Error opening %s %s\n",
                       cert_descrip, file);
            ERR_print_errors(err);
            goto end;
        }
    }

    if 	(format == FORMAT_ASN1)
        x=d2i_X509_bio(cert,NULL);
    else if (format == FORMAT_PEM)
        x=PEM_read_bio_X509_AUX(cert,NULL, NULL, NULL);
    else	{
        BIO_printf(err,"bad input format specified for %s\n",
                   cert_descrip);
        goto end;
    }
end:
    if (x == NULL)
    {
        BIO_printf(err,"unable to load certificate\n");
        ERR_print_errors(err);
    }
    if (cert != NULL) BIO_free(cert);
    return(x);
}

int mkcert(BIO *bio,
           X509 **x509p,
           EVP_PKEY **pkeyp,
           X509 *cacert,
           EVP_PKEY **cakey,
           int bits,
           BIGNUM* serial,
           const char* cname,
           int days)
{
    X509 *x;
    EVP_PKEY *pk;
    RSA *rsa;
    X509_NAME *issuer_name=NULL;
    X509_NAME *name=NULL;

    if ((pkeyp == NULL) || (*pkeyp == NULL))
    {
        if ((pk=EVP_PKEY_new()) == NULL)
        {
            abort();
            return(0);
        }
    }
    else
        pk= *pkeyp;

    if ((x509p == NULL) || (*x509p == NULL))
    {
        if ((x=X509_new()) == NULL)
            goto err;
    }
    else
        x= *x509p;

    rsa=RSA_generate_key(bits,RSA_F4, NULL, NULL);
    if (!EVP_PKEY_assign_RSA(pk,rsa))
    {
        abort();
        goto err;
    }
    rsa=NULL;

    X509_set_version(x,2);
    BN_to_ASN1_INTEGER(serial,X509_get_serialNumber(x));
    // validity started 1 year in the past.
    X509_gmtime_adj(X509_get_notBefore(x),(long)60*60*24*365*-1);
    X509_gmtime_adj(X509_get_notAfter(x),(long)60*60*24*days);
    X509_set_pubkey(x,pk);

    issuer_name=X509_get_subject_name(cacert);
    X509_set_issuer_name(x,issuer_name);

    name=X509_get_subject_name(x);

    X509_NAME_add_entry_by_txt(name,"C",
                               MBSTRING_ASC, "UK", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name,"O",
                               MBSTRING_ASC, "ACME", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name,"OU",
                               MBSTRING_ASC, "CHEMICALS", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name,"CN",
                               MBSTRING_ASC, cname, -1, -1, 0);
    if (!X509_set_subject_name(x,name)) goto err;

    /* Add various extensions: standard extensions */
    add_ext(x, NID_basic_constraints, "critical,CA:FALSE");
    add_ext(x, NID_key_usage, "critical,digitalSignature,keyEncipherment");
    add_ext(x, NID_ext_key_usage, "critical,clientAuth");

    add_ext(x, NID_subject_key_identifier, "hash");

    if (!X509_sign(x,*cakey,EVP_md5()))
        goto err;

    *x509p=x;
    *pkeyp=pk;
    return(1);
err:
    return(0);
}

int add_ext(X509 *cert,
            int nid,
            char *value)
{
    X509_EXTENSION *ex;
    X509V3_CTX ctx;
    /* This sets the 'context' of the extensions. */
    /* No configuration database */
    X509V3_set_ctx_nodb(&ctx);
    /* subject certs only
     * no issuer, no request and no CRL
     */
    X509V3_set_ctx(&ctx, NULL, cert, NULL, NULL, 0);
    ex = X509V3_EXT_conf_nid(NULL, &ctx, nid, value);
    if (!ex)
        return 0;

    X509_add_ext(cert,ex,-1);
    X509_EXTENSION_free(ex);
    return 1;
}
/*
int pkey_ctrl_string(EVP_PKEY_CTX *ctx, char *value)
{
    int rv;
    char *stmp, *vtmp = NULL;
    stmp = BUF_strdup(value);
    if (!stmp)
        return -1;
    vtmp = strchr(stmp, ':');
    if (vtmp)
    {
        *vtmp = 0;
        vtmp++;
    }
    rv = EVP_PKEY_CTX_ctrl_str(ctx, stmp, vtmp);
    OPENSSL_free(stmp);
    return rv;
}
*/

void
pkcs12WriteToFile(BIO *err, PKCS12 *pkcs12, char *fn)
{
    BIO *out = NULL;

    if (!pkcs12 || !fn) {
        if (!pkcs12)
            BIO_printf(err, "No pkcs12 object to write!");
        else
            BIO_printf(err, "No filename supplied!");
        return;
    }

    out = BIO_new(BIO_s_file());
    if (!out) {
        BIO_printf(err, "Unable to create a BIO");
        return;
    }

    if (BIO_write_filename(out, fn) == 1) {
        if ((i2d_PKCS12_bio(out, pkcs12)) == 0)
            BIO_printf(err, "Unable to write the PKCS#!");
    }

    BIO_free_all(out);
}
