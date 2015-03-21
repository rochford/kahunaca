# Kahuna Certificate Authority #

### Aims ###
  1. Create and store a HTTPS client certificate
  1. Revoke a certificates
  1. Generate a CRL

All data to be stored in a SQL database.

This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit. (http://www.openssl.org/)

## Usage ##

### Compile ###
Project uses CMake. Openssl libraries are linked against, so they need to be installed.

### Create A PKCS#12 bundle ###
```
$ ./kahuna_ca adam
MIIXOgIBAzCCFwQGCSqGSIb3DQEHAaCCFvUEghbxMIIW7TCCE78GCSqGSIb3DQEH
...
LTAhMAkGBSsOAwIaBQAEFM6r1ZnB22uG0Hq7YOkWyBTYpHOeBAhzLJjHCDp62Q==
```

On the command line supply the subject name. This name will be set as the subject name for the certificate. The private key, certificate some other certificates are then included into a PKCS#12 bundle that is Base64 encoded and stored in an SQLite database.

```
$ sqlite3 test.db
SQLite version 3.7.9 2011-11-01 00:52:41
Enter ".help" for instructions
Enter SQL statements terminated with a ";"
sqlite> .schema
CREATE TABLE CERTIFICATES(   SERIAL_NUMBER     TEXT PRIMARY KEY NOT NULL,   SUBJECT           TEXT    NOT NULL,   ISSUER            TEXT    NOT NULL,   STATUS            INTEGER NOT NULL DEFAULT 1,   REVOKED_TIMESTAMP TEXT,   PKCS12            TEXT );
CREATE TABLE CERT_META_DATA(   SERIAL_NUMBER     TEXT NOT NULL,   CRL_NUMBER        TEXT NOT NULL);
CREATE TABLE CRL(   CRL_NUMBER     TEXT PRIMARY KEY,   DATA           TEXT);
sqlite> select * from cert_meta_data;
34|44
sqlite> select serial_number, subject from certificates;
34|/C=UK/O=ACME/OU=CHEMICALS/CN=adam
sqlite>
```

### Sample Firefox import ###
The PKCS#12 bundles can be imported to Firefox browser. Here are the steps:

`./kahuna_ca charlie > charlie.pem`

The standard output is piped to a file. Now convert the file to a PKCS#12 binary file like this:

`base64 -d charlie.pem > charlie.p12`

Now import the PKCS#12 bundle into Firefox. The PKCS#12 passphrase is 'test'.

### Revocation ###

`./kahuna_ca <serial_number_to_revoke>`

Certificates can be revoked by providing their serial number. The database is updated with the fact that the certificate is revoked. The CRL is generated next

`./kahuna_ca crl`

```
$ ./kahuna_ca 34
$ ./kahuna_ca crl
add_revoked_certs serial:34, timestamp:141117193255Z
```

The CRL data is stored in the SQL database. For testing purposes it is also written to a file crl.crl

```
$ openssl crl -noout -text -in crl.crl 
Certificate Revocation List (CRL):
        Version 2 (0x1)
    Signature Algorithm: sha1WithRSAEncryption
        Issuer: /C=UK/O=ACME/CN=TEST CA
        Last Update: Nov 17 19:33:00 2014 GMT
        Next Update: Nov 18 19:33:00 2014 GMT
        CRL extensions:
            X509v3 CRL Number: 
                1
Revoked Certificates:
    Serial Number: 34
        Revocation Date: Nov 17 19:32:55 2014 GMT
    Signature Algorithm: sha1WithRSAEncryption
         9b:2d:d1:75:dc:f9:b4:28:c0:e3:c8:51:4e:78:70:16:a6:88:
         d0:36:28:7e:f6:61:84:15:57:04:5a:a6:af:e4:75:b7:16:11:
         19:8b:df:37:ca:8e:14:7f:2a:94:46:75:33:4a:0b:91:b3:93:
         97:32:bd:29:c5:c0:5f:72:9a:d8:7e:a1:c6:5e:f4:5f:0e:71:
         6b:a2:93:16:5a:78:5a:72:60:24:cc:93:50:ed:31:a0:57:59:
         ad:30:7f:8a:85:69:a9:7e:d6:c3:7a:ff:81:67:c3:4e:91:9b:
         d9:4d:29:71:7d:ae:1a:65:11:b4:65:c6:8f:e1:40:3c:0c:3f:
         50:e9:03:7b:d5:8c:1a:3e:a2:c7:39:3b:2c:fe:2b:83:8a:05:
         81:52:2a:04:73:0b:56:5b:d3:4b:b7:e9:e1:f4:5a:8c:db:d7:
         44:68:ce:76:08:ba:4b:0f:8c:66:84:d0:4b:fe:49:02:58:1b:
         00:85:06:03:12:29:a0:4d:47:36:09:d6:bb:30:ff:93:a0:6b:
         0d:c1:a7:60:55:09:c0:eb:96:7a:89:81:e5:4e:79:ca:08:02:
         bb:48:e4:98:97:5f:26:d4:ed:31:5b:b6:02:99:ea:e7:92:aa:
         68:87:6b:9f:e3:4a:fd:23:d4:8d:c4:68:a1:84:ee:49:be:ce:
         e5:fe:ff:41:a6:45:bc:12:b5:d5:e4:a0:b3:44:d1:4b:8e:b3:
         05:74:22:4f:dc:1c:94:6c:e4:fb:8c:8b:90:d8:c0:b5:f7:43:
         db:f0:d6:20:20:c9:9d:09:4d:e3:e4:6c:6b:44:29:4a:a9:23:
         e7:80:e7:ca:e0:af:cf:28:b9:b2:55:c7:b8:bb:77:77:12:3a:
         88:90:3b:ce:d6:6d:9c:f6:55:ea:db:09:bf:e5:ed:be:92:e9:
         70:12:6b:6b:c0:6a:31:fc:b6:9a:19:d0:c2:dc:ed:bc:97:50:
         25:0f:5a:e7:b4:7f:e1:cd:4e:45:38:00:c3:8d:a8:58:2c:36:
         31:87:b3:59:9e:ce:74:9f:7f:c6:42:18:a8:bb:70:75:3c:da:
         62:74:a3:f5:ab:d6:eb:8d:06:88:0a:3e:93:9d:90:d6:a5:c6:
         f0:79:0b:64:8a:47:96:2e:5e:4d:00:6a:ce:fd:50:3a:55:63:
         95:d7:1b:7c:37:1d:8d:fb:0c:72:cf:2b:a9:dd:5e:1a:d3:dc:
         51:28:8f:1b:c1:21:69:6a:e0:3e:08:6c:fe:64:ac:ca:0a:45:
         12:1a:59:e6:a9:12:52:bb:30:e0:85:02:80:46:90:e7:ae:3f:
         15:34:4f:53:ca:58:d6:7c:cb:34:97:e6:69:d4:f9:44:1c:c7:
         64:ae:3c:24:4d:ff:d6:80
```
