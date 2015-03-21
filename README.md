
#Kahuna Certificate Authority
Aims

    Create and store a HTTPS client certificate
    Revoke a certificates
    Generate a CRL 

All data to be stored in a SQL database. Released under the LGPL license. 

This product includes software developed by the OpenSSL Project for use in the OpenSSL Toolkit. (http://www.openssl.org/)
Project uses CMake. Openssl libraries are linked against, so they need to be installed.

#Create A PKCS#12 bundle

$ ./kahuna_ca adam
On the command line supply the subject name. This name will be set as the subject name for the certificate. The private key, certificate some other certificates are then included into a PKCS#12 bundle that is Base64 encoded and stored in an SQLite database.

#Sample Firefox import

The PKCS#12 bundles can be imported to Firefox browser. Here are the steps:

./kahuna_ca charlie > charlie.pem

The standard output is piped to a file. Now convert the file to a PKCS#12 binary file like this:

base64 -d charlie.pem > charlie.p12

Now import the PKCS#12 bundle into Firefox. The PKCS#12 passphrase is 'test'. 

#Revocation

$ ./kahuna_ca <serial_number_to_revoke>
Certificates can be revoked by providing their serial number. The database is updated with the fact that the certificate is revoked. The CRL is generated next

$ ./kahuna_ca crl
The CRL data is stored in the SQL database. For testing purposes it is also written to a file crl.crl 

