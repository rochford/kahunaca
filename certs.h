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

#ifndef CERTS_H
#define CERTS_H

const char* rootCaCert =
"-----BEGIN CERTIFICATE-----\n" \
"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\n" \
"-----END CERTIFICATE-----\n";

const char* myCaCert =
"-----BEGIN CERTIFICATE-----\n" \
"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\n" \
"Ju2GmDAh0+GKQe8sZmI1bg==\n" \
"-----END CERTIFICATE-----\n";

const char* myCaKey =
"-----BEGIN RSA PRIVATE KEY-----\n" \
"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\n" \
"-----END RSA PRIVATE KEY-----\n";

#endif // CERTS_H
