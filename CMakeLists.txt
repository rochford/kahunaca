#
# Copyright (c) 2014 Timothy Rochford
#
# This product includes software developed by the OpenSSL Project
# for use in the OpenSSL Toolkit (http://www.openssl.org/)
#
#    This file is part of Kahuna CA.
#
#    Kahuna CA is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Lesser General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    Kahuna CA is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Lesser General Public License for more details.
#
#    You should have received a copy of the GNU Lesser General Public License
#    along with Kahuna CA.  If not, see <http://www.gnu.org/licenses/>.
#
cmake_minimum_required (VERSION 2.6)
project (kahuna_ca)

set(libs
     crypto sqlite3
)

add_executable(kahuna_ca mkcert.c crl.c utils.c certs.h sqlconstants.h sqlite.c main.c)
target_link_libraries(kahuna_ca ${libs})
