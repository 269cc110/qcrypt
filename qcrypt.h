/*
 *	qcrypt - quick tool for encrypting and decrypting files
 *	Copyright (C) 2016 condorcraft110
 *
 *	This program is free software: you can redistribute it and/or modify
 *	it under the terms of the GNU General Public License as published by
 *	the Free Software Foundation, either version 3 of the License, or
 *	(at your option) any later version.
 *
 *	This program is distributed in the hope that it will be useful,
 *	but WITHOUT ANY WARRANTY; without even the implied warranty of
 *	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *	GNU General Public License for more details.
 *
 *	You should have received a copy of the GNU General Public License
 *	along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef QCRYPT_H_
#define QCRYPT_H_

#include <string>

using std::cout;
using std::endl;
using std::cerr;
using std::cin;
using std::string;

bool file_exists(string &name);

void to_lower(string &data);

class qcrypt_handler
{
	public:
		virtual ~qcrypt_handler() {}
		virtual int process(int args, string input, string output, string key, string textmode, bool iknl) = 0;
};

#define HANDLER(a)class qcrypt_##a : public virtual qcrypt_handler \
{ \
	public: \
		~qcrypt_##a() {} \
		int process(int args, string input, string output, string textmode, string key, bool iknl); \
};

HANDLER(aes_256_cbc)
HANDLER(aes_192_cbc)
HANDLER(aes_128_cbc)

HANDLER(aes_256_ofb)
HANDLER(aes_192_ofb)
HANDLER(aes_128_ofb)

HANDLER(blowfish_256_cbc)

HANDLER(blowfish_256_ofb)

HANDLER(twofish_256_cbc)
HANDLER(twofish_192_cbc)
HANDLER(twofish_128_cbc)

HANDLER(twofish_256_ofb)
HANDLER(twofish_192_ofb)
HANDLER(twofish_128_ofb)

HANDLER(serpent_256_cbc)
HANDLER(serpent_192_cbc)
HANDLER(serpent_128_cbc)

HANDLER(serpent_256_ofb)
HANDLER(serpent_192_ofb)
HANDLER(serpent_128_ofb)

HANDLER(mars_256_cbc)
HANDLER(mars_192_cbc)
HANDLER(mars_128_cbc)

HANDLER(mars_256_ofb)
HANDLER(mars_192_ofb)
HANDLER(mars_128_ofb)

HANDLER(gost_256_ofb)

#undef HANDLER

#endif /* QCRYPT_H_ */
