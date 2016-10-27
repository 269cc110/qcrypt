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

#include <string>
#include <fstream>
#include <string>

#include "cryptopp/modes.h"
#include "cryptopp/files.h"
#include "cryptopp/cryptlib.h"
#include "cryptopp/filters.h"
#include "cryptopp/osrng.h"
#include "cryptopp/secblock.h"
#include "cryptopp/hex.h"
#include "cryptopp/base32.h"
#include "cryptopp/base64.h"

#include "cryptopp/rijndael.h"
#include "cryptopp/blowfish.h"
#include "cryptopp/twofish.h"
#include "cryptopp/serpent.h"
#include "cryptopp/mars.h"

#include "qcrypt.h"

using namespace CryptoPP;

#define CBC(a, b) int qcrypt_##b##_cbc(int args, string input, string output, string key, string textmode, bool iknl, int kl) \
{ \
	if(args & 128) cout << "textmode " << ((args & 256) ? ("on (" + textmode + ")") : "off") << endl; \
\
	if(args & 1) \
	{ \
		AutoSeededRandomPool prng; \
\
		if(args & 128) cout << "generating key (" << kl << " bit)" << endl; \
\
		SecByteBlock key(kl / 8); \
		prng.GenerateBlock(key, key.size()); \
\
		if(args & 128) \
		{ \
			cout << "block size " << (a::BLOCKSIZE * 8) << " bit" << endl; \
			cout << "generating IV" << endl; \
		} \
\
		byte iv[a::BLOCKSIZE]; \
		prng.GenerateBlock(iv, sizeof(iv)); \
\
		/*string encoded_iv; \
		ArraySource ivas(iv, a::BLOCKSIZE, true, new Base64Encoder(new StringSink(encoded_iv))); \
		cout << "IV: " << encoded_iv << endl;*/ \
\
		CBC_Mode<a>::Encryption enc; \
		enc.SetKeyWithIV(key, key.size(), iv); \
\
		std::ofstream outs(output, std::fstream::binary); \
\
		if(args & 256) \
		{ \
			if(textmode == "hex") \
			{ \
				HexEncoder *hencoder = new HexEncoder(new FileSink(outs)); \
\
				hencoder->Put(iv, a::BLOCKSIZE); \
				outs << '\n'; \
\
				FileSource fs(input.c_str(), true, new StreamTransformationFilter(enc, hencoder)); \
			} \
			else if(textmode == "base32") \
			{ \
				Base32Encoder *b32encoder = new Base32Encoder(new FileSink(outs)); \
\
				b32encoder->Put(iv, a::BLOCKSIZE); \
				outs << '\n'; \
\
				FileSource fs(input.c_str(), true, new StreamTransformationFilter(enc, b32encoder)); \
			} \
			else if(textmode == "base64") \
			{ \
				Base64Encoder *b64encoder = new Base64Encoder(new FileSink(outs), false); \
\
				b64encoder->Put(iv, a::BLOCKSIZE); \
				outs << '\n'; \
\
				FileSource fs(input.c_str(), true, new StreamTransformationFilter(enc, b64encoder)); \
			} \
		} \
		else \
		{ \
			outs.write((const char *)iv, a::BLOCKSIZE); \
			FileSource source(input.c_str(), true, new StreamTransformationFilter(enc, new FileSink(outs))); \
		} \
\
		outs.flush(); \
		outs.close(); \
\
		if(iknl) cout << endl; \
\
		string encoded_key; \
		ArraySource key_source(key, key.size(), true, new Base64Encoder(new StringSink(encoded_key))); \
\
		cout << ((args & 64) ? "" : "key: ") << encoded_key << endl; \
	} \
	else \
	{ \
		std::ifstream ins(input, std::fstream::binary); \
\
		byte iv[a::BLOCKSIZE]; \
\
		if(args & 128) cout << "reading IV" << endl; \
\
		if(args & 256) \
		{ \
			string siv; \
\
			if(textmode == "hex") \
			{ \
				std::getline(ins, siv); \
\
				StringSource ivhsource(siv, true, new HexDecoder(new ArraySink(iv, a::BLOCKSIZE))); \
			} \
			else if(textmode == "base32") \
			{ \
				std::getline(ins, siv); \
\
				StringSource ivb32source(siv, true, new Base32Decoder(new ArraySink(iv, a::BLOCKSIZE))); \
			} \
			else if(textmode == "base64") \
			{ \
				std::getline(ins, siv); \
\
				StringSource ivb64source(siv, true, new Base64Decoder(new ArraySink(iv, a::BLOCKSIZE))); \
			} \
		} \
		else ins.read((char *)iv, a::BLOCKSIZE); \
\
		/*string encoded_iv; \
		ArraySource ivas(iv, a::BLOCKSIZE, true, new Base64Encoder(new StringSink(encoded_iv))); \
		cout << "IV: " << encoded_iv << endl;*/ \
\
		/*char c; \
		ins >> c; \
		cout << c << endl;*/ \
\
		SecByteBlock decoded_key(kl); \
		StringSource key_source(key.c_str(), true, new Base64Decoder(new ArraySink(decoded_key, kl))); \
\
		CBC_Mode<a>::Decryption dec; \
\
		dec.SetKeyWithIV(decoded_key, kl / 8, iv); \
\
		StreamTransformationFilter *stf = new StreamTransformationFilter(dec, new FileSink(output.c_str())); \
\
		if(args & 256) \
		{ \
			if(textmode == "hex") FileSource fs(ins, true, new HexDecoder(stf)); \
			else if(textmode == "base32") FileSource fs(ins, true, new Base32Decoder(stf)); \
			else if(textmode == "base64") FileSource fs(ins, true, new Base64Decoder(stf)); \
		} \
		else FileSource fs(ins, true, stf); \
\
		ins.close(); \
	} \
\
	if(!(args & 64)) cout << "written to " << output << endl; \
\
	return 0; \
} \

#define OFB(a, b) int qcrypt_##b##_ofb(int args, string input, string output, string key, string textmode, bool iknl, int kl) \
{ \
	if(args & 128) cout << "textmode " << ((args & 256) ? ("on (" + textmode + ")") : "off") << endl; \
\
	if(args & 1) \
	{ \
		AutoSeededRandomPool prng; \
\
		if(args & 128) cout << "generating key (" << kl << " bit)" << endl; \
\
		SecByteBlock key(kl / 8); \
		prng.GenerateBlock(key, key.size()); \
\
		if(args & 128) \
		{ \
			cout << "block size " << (a::BLOCKSIZE * 8) << " bit" << endl; \
			cout << "generating IV" << endl; \
		} \
\
		byte iv[a::BLOCKSIZE]; \
		prng.GenerateBlock(iv, sizeof(iv)); \
\
		/*string encoded_iv; \
		ArraySource ivas(iv, a::BLOCKSIZE, true, new Base64Encoder(new StringSink(encoded_iv))); \
		cout << "IV: " << encoded_iv << endl;*/ \
\
		OFB_Mode<a>::Encryption enc; \
		enc.SetKeyWithIV(key, key.size(), iv); \
\
		std::ofstream outs(output, std::fstream::binary); \
\
		if(args & 256) \
		{ \
			if(textmode == "hex") \
			{ \
				HexEncoder *hencoder = new HexEncoder(new FileSink(outs)); \
\
				hencoder->Put(iv, a::BLOCKSIZE); \
				outs << '\n'; \
\
				FileSource fs(input.c_str(), true, new StreamTransformationFilter(enc, hencoder)); \
			} \
			else if(textmode == "base32") \
			{ \
				Base32Encoder *b32encoder = new Base32Encoder(new FileSink(outs)); \
\
				b32encoder->Put(iv, a::BLOCKSIZE); \
				outs << '\n'; \
\
				FileSource fs(input.c_str(), true, new StreamTransformationFilter(enc, b32encoder)); \
			} \
			else if(textmode == "base64") \
			{ \
				Base64Encoder *b64encoder = new Base64Encoder(new FileSink(outs), false); \
\
				b64encoder->Put(iv, a::BLOCKSIZE); \
				outs << '\n'; \
\
				FileSource fs(input.c_str(), true, new StreamTransformationFilter(enc, b64encoder)); \
			} \
		} \
		else \
		{ \
			outs.write((const char *)iv, a::BLOCKSIZE); \
			FileSource source(input.c_str(), true, new StreamTransformationFilter(enc, new FileSink(outs))); \
		} \
\
		outs.flush(); \
		outs.close(); \
\
		if(iknl) cout << endl; \
\
		string encoded_key; \
		ArraySource key_source(key, key.size(), true, new Base64Encoder(new StringSink(encoded_key))); \
\
		cout << ((args & 64) ? "" : "key: ") << encoded_key << endl; \
	} \
	else \
	{ \
		std::ifstream ins(input, std::fstream::binary); \
\
		byte iv[a::BLOCKSIZE]; \
\
		if(args & 128) cout << "reading IV" << endl; \
\
		if(args & 256) \
		{ \
			string siv; \
\
			if(textmode == "hex") \
			{ \
				std::getline(ins, siv); \
\
				StringSource ivhsource(siv, true, new HexDecoder(new ArraySink(iv, a::BLOCKSIZE))); \
			} \
			else if(textmode == "base32") \
			{ \
				std::getline(ins, siv); \
\
				StringSource ivb32source(siv, true, new Base32Decoder(new ArraySink(iv, a::BLOCKSIZE))); \
			} \
			else if(textmode == "base64") \
			{ \
				std::getline(ins, siv); \
\
				StringSource ivb64source(siv, true, new Base64Decoder(new ArraySink(iv, a::BLOCKSIZE))); \
			} \
		} \
		else ins.read((char *)iv, a::BLOCKSIZE); \
\
		/*string encoded_iv; \
		ArraySource ivas(iv, a::BLOCKSIZE, true, new Base64Encoder(new StringSink(encoded_iv))); \
		cout << "IV: " << encoded_iv << endl;*/ \
\
		/*char c; \
		ins >> c; \
		cout << c << endl;*/ \
\
		SecByteBlock decoded_key(kl); \
		StringSource key_source(key.c_str(), true, new Base64Decoder(new ArraySink(decoded_key, kl))); \
\
		OFB_Mode<a>::Decryption dec; \
\
		dec.SetKeyWithIV(decoded_key, kl / 8, iv); \
\
		StreamTransformationFilter *stf = new StreamTransformationFilter(dec, new FileSink(output.c_str())); \
\
		if(args & 256) \
		{ \
			if(textmode == "hex") FileSource fs(ins, true, new HexDecoder(stf)); \
			else if(textmode == "base32") FileSource fs(ins, true, new Base32Decoder(stf)); \
			else if(textmode == "base64") FileSource fs(ins, true, new Base64Decoder(stf)); \
		} \
		else FileSource fs(ins, true, stf); \
\
		ins.close(); \
	} \
\
	if(!(args & 64)) cout << "written to " << output << endl; \
\
	return 0; \
} \

CBC(AES, aes)

#define AES_CBC(kl) int qcrypt_aes_##kl##_cbc::process(int args, string input, string output, string key, string textmode, bool iknl) \
{ \
	if(kl != 256 && kl != 192 && kl != 128) \
	{ \
		cerr << "invalid key length " << kl << endl; \
		return -6; \
	} \
\
	return qcrypt_aes_cbc(args, input, output, key, textmode, iknl, kl); \
}

AES_CBC(256)
AES_CBC(192)
AES_CBC(128)

#undef AES_CBC

OFB(AES, aes)

#define AES_OFB(kl) int qcrypt_aes_##kl##_ofb::process(int args, string input, string output, string key, string textmode, bool iknl) \
{ \
	if(kl != 256 && kl != 192 && kl != 128) \
	{ \
		cerr << "invalid key length " << kl << endl; \
		return -6; \
	} \
\
	return qcrypt_aes_ofb(args, input, output, key, textmode, iknl, kl); \
}

AES_OFB(256)
AES_OFB(192)
AES_OFB(128)

#undef AES_OFB

CBC(Blowfish, blowfish)

#define BLOWFISH_CBC(kl) int qcrypt_blowfish_##kl##_cbc::process(int args, string input, string output, string key, string textmode, bool iknl) \
{ \
	if((kl % 8) || kl < 32 || kl > 448) \
	{ \
		cerr << "invalid key length " << kl << endl; \
		return -6; \
	} \
\
	return qcrypt_blowfish_cbc(args, input, output, key, textmode, iknl, kl); \
}

BLOWFISH_CBC(256)

#undef BLOWFISH_CBC

OFB(Blowfish, blowfish)

#define BLOWFISH_OFB(kl) int qcrypt_blowfish_##kl##_ofb::process(int args, string input, string output, string key, string textmode, bool iknl) \
{ \
	if((kl % 8) || kl < 32 || kl > 448) \
	{ \
		cerr << "invalid key length " << kl << endl; \
		return -6; \
	} \
\
	return qcrypt_blowfish_ofb(args, input, output, key, textmode, iknl, kl); \
}

BLOWFISH_OFB(256)

#undef BLOWFISH_OFB

CBC(Twofish, twofish)

#define TWOFISH_CBC(kl) int qcrypt_twofish_##kl##_cbc::process(int args, string input, string output, string key, string textmode, bool iknl) \
{ \
	if(kl != 256 && kl != 192 && kl != 128) \
	{ \
		cerr << "invalid key length " << kl << endl; \
		return -6; \
	} \
\
	return qcrypt_twofish_cbc(args, input, output, key, textmode, iknl, kl); \
}

TWOFISH_CBC(256)
TWOFISH_CBC(192)
TWOFISH_CBC(128)

#undef TWOFISH_CBC

CBC(Serpent, serpent)

#define SERPENT_CBC(kl) int qcrypt_serpent_##kl##_cbc::process(int args, string input, string output, string key, string textmode, bool iknl) \
{ \
	if(kl != 256 && kl != 192 && kl != 128) \
	{ \
		cerr << "invalid key length " << kl << endl; \
		return -6; \
	} \
\
	return qcrypt_serpent_cbc(args, input, output, key, textmode, iknl, kl); \
}

SERPENT_CBC(256)
SERPENT_CBC(192)
SERPENT_CBC(128)

#undef SERPENT_CBC

CBC(MARS, mars)

#define MARS_CBC(kl) int qcrypt_mars_##kl##_cbc::process(int args, string input, string output, string key, string textmode, bool iknl) \
{ \
	if(kl % 32 || kl < 128 || kl > 448) \
	{ \
		cerr << "invalid key length " << kl << endl; \
		return -6; \
	} \
\
	return qcrypt_mars_cbc(args, input, output, key, textmode, iknl, kl); \
}

MARS_CBC(256)
MARS_CBC(192)
MARS_CBC(128)

#undef MARS_CBC

#undef CBC
#undef OFB
