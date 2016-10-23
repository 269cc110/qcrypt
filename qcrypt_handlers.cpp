#include <string>
#include <fstream>
#include <string>

#include <cryptopp/modes.h>
#include <cryptopp/files.h>
#include <cryptopp/cryptlib.h>
#include <cryptopp/filters.h>
#include <cryptopp/osrng.h>
#include <cryptopp/secblock.h>
#include <cryptopp/rijndael.h>
#include <cryptopp/hex.h>
#include <cryptopp/base32.h>
#include <cryptopp/base64.h>

#include "qcrypt.h"

using namespace CryptoPP;

int qcrypt_aes_cbc(int args, string input, string output, string key, string textmode, bool iknl, int keylength)
{
	if(keylength != 256 && keylength != 192 && keylength != 128)
	{
		cerr << "invalid key length " << keylength << endl;

		return -6;
	}

	if(args & 128) cout << "textmode " << ((args & 256) ? ("on (" + textmode + ")") : "off") << endl;

	if(args & 1)
	{
		AutoSeededRandomPool prng;

		if(args & 128) cout << "generating key (" << keylength << " bit)" << endl;

		SecByteBlock key(keylength / 8);
		prng.GenerateBlock(key, key.size());

		if(args & 128)
		{
			cout << "block size " << (AES::BLOCKSIZE * 8) << " bit" << endl;
			cout << "generating IV" << endl;
		}

		byte iv[AES::BLOCKSIZE];
		prng.GenerateBlock(iv, sizeof(iv));

		/*string encoded_iv;
		ArraySource ivas(iv, AES::BLOCKSIZE, true, new Base64Encoder(new StringSink(encoded_iv)));
		cout << "IV: " << encoded_iv << endl;*/

		CBC_Mode<AES>::Encryption enc;
		enc.SetKeyWithIV(key, key.size(), iv);

		std::ofstream outs(output, std::fstream::binary);

		if(args & 256)
		{
			if(textmode == "hex")
			{
				HexEncoder *hencoder = new HexEncoder(new FileSink(outs));

				hencoder->Put(iv, AES::BLOCKSIZE);
				outs << '\n';

				FileSource fs(input.c_str(), true, new StreamTransformationFilter(enc, hencoder));
			}
			else if(textmode == "base32")
			{
				Base32Encoder *b32encoder = new Base32Encoder(new FileSink(outs));

				b32encoder->Put(iv, AES::BLOCKSIZE);
				outs << '\n';

				FileSource fs(input.c_str(), true, new StreamTransformationFilter(enc, b32encoder));
			}
			else if(textmode == "base64")
			{
				Base64Encoder *b64encoder = new Base64Encoder(new FileSink(outs), false);

				b64encoder->Put(iv, AES::BLOCKSIZE);
				outs << '\n';

				FileSource fs(input.c_str(), true, new StreamTransformationFilter(enc, b64encoder));
			}
		}
		else
		{
			outs.write((const char *)iv, AES::BLOCKSIZE);
			FileSource source(input.c_str(), true, new StreamTransformationFilter(enc, new FileSink(outs)));
		}

		outs.flush();
		outs.close();

		if(iknl) cout << endl;

		string encoded_key;
		ArraySource key_source(key, key.size(), true, new Base64Encoder(new StringSink(encoded_key)));

		cout << ((args & 64) ? "" : "key: ") << encoded_key << endl;
	}
	else
	{
		std::ifstream ins(input, std::fstream::binary);

		byte iv[AES::BLOCKSIZE];

		if(args & 128) cout << "reading IV" << endl;

		if(args & 256)
		{
			string siv;

			if(textmode == "hex")
			{
				std::getline(ins, siv);

				StringSource ivhsource(siv, true, new HexDecoder(new ArraySink(iv, AES::BLOCKSIZE)));
			}
			else if(textmode == "base32")
			{
				std::getline(ins, siv);

				StringSource ivb32source(siv, true, new Base32Decoder(new ArraySink(iv, AES::BLOCKSIZE)));
			}
			else if(textmode == "base64")
			{
				std::getline(ins, siv);

				StringSource ivb64source(siv, true, new Base64Decoder(new ArraySink(iv, AES::BLOCKSIZE)));
			}
		}
		else ins.read((char *)iv, AES::BLOCKSIZE);

		/*string encoded_iv;
		ArraySource ivas(iv, AES::BLOCKSIZE, true, new Base64Encoder(new StringSink(encoded_iv)));
		cout << "IV: " << encoded_iv << endl;*/

		/*char c;
		ins >> c;
		cout << c << endl;*/

		SecByteBlock decoded_key(keylength);
		StringSource key_source(key.c_str(), true, new Base64Decoder(new ArraySink(decoded_key, keylength)));

		CBC_Mode<AES>::Decryption dec;

		dec.SetKeyWithIV(decoded_key, keylength / 8, iv);

		StreamTransformationFilter *stf = new StreamTransformationFilter(dec, new FileSink(output.c_str()));

		if(args & 256)
		{
			if(textmode == "hex") FileSource fs(ins, true, new HexDecoder(stf));
			else if(textmode == "base32") FileSource fs(ins, true, new Base32Decoder(stf));
			else if(textmode == "base64") FileSource fs(ins, true, new Base64Decoder(stf));
		}
		else FileSource fs(ins, true, stf);

		ins.close();
	}

	if(!(args & 64)) cout << "written to " << output << endl;

	return 0;
}

int qcrypt_aes_256_cbc::process(int args, string input, string output, string key, string textmode, bool iknl)
{
	return qcrypt_aes_cbc(args, input, output, key, textmode, iknl, 256);
}

int qcrypt_aes_192_cbc::process(int args, string input, string output, string key, string textmode, bool iknl)
{
	return qcrypt_aes_cbc(args, input, output, key, textmode, iknl, 192);
}

int qcrypt_aes_128_cbc::process(int args, string input, string output, string key, string textmode, bool iknl)
{
	return qcrypt_aes_cbc(args, input, output, key, textmode, iknl, 128);
}
