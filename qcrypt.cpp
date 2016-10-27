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

#include <iostream>
#include <string>
#include <cstring>
#include <vector>
#include <map>
#include <algorithm>

#include <sys/stat.h>
#include <unistd.h>

#include <cryptopp/cryptlib.h>

#include "qcrypt.h"

using std::cout;
using std::endl;
using std::cerr;
using std::cin;
using std::string;

std::map<string, qcrypt_handler *> *handlers;

const string default_algorithm = "aes-256-cbc";

bool file_exists(string &name)
{
	struct stat buffer;
	return !stat(name.c_str(), &buffer);
}

void to_lower(string &data)
{
	std::transform(data.begin(), data.end(), data.begin(), ::tolower);
}

void print_help(char *invname)
{
	cout << "qcrypt 0.2" << endl << endl;
	cout << invname << " [[-e | -d] | -h | -l | -i <infile> | -o <outfile> | -k <key> | -a <algorithm> | [-s | -v] | -t]..." << endl;
	cout << "\t-e - encryption mode" << endl;
	cout << "\t-d - decryption mode" << endl;
	cout << "\t-h - prints this help message and exits, if the only argument" << endl;
	cout << "\t-h - prints the licence and exits, if the only argument" << endl;
	cout << "\t-i - specifies input file" << endl;
	cout << "\t-o - specifies output file" << endl;
	cout << "\t-k - specifies decryption key (only valid with -d)" << endl;
	cout << "\t-a - specifies algorithm" << endl;

	cout << "\t\tsupported algorithms: ";

	bool first = true;
	string algorithm;

	for(auto &handler : *handlers)
	{
		algorithm = handler.first;

		if(!first) cout << ", ";

		cout << algorithm;

		if(algorithm == default_algorithm) cout << " (default)";

		first = false;
	}

	cout << endl;

	cout << "\t-s - silent operation (no stdout except generated key)" << endl;
	cout << "\t-v - verbose operation" << endl;
	cout << "\t-t - plaintext mode (output file for encryption, input file for decryption) [CURRENTLY UNSUPPORTED]" << endl;
	cout << "\t\tsupported modes: hex, base32, base64 (default)" << endl;
}

void print_licence()
{
	cout << "qcrypt - quick tool for encrypting and decrypting files" << endl << endl;
	cout << "Copyright (C) 2016 condorcraft110" << endl << endl;
	cout << "This program is free software: you can redistribute it and/or modify" << endl;
	cout << "it under the terms of the GNU General Public License as published by" << endl;
	cout << "the Free Software Foundation, either version 3 of the License, or" << endl;
	cout << "(at your option) any later version." << endl << endl;
	cout << "This program is distributed in the hope that it will be useful," << endl;
	cout << "but WITHOUT ANY WARRANTY; without even the implied warranty of" << endl;
	cout << "MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the" << endl;
	cout << "GNU General Public License for more details." << endl << endl;
	cout << "You should have received a copy of the GNU General Public License" << endl;
	cout << "along with this program.  If not, see <http://www.gnu.org/licenses/>." << endl;
}

int rmain(int argc, char *argv[], std::vector<string> supported_textmodes, std::map<string, qcrypt_handler *> handlers)
{
	char *arg;
	unsigned short args = 0;

	char *cinput = nullptr, *coutput = nullptr, *ckey = nullptr, *calgorithm = nullptr, *ctextmode = nullptr;

	for(int i = 1; i < argc; i++)
	{
		if((arg = argv[i])[0] != '-' || strlen(arg) != 2)
		{
			cerr << "invalid argument " << arg << endl;
			return -1;
		}

		if(i == 1)
		{
			if(!strcmp(arg, (char *)"-h"))
			{
				print_help(argv[0]);
				return 0;
			}
			else if(!strcmp(arg, (char *)"-l"))
			{
				print_licence();
				return 0;
			}
		}

		switch(arg[1])
		{
			case 'e':
				if(args & 2)
				{
					cerr << "-e and -d are mutually exclusive" << endl;
					return -1;
				}

				if(args & 1)
				{
					cerr << "duplicate argument -e" << endl;
					return -1;
				}

				args |= 1;

				break;

			case 'd':
				if(args & 1)
				{
					cerr << "-e and -d are mutually exclusive" << endl;
					return -1;
				}

				if(args & 2)
				{
					cerr << "duplicate argument -d" << endl;
					return -1;
				}

				args |= 2;

				break;

			case 'i':
				if(args & 4)
				{
					cerr << "duplicate argument -i" << endl;
					return -1;
				}

				if(++i == argc)
				{
					cerr << "no input specified with -i" << endl;
					return -1;
				}

				cinput = argv[i];

				if(strlen(cinput) == 0 || cinput[0] == '-')
				{
					cerr << "no input specified with -i" << endl;
					return -1;
				}

				args |= 4;

				break;

			case 'o':
				if(args & 8)
				{
					cerr << "duplicate argument -o" << endl;
					return -1;
				}

				if(++i == argc)
				{
					cerr << "no output specified with -o" << endl;
					return -1;
				}

				coutput = argv[i];

				if(strlen(coutput) == 0 || coutput[0] == '-')
				{
					cerr << "no output specified with -o" << endl;
					return -1;
				}

				args |= 8;

				break;

			case 'k':
				if(args & 16)
				{
					cerr << "duplicate argument -k" << endl;
					return -1;
				}

				if(++i == argc)
				{
					cerr << "no key specified with -k" << endl;
					return -1;
				}

				ckey = argv[i];

				if(strlen(ckey) == 0 || ckey[0] == '-')
				{
					cerr << "no key specified with -k" << endl;
					return -1;
				}

				args |= 16;

				break;

			case 'a':
				if(args & 32)
				{
					cerr << "duplicate argument -a" << endl;
					return -1;
				}

				if(++i == argc)
				{
					cerr << "no algorithm specified with -a" << endl;
					return -1;
				}

				calgorithm = argv[i];

				if(strlen(calgorithm) == 0 || calgorithm[0] == '-')
				{
					cerr << "no algorithm specified with -a" << endl;
					return -1;
				}

				{
					string talgorithm = string(calgorithm);
					to_lower(talgorithm);

					if(handlers.find(talgorithm) == handlers.end())
					{
						cerr << "unsupported algorithm " << calgorithm << endl;
						return -2;
					}
				}

				args |= 32;

				break;

			case 's':
				if(args & 64)
				{
					cerr << "duplicate argument -s" << endl;
					return -1;
				}

				if(args & 128)
				{
					cerr << "-s and -v are mutually exclusive" << endl;
					return -1;
				}

				args |= 64;

				break;

			case 'v':
				if(args & 128)
				{
					cerr << "duplicate argument -v" << endl;
					return -1;
				}

				if(args & 64)
				{
					cerr << "-s and -v are mutually exclusive" << endl;
					return -1;
				}

				args |= 128;

				break;

			case 't':
				cerr << "textmode is currently unsupported" << endl;
				return 1;

				if(args & 256)
				{
					cerr << "duplicate argument -t" << endl;
					return -1;
				}

				if(++i == argc || strlen(ctextmode = argv[i]) == 0 || ctextmode[0] == '-')
				{
					ctextmode = (char *)"base64";
				}

				if(std::find(supported_textmodes.begin(), supported_textmodes.end(), string(ctextmode)) == supported_textmodes.end())
				{
					cerr << "unsupported text mode " << ctextmode << endl;
					return -3;
				}

				args |= 256;

				break;

			default:
				cerr << "invalid argument " << arg << endl;
				return -1;
		}
	}

	if(!(args & 1) && !(args & 2))
	{
		if(args & 128) cout << "direction not specified, assuming encryption" << endl;

		args |= 1;
	}

	if((args & 1) && (args & 16))
	{
		cerr << "-k can only be specified with -d" << endl;

		return -5;
	}

	//cout << (int)args << endl;

	bool iknl = args & 128;

	string input, output, key, algorithm, textmode;

#define SETSTR(a, b) { \
	if(!c##b) \
	{ \
		if(args & 128) cout << a << " not specified" << endl; \
		cout << a << ": "; \
		getline(cin, b); \
		iknl = true; \
	} \
	else \
	{ \
		b = string(c##b); \
		memset(c##b, 0, strlen(c##b)); \
		c##b = nullptr; \
	} \
}

	SETSTR("input file", input)

	/*while(!file_exists(input))
	{
		cerr << "file not found" << endl;
		cout << "input file: ";
		getline(cin, input);
		iknl = true;
	}*/

	if(!file_exists(input))
	{
		cerr << "failed to open file" << endl;
		return -8;
	}

	SETSTR("output file", output)

	if(args & 2) SETSTR("key", key)

#undef SETSTR

	if(!calgorithm) algorithm = "aes-256-cbc";
	else
	{
		algorithm = string(calgorithm);
		memset(calgorithm, 0, strlen(calgorithm));
		calgorithm = nullptr;
		to_lower(algorithm);
	}

	if(ctextmode)
	{
		textmode = string(ctextmode);
		memset(ctextmode, 0, strlen(ctextmode));
		ctextmode = nullptr;
		to_lower(textmode);
	}

	int errcode = 1;

	try
	{
		errcode = handlers[algorithm]->process(args, input, output, key, textmode, iknl);
	}
	catch(CryptoPP::Exception &e)
	{
		cerr << e.what() << endl;
		errcode = -4;
	}

	return errcode;
}

int main(int argc, char *argv[])
{
	handlers = new std::map<string, qcrypt_handler *>;

#define HANDLER(al, kl, mode) (*handlers)[string(#al) + "-" + string(#kl) + "-" + string(#mode)] = new qcrypt_##al##_##kl##_##mode;

	HANDLER(aes, 256, cbc)
	HANDLER(aes, 192, cbc)
	HANDLER(aes, 128, cbc)

	HANDLER(blowfish, 256, cbc)

	HANDLER(twofish, 256, cbc)
	HANDLER(twofish, 192, cbc)
	HANDLER(twofish, 128, cbc)

	HANDLER(serpent, 256, cbc)
	HANDLER(serpent, 192, cbc)
	HANDLER(serpent, 128, cbc)

#undef HANDLER

	if(argc < 2)
	{
		print_help(argv[0]);

		for(auto &p : *handlers)
		{
			delete p.second;
		}

		delete handlers;

		return 0;
	}

	std::vector<string> supported_textmodes;

	supported_textmodes.push_back("hex");
	supported_textmodes.push_back("base32");
	supported_textmodes.push_back("base64");

	int errcode = rmain(argc, argv, supported_textmodes, *handlers);

	for(auto &p : *handlers)
	{
		delete p.second;
	}

	delete handlers;

	return errcode;
}
