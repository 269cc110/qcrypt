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

#undef HANDLER

#endif /* QCRYPT_H_ */
