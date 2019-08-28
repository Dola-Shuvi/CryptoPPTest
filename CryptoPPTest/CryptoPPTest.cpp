#include <iostream>
#include <string>
#include <iomanip>
using namespace std;

#include "cryptlib.h"
#include "filters.h"
#include "files.h"
#include "modes.h"
#include "queue.h"
#include "aes.h"
#include "CryptoPPTest.h"
#include "sha.h"
using namespace CryptoPP;

int main(int argc, char* argv[])
{
	byte key[AES::MAX_KEYLENGTH];
	byte iv[AES::BLOCKSIZE];


	memcpy(key, generateSHA256(argv[1]), sizeof(key));
	memcpy(iv, key, sizeof(iv));

	vector<unsigned char> plain = { 65, 116, 116, 97, 99, 107, 32, 97, 116, 32, 100, 97, 119, 110, 33 };

	std::copy(plain.begin(), plain.end(), std::ostream_iterator<char>(std::cout, ""));
	cout << endl;

	/////////////////////////////////////////////////////////////
	vector<unsigned char> encrypted = Encrypt(key, iv, plain);
	std::copy(encrypted.begin(), encrypted.end(), std::ostream_iterator<char>(std::cout, ""));
	cout << endl;
	vector<unsigned char> decrypted = Decrypt(key, iv, encrypted);
	std::copy(decrypted.begin(), decrypted.end(), std::ostream_iterator<char>(std::cout, ""));
	cout << endl;
	/////////////////////////////////////////////////////////////

	return 0;
}

vector<unsigned char> Encrypt(byte key[], byte iv[], vector<unsigned char> data) {

	byte keycopy[AES::MAX_KEYLENGTH];
	memcpy(keycopy, key, sizeof(keycopy));

	byte ivcopy[AES::BLOCKSIZE];
	memcpy(ivcopy, iv, sizeof(ivcopy));

	CBC_Mode<AES>::Encryption enc;
	enc.SetKeyWithIV(keycopy, sizeof(keycopy), ivcopy, sizeof(ivcopy));

	vector<unsigned char> cipher;

	// Make room for padding
	cipher.resize(data.size() + AES::BLOCKSIZE);
	ArraySink cs(&cipher[0], cipher.size());

	ArraySource(data.data(), data.size(), true,
		new StreamTransformationFilter(enc, new Redirector(cs), StreamTransformationFilter::PKCS_PADDING));

	// Set cipher text length now that its known
	cipher.resize(cs.TotalPutLength());

	return cipher;
}

vector<unsigned char> Decrypt(byte key[], byte iv[], vector<unsigned char> data) {

	byte keycopy[AES::MAX_KEYLENGTH];
	memcpy(keycopy, key, sizeof(keycopy));

	byte ivcopy[AES::BLOCKSIZE];
	memcpy(ivcopy, iv, sizeof(ivcopy));

	CBC_Mode<AES>::Decryption dec;
	dec.SetKeyWithIV(keycopy, sizeof(keycopy), ivcopy, sizeof(ivcopy));

	vector<unsigned char> recover;

	// Recovered text will be less than cipher text
	recover.resize(data.size());
	ArraySink rs(&recover[0], recover.size());

	ArraySource(data.data(), data.size(), true,
		new StreamTransformationFilter(dec, new Redirector(rs), StreamTransformationFilter::PKCS_PADDING));	

	// Set recovered text length now that its known
	recover.resize(rs.TotalPutLength());

	return recover;
}

byte* generateSHA256(string data)
{
	byte const* pbData = (byte*)data.data();
	unsigned int nDataLen = data.size();
	byte abDigest[SHA256::DIGESTSIZE];

	SHA256().CalculateDigest(abDigest, pbData, nDataLen);

	return abDigest;
}