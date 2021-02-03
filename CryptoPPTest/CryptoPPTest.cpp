#include <iostream>
#include <string>
#include <iomanip>
#include <random>
#include <numeric>
using namespace std;

#include "cryptlib.h"
#include "filters.h"
#include "files.h"
#include "modes.h"
#include "queue.h"
#include "aes.h"
#include "CryptoPPTest.h"
#include "sha.h"
#include "zlib.h"
using namespace CryptoPP;

#ifdef USEZOPFLI
#include "zopfli.h"
#endif // USEZOPFLI




int main(int argc, char* argv[])
{
	byte key[AES::MAX_KEYLENGTH];
	byte iv[AES::BLOCKSIZE];

	cout << to_string(chrono::system_clock::now().time_since_epoch().count()) << endl;

	memcpy(key, generateSHA256(argv[1]), sizeof(key));
	memcpy(iv, key, sizeof(iv));

	vector<unsigned int> noise = generateNoise(generateSHA256("Harambe"), 8, 128);
	std::copy(noise.begin(), noise.end(), std::ostream_iterator<unsigned int>(std::cout, " "));
	cout << endl;

	//vector<unsigned char> plain = { 65, 116, 116, 97, 99, 107, 32, 97, 116, 32, 100, 97, 119, 110, 33, 65, 116, 116, 97, 99, 107, 32, 97, 116, 32, 100, 97, 119, 110, 33, 65, 116, 116, 97, 99, 107, 32, 97, 116, 32, 100, 97, 119, 110, 33 };
	
	vector<unsigned char> plain = readAllBytes("lorem.txt");

	//std::copy(plain.begin(), plain.end(), std::ostream_iterator<char>(std::cout, ""));
	cout << plain.size() << endl;
	cout << endl;

#ifdef USEZOPFLI
	vector<byte> compressed = zopfliCompress(plain);
#else
	vector<byte> compressed = zlibCompress(plain);
#endif	

	//std::copy(compressed.begin(), compressed.end(), std::ostream_iterator<char>(std::cout, ""));
	cout << compressed.size() << endl;
	cout << endl;

	/////////////////////////////////////////////////////////////
	vector<unsigned char> encrypted = Encrypt(key, iv, compressed);
	//std::copy(encrypted.begin(), encrypted.end(), std::ostream_iterator<char>(std::cout, ""));
	cout << encrypted.size() << endl;
	cout << endl;
	vector<unsigned char> decrypted = Decrypt(key, iv, encrypted);
	//std::copy(decrypted.begin(), decrypted.end(), std::ostream_iterator<char>(std::cout, ""));
	cout << decrypted.size() << endl;
	cout << endl;
	/////////////////////////////////////////////////////////////

	vector<byte> decompressed = zlibDecompress(compressed);

	//std::copy(decompressed.begin(), decompressed.end(), std::ostream_iterator<char>(std::cout, ""));
	cout << decompressed.size() << endl;
	cout << endl;

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

	(void)ArraySource(data.data(), data.size(), true,
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

	(void)ArraySource(data.data(), data.size(), true,
		new StreamTransformationFilter(dec, new Redirector(rs), StreamTransformationFilter::PKCS_PADDING));

	// Set recovered text length now that its known
	recover.resize(rs.TotalPutLength());

	return recover;
}

byte* generateSHA256(string data)
{
	byte const* pbData = (byte*)data.data();
	size_t nDataLen = data.size();
	byte* abDigest = new byte[SHA256::DIGESTSIZE];

	SHA256().CalculateDigest(abDigest, pbData, nDataLen);

	return abDigest;
}

vector<byte> zlibCompress(vector<byte> input) {
	ZlibCompressor zipper;
	zipper.Put((byte*)input.data(), input.size());
	zipper.MessageEnd();

	word64 avail = zipper.MaxRetrievable();
	if (avail)
	{
		vector<byte> compressed;
		compressed.resize(avail);

		zipper.Get(&compressed[0], compressed.size());
		return compressed;
	}
	exit(1);
}

vector<byte> zlibDecompress(vector<byte> input) {
	ZlibDecompressor zipper;
	zipper.Put((byte*)input.data(), input.size());
	zipper.MessageEnd();

	word64 avail = zipper.MaxRetrievable();
	vector<byte> decompressed;
	decompressed.resize(avail);

	zipper.Get(&decompressed[0], decompressed.size());

	return decompressed;
}

#ifdef USEZOPFLI
vector<byte> zopfliCompress(vector<byte> input) {
	ZopfliOptions options;
	ZopfliInitOptions(&options);

	if (input.size() > 10000000) {
		options.blocksplittingmax = 32;
		options.numiterations = 8;
	}
	else if(input.size() > 1000000) {
		options.blocksplittingmax = 32;
		options.numiterations = 16;
	}
	else {
		options.blocksplittingmax = 32;
		options.numiterations = 32;
	}

	

	size_t size = 0;
	unsigned char* temp;

	ZopfliCompress(&options, ZOPFLI_FORMAT_ZLIB, input.data(), input.size(), &temp, &size);

	vector<unsigned char> output(temp, temp + size);
	output.shrink_to_fit();

	return output;

}
#endif // USEZOPFLI;

vector<unsigned int> generateNoise(byte* seedPointer, unsigned int dataLength, unsigned int imageLength) {
	byte seed[SHA256::DIGESTSIZE];
	memcpy(seed, seedPointer, sizeof(seed));
	
	seed_seq seed2(begin(seed), end(seed));
	mt19937 g(seed2);

	vector<unsigned int> noise(imageLength);
	iota(begin(noise), end(noise), 0);

	unsigned int offset = 32;
	noise.erase(noise.begin(), noise.begin() + offset);

	shuffle(begin(noise), end(noise), g);

	noise.resize((size_t)((uint64_t)dataLength * 8U));

	return noise;
}

vector<unsigned char> readAllBytes(string fileName) {
	//Open file
	ifstream infile(fileName, ios::in | ios::binary);
	vector<unsigned char> buffer;

	//Get length of file
	infile.seekg(0, infile.end);
	size_t length = infile.tellg();
	infile.seekg(0, infile.beg);

	//Read file
	if (length > 0) {
		buffer.resize(length);
		infile.read((char*)& buffer[0], length);
	}

	//Close instream
	infile.close();

	return buffer;
}