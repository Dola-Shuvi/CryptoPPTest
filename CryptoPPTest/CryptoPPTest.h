#pragma once
typedef unsigned char byte;

vector<unsigned char> Encrypt(byte key[], byte iv[], vector<unsigned char> data);

vector<unsigned char> Decrypt(byte key[], byte iv[], vector<unsigned char> data);

byte* generateSHA256(string data);

vector<byte> zlibCompress(vector<byte> input);

vector<byte> zlibDecompress(vector<byte> input);

#ifdef USEZOPFLI
vector<byte> zopfliCompress(vector<byte> input);
#endif // USEZOPFLI

vector<unsigned char> readAllBytes(string fileName);
