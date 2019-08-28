#pragma once
typedef unsigned char byte;

vector<unsigned char> Encrypt(byte key[], byte iv[], vector<unsigned char> data);

vector<unsigned char> Decrypt(byte key[], byte iv[], vector<unsigned char> data);

byte* generateSHA256(string data);
