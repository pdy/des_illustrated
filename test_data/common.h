/*

  MIT License

  Copyright (c) 2021 Pawel Drzycimski

  Permission is hereby granted, free of charge, to any person obtaining a copy
  of this software and associated documentation files (the "Software"), to deal
  in the Software without restriction, including without limitation the rights
  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
  copies of the Software, and to permit persons to whom the Software is
  furnished to do so, subject to the following conditions:

  The above copyright notice and this permission notice shall be included in all
  copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
  SOFTWARE.

*/

#ifndef PDY_DES_ILLUS_TEST_DATA_COMMON_H_
#define PDY_DES_ILLUS_TEST_DATA_COMMON_H_

#include <stdint.h>

const char *data_filename[] =
{
  "data_1.bin",
  "data_2.bin"
};

const char *key_filename[] =
{
  "hex_key_1.txt",
  "hex_key_2.txt"
};

const char *cipher_filename[] = 
{
  "cipher_1.bin",
  "cipher_2.bin"
};

const char *key[] =
{
  "133457799BBCDFF1",
  "0E329232EA6D0D73"
};

const unsigned char data[2][8] = 
{ 
  { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef },
  { 0x87, 0x87, 0x87, 0x87, 0x87, 0x87, 0x87, 0x87 }
};

const unsigned char cipher[2][8] = 
{ 
  { 0x85, 0xe8, 0x13, 0x54, 0x0f, 0x0a, 0xb4, 0x05 },
  { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
};

typedef struct lewinski_t
{
  const char *data_filename;
  const char *cipher_filename;
  const char *key_filename;

  const char *data_not_padded;
  const char *key_hex_str;
  uint8_t cipher[40];
}lewinski_t;

const static lewinski_t lewinski = {
  .data_filename = "lewinski_data.bin",
  .cipher_filename = "lewinski_cipher.bin",
  .key_filename = "lewinski_key.txt",
  
  .data_not_padded = "Your lips are smoother than vaseline\r\n",
  .key_hex_str  = "0E329232EA6D0D73",
  .cipher = {0xC0,0x99,0x9F,0xDD,0xE3,0x78,0xD7,0xED,0x72,0x7D,0xA0,0x0B,0xCA,0x5A,0x84,0xEE,0x47,0xF2,0x69,0xA4,0xD6,0x43,0x81,0x90,0x9D,0xD5,0x2F,0x78,0xF5,0x35,0x84,0x99,0x82,0x8A,0xC9,0xB4,0x53,0xE0,0xE6,0x53}
};

#endif

