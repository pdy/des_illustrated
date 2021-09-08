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

#include <stdio.h>
#include <string.h>

int main(void)
{
  const char *data_filename[] =
  {
    "data_1.bin"
  };

  const char *key_filename[] =
  {
    "hex_key_1.txt"
  };

  const char *cipher_filename[] = 
  {
    "cipher_1.bin"
  };

  const char *key[] =
  {
    "133457799BBCDFF1"
  };
  
  const unsigned char data[1][8] = 
  { 
    { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef }
  };

  const unsigned char cipher[1][8] = 
  { 
    { 0x85, 0xe8, 0x13, 0x54, 0x0f, 0x0a, 0xb4, 0x05 }
  };


  for(size_t i = 0; i < 1; ++i)
  {
    FILE *data_file = fopen(data_filename[i], "wb");
    if(!data_file)
    {
      printf("%s: %s\n", "Can't open the data file", data_filename[i]);
      return 0;
    }

    FILE *key_file = fopen(key_filename[i], "w");
    if(!key_file)
    {
      printf("%s: %s\n", "Can't open the key file", key_filename[i]);
      fclose(data_file);
      return 0;
    }

    FILE *cipher_file = fopen(cipher_filename[i], "w");
    if(!cipher_file)
    {
      printf("%s: %s\n", "Can't open the cipher file", cipher_filename[i]);
      fclose(data_file);
      fclose(key_file);
      return 0;
    }

    fwrite(data[i], 1, sizeof(data[i]), data_file);
    fwrite(cipher[i], 1, sizeof(cipher[i]), cipher_file);
    fprintf(key_file, "%s\n", key[i]);

    fclose(data_file);
    fclose(key_file);
    fclose(cipher_file);
  }
   
  return 0;
}
