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

int main(int argc, char **argv)
{
  if(argc < 2)
  {
    printf("Path to the binary required in first position\n");
    return 0;
  }

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

  const char *des_bin_path = argv[1];
  const char *tmp_bin_file_path = "./tmp_file.bin";

  for(size_t i = 0; i < 2; ++i)
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
  
    FILE *tmp_bin_file = fopen(tmp_bin_file_path, "w");
    if(!tmp_bin_file)
    {
      printf("%s: %s\n", "Can't open the tmp bin file", cipher_filename[i]);
      fclose(data_file);
      fclose(key_file);
      fclose(cipher_file);
      return 0;
    }
     
    fclose(data_file);
    fclose(key_file);
    fclose(cipher_file);
    fclose(tmp_bin_file);
  }
   
  return 0;
}