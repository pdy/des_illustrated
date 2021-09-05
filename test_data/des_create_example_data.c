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
  const char *data_filename = "data_single_block.bin";
  const char *key_filename = "hex_key.txt";
  const char *key = "133457799BBCDFF1";
  const unsigned char data[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };

  FILE *data_file = fopen(data_filename, "wb");
  if(!data_file)
  {
    printf("%s: %s\n", "Can't open the data file", data_filename);
    return 0;
  }

  FILE *key_file = fopen(key_filename, "w");
  if(!key_file)
  {
    printf("%s: %s\n", "Can't open the key file", key_filename);
    fclose(data_file);
    return 0;
  }

  fwrite(data, 1, sizeof(data), data_file);
  fprintf(key_file, "%s\n", key);

  fclose(data_file);
  fclose(key_file);
   
  return 0;
}
