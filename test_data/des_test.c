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
#include <stdlib.h>

#include <unistd.h>

static long get_file_size(FILE *file)
{
  fseek(file, 0, SEEK_END);
  const long ret = ftell(file);
  fseek(file, 0, SEEK_SET); 

  return ret;
}

static unsigned long read_whole_file(const char * const filename, char **ret)
{
  FILE *file = fopen(filename, "r");
  if(!file)
    return 0;

  const long file_size = get_file_size(file);
  *ret = (char*)malloc(sizeof(char) * (unsigned long)file_size);
  if(!ret)
    return 0;

  const unsigned long actual_size = fread(*ret, 1, (unsigned long)file_size, file);
  printf("%s read size %lu buff size %lu\n", filename, actual_size, file_size); 
  fclose(file);

//  ret = buffer;
  return actual_size;
}

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

  char encrypt_cmd[10240] = {0};
  char decrypt_cmd[10240] = {0};
  for(size_t i = 0; i < 2; ++i)
  { 
    sprintf(encrypt_cmd, "%s e %s %s %s", argv[1], key_filename[i], data_filename[i], tmp_bin_file_path);
    sprintf(decrypt_cmd, "%s d %s %s %s", argv[1], key_filename[i], tmp_bin_file_path, data_filename[i]);
  
    printf("\n\nEncrypt %s \n\n", encrypt_cmd);

    system(encrypt_cmd);

    char *file_content = NULL; 
    const unsigned long bytes_read = read_whole_file(tmp_bin_file_path, &file_content);
    if(!bytes_read)
    {
      printf("Cant read from %s", tmp_bin_file_path);
      return 0;
    } 

    const unsigned char *correct_encrypt_result = cipher[i];
    for(size_t j = 0; j < 8; ++j)
    {
      if(correct_encrypt_result[j] != (unsigned char)file_content[j])
      {
        printf("!!! ENCRYPTING FAILED !!!\n %s", data_filename[i]);
        unlink(tmp_bin_file_path);
        return 0;
      }
    }

    memset(encrypt_cmd, 0x00, 10240);
    memset(decrypt_cmd, 0x00, 10240);
  }
  
  unlink(tmp_bin_file_path);

  return 0;
}
