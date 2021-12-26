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

#include "common.h"

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

  const char *des_bin_path = argv[1];
  const char *tmp_bin_file_path = "./tmp_file.bin";

  char encrypt_cmd[10240] = {0};
  char decrypt_cmd[10240] = {0};
  for(size_t i = 0; i < DES_TEST_CASES; ++i)
  { 
    sprintf(encrypt_cmd, "%s -e %s -k %s -o %s -q", argv[1], data_filename[i], key_filename[i], tmp_bin_file_path);
    sprintf(decrypt_cmd, "%s -d %s -k %s -o %s -q", argv[1], cipher_filename[i], key_filename[i], tmp_bin_file_path);
  
    char *file_content = NULL; 
    
    printf("\n\nEncrypt %s \n\n", encrypt_cmd);

    system(encrypt_cmd);

    const unsigned long encrypt_bytes_read = read_whole_file(tmp_bin_file_path, &file_content);
    if(!encrypt_bytes_read)
    {
      printf("Cant read from %s during ENCRYPT test\n", tmp_bin_file_path);
      return 0;
    } 

    const unsigned char *correct_encrypt_result = cipher[i];
    for(size_t j = 0; j < 8; ++j)
    {
      if(correct_encrypt_result[j] != (unsigned char)file_content[j])
      {
        printf("\n\n!!! ENCRYPTING FAILED !!!\n %s\n\n", data_filename[i]);
        remove_file(tmp_bin_file_path);
        return 0;
      }
    }

    free(file_content);

    printf("\n\nDecrypt %s \n\n", decrypt_cmd);
    
    system(decrypt_cmd);

    const unsigned long decrypt_bytes_read = read_whole_file(tmp_bin_file_path, &file_content);
    if(!decrypt_bytes_read)
    {
      printf("Cant read from %s during DECRYPT test\n", tmp_bin_file_path);
      return 0;
    } 

    const unsigned char *correct_decrypt_result = data[i];
    for(size_t j = 0; j < 8; ++j)
    {
      if(correct_decrypt_result[j] != (unsigned char)file_content[j])
      {
        printf("\n\n!!! DECRYPTING FAILED !!!\n %s\n\n", cipher_filename[i]);
        remove_file(tmp_bin_file_path);
        return 0;
      }
    }

    free(file_content);

    memset(encrypt_cmd, 0x00, 10240);
    memset(decrypt_cmd, 0x00, 10240);
  }
 
  sprintf(encrypt_cmd, "%s -e %s -k %s -o %s -q", argv[1], lewinski.data_filename, lewinski.key_filename, tmp_bin_file_path);
  sprintf(decrypt_cmd, "%s -d %s -k %s -o %s -q", argv[1], lewinski.cipher_filename, lewinski.key_filename, tmp_bin_file_path);


  char *file_content = NULL; 
    
  printf("\n\nEncrypt %s \n\n", encrypt_cmd);

  system(encrypt_cmd);

  const unsigned long encrypt_bytes_read = read_whole_file(tmp_bin_file_path, &file_content);
  if(!encrypt_bytes_read)
  {
    printf("Cant read from %s during ENCRYPT test\n", tmp_bin_file_path);
    return 0;
  } 

  const unsigned char *correct_encrypt_result = lewinski.cipher;
  for(size_t j = 0; j < encrypt_bytes_read && j < sizeof(lewinski.cipher) / sizeof(lewinski.cipher[0]); ++j)
  {
    if(correct_encrypt_result[j] != (unsigned char)file_content[j])
    {
      printf("\n\n!!! ENCRYPTING FAILED !!!\n %s\n\n", lewinski.data_filename);
      //remove_file(tmp_bin_file_path);
      return 0;
    }
  }

  free(file_content);
  
  
  printf("\n\nDecrypt %s \n\n", decrypt_cmd);
    
  system(decrypt_cmd);

  const unsigned long decrypt_bytes_read = read_whole_file(tmp_bin_file_path, &file_content);
  if(!decrypt_bytes_read)
  {
    printf("Cant read from %s during DECRYPT test\n", tmp_bin_file_path);
    return 0;
  } 

  const unsigned char *correct_decrypt_result = lewinski.data_not_padded;
  for(size_t j = 0; j < decrypt_bytes_read && strlen(lewinski.data_not_padded); ++j)
  {
    if(correct_decrypt_result[j] != (unsigned char)file_content[j])
    {
      printf("\n\n!!! DECRYPTING FAILED !!!\n %s\n\n", lewinski.cipher_filename);
      remove_file(tmp_bin_file_path);
      return 0;
    }
  }

  free(file_content);
 
  remove_file(tmp_bin_file_path);

  return 0;
}
