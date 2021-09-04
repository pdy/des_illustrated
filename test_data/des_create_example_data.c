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
