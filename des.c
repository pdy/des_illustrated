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
#include <stdint.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>
#include <string.h>
#include <stdarg.h>

#define INPUT_FILES_LEN 256

#define KEY_SIZE 8 
#define KEY_PC1_SIZE 7
#define KEY_PC2_SIZE 6
#define KEY_HEXSTR_LEN (KEY_SIZE * 2)
#define KEY_ITER_SIZE KEY_PC2_SIZE
#define KEY_SUBKEYS_NUM 16

#define MSG_SINGLE_BLOCK_SIZE 8
#define MSG_IP_SIZE 8
#define MSG_LR_SIZE 4
#define MSG_E_BIT_SIZE 6
#define MSG_B_INDICES_SIZE 8
#define MSG_SBOX_ROW_SIZE 16
#define MSG_SBOX_SELECTION_SIZE 4
#define MSG_P_PERMUT_SIZE 4

#define LOG_KEY_DETAILS
// #define LOG_KEY_CD_DETAILS
#define LOG_MSG_DETAILS
//#define LOG_MSG_LR_DETAILS
//#define LOG_MSG_LR_INTERNAL_DETAILS

#define GET_BYTE_IDX(bit_idx) ((size_t)(bit_idx - 1) / 8)

int des_printf(const char *format, ...);
void print_bin_detail(const uint8_t * const buffer, size_t size, size_t bit_word_len, size_t skip_beg);
void print_bin_with_title(const char *title, const uint8_t * const buffer, size_t size, size_t bit_word_len, size_t skip_beg);
void print_bin_simple(const char *title, const uint8_t * const buffer, size_t size);
void print_bin_bits(const char *title, const uint8_t * const buffer, size_t size, size_t bit_word_len);
void print_bin_8bit(const char *title, const uint8_t * const buffer, size_t size);
void print_buffer(const char * const buffer, unsigned long size);
void print_as_hexstr(const uint8_t * const buffer, size_t size);
void print_as_hexstr_with_title(const char *title, const uint8_t * const buffer, size_t size);

enum operation
{
  encrypt = 0,
  decrypt
};

typedef struct key_rotation_t
{
  uint8_t *subkeys;
} key_rotation_t;

typedef struct key_subkey_t
{
  uint8_t *ptr;
  size_t size;
  size_t it;

} key_subkey_t;

static key_rotation_t init_key_rot()
{
  key_rotation_t ret;
  ret.subkeys = (uint8_t*)malloc(KEY_SUBKEYS_NUM * KEY_ITER_SIZE * sizeof *ret.subkeys);

  return ret;
}

static void free_key_rot(key_rotation_t key_rot)
{
  if(key_rot.subkeys)
    free(key_rot.subkeys);
}

static key_subkey_t key_get_subkey(key_rotation_t key_rot, size_t iteration)
{
  if(!iteration || iteration > KEY_SUBKEYS_NUM)
  {
    const key_subkey_t ret = { .ptr = NULL, .size = 0, .it = 0};
    return ret;
  }

  const key_subkey_t it = 
  {
    .ptr = key_rot.subkeys + ((iteration - 1) * KEY_ITER_SIZE),
    .size = KEY_ITER_SIZE,
    .it = iteration
  };

  return it;
}

static key_subkey_t key_get_subkey_reverse(key_rotation_t key_rot, size_t iteration)
{
  if(!iteration || iteration > KEY_SUBKEYS_NUM)
  {
    const key_subkey_t ret = { .ptr = NULL, .size = 0, .it = 0};
    return ret;
  }

  const size_t idx = (size_t)KEY_SUBKEYS_NUM - iteration;

  const key_subkey_t it = 
  {
    .ptr = key_rot.subkeys + (idx * KEY_ITER_SIZE),
    .size = KEY_ITER_SIZE,
    .it = idx + 1
  };

  return it;
}

typedef key_subkey_t(*key_get_iterator)(key_rotation_t, size_t);

static key_get_iterator key_get_iterator_function(enum operation op)
{
  if(op == encrypt)
    return key_get_subkey;
  else if(op == decrypt)
    return key_get_subkey_reverse;

  return NULL;
}

static int key_is_iterator_valid(key_subkey_t it)
{
  return it.ptr != NULL && it.size == KEY_ITER_SIZE;
}

static void key_add_iteration(key_rotation_t key_rot, size_t iteration, uint8_t *key_pc2)
{
  assert(iteration >= 1 && iteration <= KEY_SUBKEYS_NUM);

  memcpy(key_rot.subkeys + ((iteration - 1) * KEY_ITER_SIZE), key_pc2, KEY_ITER_SIZE);
}

static void key_rotation_print(const key_rotation_t key_rot)
{
  size_t idx = 1;
  key_subkey_t it = key_get_subkey(key_rot, idx);
  char title_str[10 + 1] = {0};
  for(; key_is_iterator_valid(it); ++idx, it = key_get_subkey(key_rot, idx))
  {
    des_printf(title_str, "K%lu = ", idx);
    print_bin_with_title(title_str, it.ptr, it.size, 6, 0);
    memset(title_str, 0x00, sizeof title_str);
  }
}

#define ARG_APP_ENCRYPT 0x80
#define ARG_APP_DECRYPT 0x40
#define ARG_APP_QUIET   0x20

typedef struct app_arg
{
  enum operation op;
  char key_file[INPUT_FILES_LEN];
  char data_file[INPUT_FILES_LEN];
  char output_file[INPUT_FILES_LEN];

  uint8_t prv_flags;
}app_arg;

static app_arg g_app_arg;

static app_arg arg_process(int argc, char **argv)
{
  app_arg ret = {
    .op = encrypt,
    .key_file = {0},
    .data_file = {0},
    .output_file = {0},
    
    .prv_flags = 0x00
  };

  for(int i = 0; i < argc; ++i)
  {
    const char *param = argv[i];
    if(strcmp(param, "-e") == 0)
    {
      ret.op = encrypt;
      ret.prv_flags |= ARG_APP_ENCRYPT;
    }
    else if(strcmp(param, "-d") == 0)
    {
      ret.op = decrypt;
      ret.prv_flags |= ARG_APP_DECRYPT;
    }
    else if(strcmp(param, "-k") == 0)
    {
      ++i;
      char *key_ptr = argv[i];
      for(int idx = 0; key_ptr && *key_ptr && i < INPUT_FILES_LEN; ++idx, ++key_ptr)
        ret.key_file[idx] = *key_ptr;
    }
    else if(strcmp(param, "-f") == 0)
    {
      ++i;
      char *file_ptr = argv[i];
      for(int idx = 0; file_ptr && *file_ptr && i < INPUT_FILES_LEN; ++idx, ++file_ptr)
        ret.data_file[idx] = *file_ptr;
    }
    else if(strcmp(param, "-o") == 0)
    {
      ++i;
      char *out_file_ptr = argv[i];
      for(int idx = 0; out_file_ptr && *out_file_ptr && i < INPUT_FILES_LEN; ++idx, ++out_file_ptr)
        ret.output_file[idx] = *out_file_ptr;
    }
    else if(strcmp(param, "-q") == 0)
    {
      ret.prv_flags |= ARG_APP_QUIET;
    }
  }

  return ret;
}

static int arg_valid(app_arg args)
{
  if(args.prv_flags & ARG_APP_ENCRYPT && args.prv_flags & ARG_APP_DECRYPT)
  {
    des_printf("-e (encrypt) and -d (decrypt) specified at the same time!\n\n");
    return 0;
  }

  if((!(args.prv_flags & ARG_APP_ENCRYPT)) && (!(args.prv_flags & ARG_APP_DECRYPT)))
  {
    des_printf("-e (encrypt) or -d (decrypt) needs to be specified!\n\n");
    return 0;
  }

  if(!*args.key_file)
  {
    des_printf("-k (key file) not specified!\n\n");
    return 0;
  } 

  if(!*args.data_file)
  {
    des_printf("-f (data file) not specified!\n\n");
    return 0;
  }

  return 1;
}

static void usage(void)
{
  des_printf("des_illustrated <-e or -d> -k<key file> -f<data file> [OPTIONS] \n\n");
  des_printf("\t-e encrypt\n");
  des_printf("\t-d decrypt\n");
  des_printf("\t-k key file in hex string format\n");
  des_printf("\t-f data file to encrypt/decrypt\n");
  des_printf("\t-o <optional> output file to save the result\n");
  des_printf("\t-q <optional> quiet mode - no logs\n");
}

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
  des_printf("%s read size %lu buff size %lu\n", filename, actual_size, file_size); 
  fclose(file);

//  ret = buffer;
  return actual_size;
}

static int is_hex_digit(char c)
{
  return (c >= '0' && c <='9') || ((c >= 'a' && c <='f') || (c >= 'A' && c <= 'F'));
}

static int is_valid_hex_str(const char * const buffer, size_t size)
{
  for(size_t i = 0; i < size; ++i)
    if(!is_hex_digit(buffer[i]))
        return 0;

  return 1;
}

static uint8_t hex_char_map(char chr)
{
  switch(chr)
  {
    case '0': return 0;
    case '1': return 1;
    case '2': return 2;
    case '3': return 3;
    case '4': return 4;
    case '5': return 5;
    case '6': return 6;
    case '7': return 7;
    case '8': return 8;
    case '9': return 9;
    case 'a': return 10;
    case 'A': return 10;
    case 'b': return 11;
    case 'B': return 11;
    case 'c': return 12;
    case 'C': return 12;
    case 'd': return 13;
    case 'D': return 13;
    case 'e': return 14;
    case 'E': return 14;
    case 'f': return 15;
    case 'F': return 15;
  }

  return 0;
}

static void hex_str_to_bytes(const char * const buffer, unsigned long size, uint8_t *ret)
{
  char byte[2] = {0};
  size_t half_byte_idx = 0;

  for(unsigned long i = 0; i < size; ++i)
  {
    byte[half_byte_idx] = buffer[i];
    if(half_byte_idx == 1)
    {
      half_byte_idx = 0;

      const uint8_t lsb = hex_char_map(byte[1]);
      const uint8_t msb = hex_char_map(byte[0]);

      *ret |= lsb;
      *ret |= ((msb << 4) & 0xf0);

      ++ret;
      continue;
    }

    half_byte_idx += 1;
  }
}

static void key_pc1(const uint8_t * const buffer, uint8_t *ret)
{
  /*
   *
     57   49    41   33    25    17    9
      1   58    50   42    34    26   18
     10    2    59   51    43    35   27
     19   11     3   60    52    44   36
     63   55    47   39    31    23   15
      7   62    54   46    38    30   22
     14    6    61   53    45    37   29
     21   13     5   28    20    12    4
   *
   */

  ret[0] |= buffer[GET_BYTE_IDX(57)]      & 0x80;
  ret[0] |= buffer[GET_BYTE_IDX(49)] >> 1 & 0x40;
  ret[0] |= buffer[GET_BYTE_IDX(41)] >> 2 & 0x20;
  ret[0] |= buffer[GET_BYTE_IDX(33)] >> 3 & 0x10;
  ret[0] |= buffer[GET_BYTE_IDX(25)] >> 4 & 0x08;
  ret[0] |= buffer[GET_BYTE_IDX(17)] >> 5 & 0x04;
  ret[0] |= buffer[GET_BYTE_IDX(9)]  >> 6 & 0x02;
 
  ret[0] |= buffer[GET_BYTE_IDX(1)]  >> 7 & 0x01;
  ret[1] |= buffer[GET_BYTE_IDX(58)] << 2 & 0x80;
  ret[1] |= buffer[GET_BYTE_IDX(50)]      & 0x40;
  ret[1] |= buffer[GET_BYTE_IDX(42)] >> 1 & 0x20;
  ret[1] |= buffer[GET_BYTE_IDX(34)] >> 2 & 0x10;
  ret[1] |= buffer[GET_BYTE_IDX(26)] >> 3 & 0x08;
  ret[1] |= buffer[GET_BYTE_IDX(18)] >> 4 & 0x04;

  ret[1] |= buffer[GET_BYTE_IDX(10)] >> 5 & 0x02;
  ret[1] |= buffer[GET_BYTE_IDX(2)]  >> 6 & 0x01;
  ret[2] |= buffer[GET_BYTE_IDX(59)] << 1 & 0x80;
  ret[2] |= buffer[GET_BYTE_IDX(51)] << 1 & 0x40;
  ret[2] |= buffer[GET_BYTE_IDX(43)]      & 0x20;
  ret[2] |= buffer[GET_BYTE_IDX(35)] >> 1 & 0x10;
  ret[2] |= buffer[GET_BYTE_IDX(27)] >> 2 & 0x08;

  ret[2] |= buffer[GET_BYTE_IDX(19)] >> 3 & 0x04;
  ret[2] |= buffer[GET_BYTE_IDX(11)] >> 4 & 0x02;
  ret[2] |= buffer[GET_BYTE_IDX(3)]  >> 5 & 0x01;
  ret[3] |= buffer[GET_BYTE_IDX(60)] << 3 & 0x80;
  ret[3] |= buffer[GET_BYTE_IDX(52)] << 2 & 0x40;
  ret[3] |= buffer[GET_BYTE_IDX(44)] << 1 & 0x20;
  ret[3] |= buffer[GET_BYTE_IDX(36)]      & 0x10;

  ret[3] |= buffer[GET_BYTE_IDX(63)] << 2 & 0x08;
  ret[3] |= buffer[GET_BYTE_IDX(55)] << 1 & 0x04;
  ret[3] |= buffer[GET_BYTE_IDX(47)]      & 0x02;
  ret[3] |= buffer[GET_BYTE_IDX(39)] >> 1 & 0x01;
  ret[4] |= buffer[GET_BYTE_IDX(31)] << 6 & 0x80;
  ret[4] |= buffer[GET_BYTE_IDX(23)] << 5 & 0x40;
  ret[4] |= buffer[GET_BYTE_IDX(15)] << 4 & 0x20;

  ret[4] |= buffer[GET_BYTE_IDX(7)]  << 3 & 0x10;
  ret[4] |= buffer[GET_BYTE_IDX(62)] << 1 & 0x08;
  ret[4] |= buffer[GET_BYTE_IDX(54)]      & 0x04;
  ret[4] |= buffer[GET_BYTE_IDX(46)] >> 1 & 0x02;
  ret[4] |= buffer[GET_BYTE_IDX(38)] >> 2 & 0x01;
  ret[5] |= buffer[GET_BYTE_IDX(30)] << 5 & 0x80;
  ret[5] |= buffer[GET_BYTE_IDX(22)] << 4 & 0x40;

  ret[5] |= buffer[GET_BYTE_IDX(14)] << 3 & 0x20;
  ret[5] |= buffer[GET_BYTE_IDX(6)]  << 2 & 0x10;
  ret[5] |= buffer[GET_BYTE_IDX(61)]      & 0x08;
  ret[5] |= buffer[GET_BYTE_IDX(53)] >> 1 & 0x04;
  ret[5] |= buffer[GET_BYTE_IDX(45)] >> 2 & 0x02;
  ret[5] |= buffer[GET_BYTE_IDX(37)] >> 3 & 0x01;
  ret[6] |= buffer[GET_BYTE_IDX(29)] << 4 & 0x80;

  ret[6] |= buffer[GET_BYTE_IDX(21)] << 3 & 0x40;
  ret[6] |= buffer[GET_BYTE_IDX(13)] << 2 & 0x20;
  ret[6] |= buffer[GET_BYTE_IDX(5)]  << 1 & 0x10;
  ret[6] |= buffer[GET_BYTE_IDX(28)] >> 1 & 0x08;
  ret[6] |= buffer[GET_BYTE_IDX(20)] >> 2 & 0x04;
  ret[6] |= buffer[GET_BYTE_IDX(12)] >> 3 & 0x02;
  ret[6] |= buffer[GET_BYTE_IDX(4)]  >> 4 & 0x01;
}

static void key_pc2(const uint8_t * const buffer, uint8_t *ret)
{
  /*
   *
      14    17   11    24     1    5
       3    28   15     6    21   10
      23    19   12     4    26    8
      16     7   27    20    13    2
      41    52   31    37    47   55
      30    40   51    45    33   48
      44    49   39    56    34   53
      46    42   50    36    29   32
   *
   */

  ret[0] |= buffer[GET_BYTE_IDX(14)] << 5 & 0x80;
  ret[0] |= buffer[GET_BYTE_IDX(17)] >> 1 & 0x40;
  ret[0] |= buffer[GET_BYTE_IDX(11)]      & 0x20;
  ret[0] |= buffer[GET_BYTE_IDX(24)] << 4 & 0x10;
  ret[0] |= buffer[GET_BYTE_IDX(1) ] >> 4 & 0x08;
  ret[0] |= buffer[GET_BYTE_IDX(5) ] >> 1 & 0x04;

  ret[0] |= buffer[GET_BYTE_IDX(3) ] >> 4 & 0x02;
  ret[0] |= buffer[GET_BYTE_IDX(28)] >> 4 & 0x01;
  ret[1] |= buffer[GET_BYTE_IDX(15)] << 6 & 0x80;
  ret[1] |= buffer[GET_BYTE_IDX(6 )] << 4 & 0x40;
  ret[1] |= buffer[GET_BYTE_IDX(21)] << 2 & 0x20;
  ret[1] |= buffer[GET_BYTE_IDX(10)] >> 2 & 0x10;

  ret[1] |= buffer[GET_BYTE_IDX(23)] << 2 & 0x08;
  ret[1] |= buffer[GET_BYTE_IDX(19)] >> 3 & 0x04;
  ret[1] |= buffer[GET_BYTE_IDX(12)] >> 3 & 0x02;
  ret[1] |= buffer[GET_BYTE_IDX(4 )] >> 4 & 0x01;
  ret[2] |= buffer[GET_BYTE_IDX(26)] << 1 & 0x80;
  ret[2] |= buffer[GET_BYTE_IDX(8 )] << 6 & 0x40;

  ret[2] |= buffer[GET_BYTE_IDX(16)] << 5 & 0x20;
  ret[2] |= buffer[GET_BYTE_IDX(7 )] << 3 & 0x10;
  ret[2] |= buffer[GET_BYTE_IDX(27)] >> 2 & 0x08;
  ret[2] |= buffer[GET_BYTE_IDX(20)] >> 2 & 0x04;
  ret[2] |= buffer[GET_BYTE_IDX(13)] >> 2 & 0x02;
  ret[2] |= buffer[GET_BYTE_IDX(2 )] >> 6 & 0x01;

  ret[3] |= buffer[GET_BYTE_IDX(41)]      & 0x80;
  ret[3] |= buffer[GET_BYTE_IDX(52)] << 2 & 0x40;
  ret[3] |= buffer[GET_BYTE_IDX(31)] << 4 & 0x20;
  ret[3] |= buffer[GET_BYTE_IDX(37)] << 1 & 0x10;
  ret[3] |= buffer[GET_BYTE_IDX(47)] << 2 & 0x08;
  ret[3] |= buffer[GET_BYTE_IDX(55)] << 1 & 0x04;
  
  ret[3] |= buffer[GET_BYTE_IDX(30)] >> 1 & 0x02;
  ret[3] |= buffer[GET_BYTE_IDX(40)]      & 0x01;
  ret[4] |= buffer[GET_BYTE_IDX(51)] << 2 & 0x80;
  ret[4] |= buffer[GET_BYTE_IDX(45)] << 3 & 0x40;
  ret[4] |= buffer[GET_BYTE_IDX(33)] >> 2 & 0x20;
  ret[4] |= buffer[GET_BYTE_IDX(48)] << 4 & 0x10;

  ret[4] |= buffer[GET_BYTE_IDX(44)] >> 1 & 0x08;
  ret[4] |= buffer[GET_BYTE_IDX(49)] >> 5 & 0x04;
  ret[4] |= buffer[GET_BYTE_IDX(39)]      & 0x02;
  ret[4] |= buffer[GET_BYTE_IDX(56)]      & 0x01;
  ret[5] |= buffer[GET_BYTE_IDX(34)] << 1 & 0x80;
  ret[5] |= buffer[GET_BYTE_IDX(53)] << 3 & 0x40;

  ret[5] |= buffer[GET_BYTE_IDX(46)] << 3 & 0x20;
  ret[5] |= buffer[GET_BYTE_IDX(42)] >> 2 & 0x10;
  ret[5] |= buffer[GET_BYTE_IDX(50)] >> 3 & 0x08;
  ret[5] |= buffer[GET_BYTE_IDX(36)] >> 2 & 0x04;
  ret[5] |= buffer[GET_BYTE_IDX(29)] >> 2 & 0x02;
  ret[5] |= buffer[GET_BYTE_IDX(32)]      & 0x01;
}

static void shift_left_cd_mv_bit(uint8_t *buffer, size_t size)
{
  /*
   *
   *  We're taking into account additional four bits a the begining of the sequence.
   *  First bit of the sequence is on the 0x08 position of the buffer[0];
   *
   *  Check comment in key_rotation function for more details.
   *
   */

  const uint8_t last_bit = buffer[0] >> 3 & 0x01;

  uint8_t add_bit  = 0x00;
  for(size_t i = size; i > 0; --i)
  {
    const size_t idx = i-1;
    const uint8_t org = buffer[idx];
    buffer[idx] = (uint8_t)(buffer[idx] << 1) | add_bit;

    if(org & 0x80)
      add_bit = 0x01;
    else
      add_bit = 0x00;
  }

  buffer[0] &= 0x0f; // zeroing first four bits
  buffer[size - 1] |= last_bit;
}

static key_rotation_t key_rotation(const uint8_t * const key_pc1_buffer)
{
  /*
   *
   *  Key PC1 has 56 bits - 7 bytes and we need to split it in half on 28 bits.
   *  We split it on two 4 bytes buffers where each one has
   *  zeroed first four bits in the first byte.
   *
   *  Shift function has to take into account additional bits.
   *
   */

  uint8_t c_i[4] = 
  {
    ((key_pc1_buffer[0] & 0xf0) >> 4),
    (uint8_t)((key_pc1_buffer[0] & 0x0f) << 4) | ((key_pc1_buffer[1] & 0xf0) >> 4),
    (uint8_t)((key_pc1_buffer[1] & 0x0f) << 4) | ((key_pc1_buffer[2] & 0xf0) >> 4),
    (uint8_t)((key_pc1_buffer[2] & 0x0f) << 4) | ((key_pc1_buffer[3] & 0xf0) >> 4)
  };

  uint8_t d_i[4] =
  {
    (key_pc1_buffer[3] & 0x0f ),
    key_pc1_buffer[4],
    key_pc1_buffer[5],
    key_pc1_buffer[6] 
  };

#ifdef LOG_KEY_CD_DETAILS
  print_bin_with_title("C0 = ", c_i, 4, 7, 4);
  print_bin_with_title("D0 = ", d_i, 4, 7, 4);
#endif

  key_rotation_t ret_subkeys = init_key_rot();
  if(!ret_subkeys.subkeys)
    return ret_subkeys;
 
  for(size_t i = 1; i <= 16; ++i)
  {
    if(i == 1 || i == 2 || i == 9 || i == 16)
    {
      // single shift
      shift_left_cd_mv_bit(c_i, 4);
      shift_left_cd_mv_bit(d_i, 4);

    }
    else
    {
      // double shift
      shift_left_cd_mv_bit(c_i, 4);
      shift_left_cd_mv_bit(c_i, 4);

      shift_left_cd_mv_bit(d_i, 4);
      shift_left_cd_mv_bit(d_i, 4);
    }

#ifdef LOG_KEY_CD_DETAILS
    char title_str[10 + 1] = {0};
    sdes_printf(title_str, "C%lu = ", i);
    print_bin_simple(title_str, c_i, 4);
    
    memset(title_str, 0x00, sizeof title_str);

    sdes_printf(title_str, "D%lu = ", i);
    print_bin_simple(title_str, d_i, 4);
#endif

    // CD is joined togheter without padding bits on first
    // four positions of Cn and Dn
    const uint8_t cd[7] =
    {
      (uint8_t)((c_i[0] & 0x0f) << 4 | (c_i[1] & 0xf0) >> 4),
      (uint8_t)((c_i[1] & 0x0f) << 4 | (c_i[2] & 0xf0) >> 4),
      (uint8_t)((c_i[2] & 0x0f) << 4 | (c_i[3] & 0xf0) >> 4),

      (uint8_t)((c_i[3] & 0x0f) << 4 | (d_i[0])),
      d_i[1],
      d_i[2],
      d_i[3]
    };

#ifdef LOG_KEY_CD_DETAILS
    print_bin_bits("CD = ", cd, 7, 7);
#endif

    uint8_t K_pc2[KEY_PC2_SIZE] = {0};
    key_pc2(cd, K_pc2);

#if 0
#ifdef LOG_KEY_DETAILS
    sdes_printf(title_str, "K%lu = ", i);
    print_bin_bits(title_str, K_pc2, KEY_PC2_SIZE, 6);
    memset(title_str, 0x00, sizeof title_str);
#endif
#endif
    key_add_iteration(ret_subkeys, i, K_pc2);
  } 

  return ret_subkeys; 
}

static void msg_ip(const uint8_t * const buffer, uint8_t *ret)
{
  /*
   *
    58    50   42    34    26   18    10    2
    60    52   44    36    28   20    12    4
    62    54   46    38    30   22    14    6
    64    56   48    40    32   24    16    8
    57    49   41    33    25   17     9    1
    59    51   43    35    27   19    11    3
    61    53   45    37    29   21    13    5
    63    55   47    39    31   23    15    7
   *
   */

  ret[0] |= buffer[GET_BYTE_IDX(58)] << 2 & 0x80;
  ret[0] |= buffer[GET_BYTE_IDX(50)]      & 0x40;
  ret[0] |= buffer[GET_BYTE_IDX(42)] >> 1 & 0x20;
  ret[0] |= buffer[GET_BYTE_IDX(34)] >> 2 & 0x10;
  ret[0] |= buffer[GET_BYTE_IDX(26)] >> 3 & 0x08;
  ret[0] |= buffer[GET_BYTE_IDX(18)] >> 4 & 0x04;
  ret[0] |= buffer[GET_BYTE_IDX(10)] >> 5 & 0x02;
  ret[0] |= buffer[GET_BYTE_IDX(2) ] >> 6 & 0x01;

  ret[1] |= buffer[GET_BYTE_IDX(60)] << 3 & 0x80;
  ret[1] |= buffer[GET_BYTE_IDX(52)] << 2 & 0x40;
  ret[1] |= buffer[GET_BYTE_IDX(44)] << 1 & 0x20;
  ret[1] |= buffer[GET_BYTE_IDX(36)]      & 0x10;
  ret[1] |= buffer[GET_BYTE_IDX(28)] >> 1 & 0x08;
  ret[1] |= buffer[GET_BYTE_IDX(20)] >> 2 & 0x04;
  ret[1] |= buffer[GET_BYTE_IDX(12)] >> 3 & 0x02;
  ret[1] |= buffer[GET_BYTE_IDX(4) ] >> 4 & 0x01;

  ret[2] |= buffer[GET_BYTE_IDX(62)] << 5 & 0x80;
  ret[2] |= buffer[GET_BYTE_IDX(54)] << 4 & 0x40;
  ret[2] |= buffer[GET_BYTE_IDX(46)] << 3 & 0x20;
  ret[2] |= buffer[GET_BYTE_IDX(38)] << 2 & 0x10;
  ret[2] |= buffer[GET_BYTE_IDX(30)] << 1 & 0x08;
  ret[2] |= buffer[GET_BYTE_IDX(22)]      & 0x04;
  ret[2] |= buffer[GET_BYTE_IDX(14)] >> 1 & 0x02;
  ret[2] |= buffer[GET_BYTE_IDX(6) ] >> 2 & 0x01;

  ret[3] |= buffer[GET_BYTE_IDX(64)] << 7 & 0x80;
  ret[3] |= buffer[GET_BYTE_IDX(56)] << 6 & 0x40;
  ret[3] |= buffer[GET_BYTE_IDX(48)] << 5 & 0x20;
  ret[3] |= buffer[GET_BYTE_IDX(40)] << 4 & 0x10;
  ret[3] |= buffer[GET_BYTE_IDX(32)] << 3 & 0x08;
  ret[3] |= buffer[GET_BYTE_IDX(24)] << 2 & 0x04;
  ret[3] |= buffer[GET_BYTE_IDX(16)] << 1 & 0x02;
  ret[3] |= buffer[GET_BYTE_IDX(8) ]      & 0x01;

  ret[4] |= buffer[GET_BYTE_IDX(57)]      & 0x80;
  ret[4] |= buffer[GET_BYTE_IDX(49)] >> 1 & 0x40;
  ret[4] |= buffer[GET_BYTE_IDX(41)] >> 2 & 0x20;
  ret[4] |= buffer[GET_BYTE_IDX(33)] >> 3 & 0x10;
  ret[4] |= buffer[GET_BYTE_IDX(25)] >> 4 & 0x08;
  ret[4] |= buffer[GET_BYTE_IDX(17)] >> 5 & 0x04;
  ret[4] |= buffer[GET_BYTE_IDX(9) ] >> 6 & 0x02;
  ret[4] |= buffer[GET_BYTE_IDX(1) ] >> 7 & 0x01;

  ret[5] |= buffer[GET_BYTE_IDX(59)] << 2 & 0x80;
  ret[5] |= buffer[GET_BYTE_IDX(51)] << 1 & 0x40;
  ret[5] |= buffer[GET_BYTE_IDX(43)]      & 0x20;
  ret[5] |= buffer[GET_BYTE_IDX(35)] >> 1 & 0x10;
  ret[5] |= buffer[GET_BYTE_IDX(27)] >> 2 & 0x08;
  ret[5] |= buffer[GET_BYTE_IDX(19)] >> 3 & 0x04;
  ret[5] |= buffer[GET_BYTE_IDX(11)] >> 4 & 0x02;
  ret[5] |= buffer[GET_BYTE_IDX(3) ] >> 5 & 0x01;
  
  ret[6] |= buffer[GET_BYTE_IDX(61)] << 4 & 0x80;
  ret[6] |= buffer[GET_BYTE_IDX(53)] << 3 & 0x40;
  ret[6] |= buffer[GET_BYTE_IDX(45)] << 2 & 0x20;
  ret[6] |= buffer[GET_BYTE_IDX(37)] << 1 & 0x10;
  ret[6] |= buffer[GET_BYTE_IDX(29)]      & 0x08;
  ret[6] |= buffer[GET_BYTE_IDX(21)] >> 1 & 0x04;
  ret[6] |= buffer[GET_BYTE_IDX(13)] >> 2 & 0x02;
  ret[6] |= buffer[GET_BYTE_IDX(5) ] >> 3 & 0x01;

  ret[7] |= buffer[GET_BYTE_IDX(63)] << 6 & 0x80;
  ret[7] |= buffer[GET_BYTE_IDX(55)] << 5 & 0x40;
  ret[7] |= buffer[GET_BYTE_IDX(47)] << 4 & 0x20;
  ret[7] |= buffer[GET_BYTE_IDX(39)] << 3 & 0x10;
  ret[7] |= buffer[GET_BYTE_IDX(31)] << 2 & 0x08;
  ret[7] |= buffer[GET_BYTE_IDX(23)] << 1 & 0x04;
  ret[7] |= buffer[GET_BYTE_IDX(15)]      & 0x02;
  ret[7] |= buffer[GET_BYTE_IDX(7) ] >> 1 & 0x01;
}

static void msg_ip_reverse(const uint8_t * const final_RL, uint8_t *msg_rev_IP)
{
  /*
   *
    40   8   48    16    56   24    64   32
    39   7   47    15    55   23    63   31
    38   6   46    14    54   22    62   30
    37   5   45    13    53   21    61   29
    36   4   44    12    52   20    60   28
    35   3   43    11    51   19    59   27
    34   2   42    10    50   18    58   26
    33   1   41     9    49   17    57   25
   *
   */

  msg_rev_IP[0] |= final_RL[GET_BYTE_IDX(40)] << 7 & 0x80;
  msg_rev_IP[1] |= final_RL[GET_BYTE_IDX(39)] << 6 & 0x80;
  msg_rev_IP[2] |= final_RL[GET_BYTE_IDX(38)] << 5 & 0x80;
  msg_rev_IP[3] |= final_RL[GET_BYTE_IDX(37)] << 4 & 0x80;
  msg_rev_IP[4] |= final_RL[GET_BYTE_IDX(36)] << 3 & 0x80;
  msg_rev_IP[5] |= final_RL[GET_BYTE_IDX(35)] << 2 & 0x80;
  msg_rev_IP[6] |= final_RL[GET_BYTE_IDX(34)] << 1 & 0x80;
  msg_rev_IP[7] |= final_RL[GET_BYTE_IDX(33)]      & 0x80;

  msg_rev_IP[0] |= final_RL[GET_BYTE_IDX(8) ] << 6 & 0x40;
  msg_rev_IP[1] |= final_RL[GET_BYTE_IDX(7) ] << 5 & 0x40;
  msg_rev_IP[2] |= final_RL[GET_BYTE_IDX(6) ] << 4 & 0x40;
  msg_rev_IP[3] |= final_RL[GET_BYTE_IDX(5) ] << 3 & 0x40;
  msg_rev_IP[4] |= final_RL[GET_BYTE_IDX(4) ] << 2 & 0x40;
  msg_rev_IP[5] |= final_RL[GET_BYTE_IDX(3) ] << 1 & 0x40;
  msg_rev_IP[6] |= final_RL[GET_BYTE_IDX(2) ]      & 0x40;
  msg_rev_IP[7] |= final_RL[GET_BYTE_IDX(1) ] >> 1 & 0x40;

  msg_rev_IP[0] |= final_RL[GET_BYTE_IDX(48)] << 5 & 0x20;
  msg_rev_IP[1] |= final_RL[GET_BYTE_IDX(47)] << 4 & 0x20;
  msg_rev_IP[2] |= final_RL[GET_BYTE_IDX(46)] << 3 & 0x20;
  msg_rev_IP[3] |= final_RL[GET_BYTE_IDX(45)] << 2 & 0x20;
  msg_rev_IP[4] |= final_RL[GET_BYTE_IDX(44)] << 1 & 0x20;
  msg_rev_IP[5] |= final_RL[GET_BYTE_IDX(43)]      & 0x20;
  msg_rev_IP[6] |= final_RL[GET_BYTE_IDX(42)] >> 1 & 0x20;
  msg_rev_IP[7] |= final_RL[GET_BYTE_IDX(41)] >> 2 & 0x20;

  msg_rev_IP[0] |= final_RL[GET_BYTE_IDX(16)] << 4 & 0x10;
  msg_rev_IP[1] |= final_RL[GET_BYTE_IDX(15)] << 3 & 0x10;
  msg_rev_IP[2] |= final_RL[GET_BYTE_IDX(14)] << 2 & 0x10;
  msg_rev_IP[3] |= final_RL[GET_BYTE_IDX(13)] << 1 & 0x10;
  msg_rev_IP[4] |= final_RL[GET_BYTE_IDX(12)]      & 0x10;
  msg_rev_IP[5] |= final_RL[GET_BYTE_IDX(13)] >> 1 & 0x10;
  msg_rev_IP[6] |= final_RL[GET_BYTE_IDX(12)] >> 2 & 0x10;
  msg_rev_IP[7] |= final_RL[GET_BYTE_IDX(11)] >> 3 & 0x10;

  msg_rev_IP[0] |= final_RL[GET_BYTE_IDX(56)] << 3 & 0x08;
  msg_rev_IP[1] |= final_RL[GET_BYTE_IDX(55)] << 2 & 0x08;
  msg_rev_IP[2] |= final_RL[GET_BYTE_IDX(54)] << 1 & 0x08;
  msg_rev_IP[3] |= final_RL[GET_BYTE_IDX(53)]      & 0x08;
  msg_rev_IP[4] |= final_RL[GET_BYTE_IDX(52)] >> 1 & 0x08;
  msg_rev_IP[5] |= final_RL[GET_BYTE_IDX(51)] >> 2 & 0x08;
  msg_rev_IP[6] |= final_RL[GET_BYTE_IDX(50)] >> 3 & 0x08;
  msg_rev_IP[7] |= final_RL[GET_BYTE_IDX(49)] >> 4 & 0x08;

  msg_rev_IP[0] |= final_RL[GET_BYTE_IDX(24)] << 2 & 0x04;
  msg_rev_IP[1] |= final_RL[GET_BYTE_IDX(23)] << 1 & 0x04;
  msg_rev_IP[2] |= final_RL[GET_BYTE_IDX(22)]      & 0x04;
  msg_rev_IP[3] |= final_RL[GET_BYTE_IDX(21)] >> 1 & 0x04;
  msg_rev_IP[4] |= final_RL[GET_BYTE_IDX(20)] >> 2 & 0x04;
  msg_rev_IP[5] |= final_RL[GET_BYTE_IDX(19)] >> 3 & 0x04;
  msg_rev_IP[6] |= final_RL[GET_BYTE_IDX(18)] >> 4 & 0x04;
  msg_rev_IP[7] |= final_RL[GET_BYTE_IDX(17)] >> 5 & 0x04;

  msg_rev_IP[0] |= final_RL[GET_BYTE_IDX(64)] << 1 & 0x02;
  msg_rev_IP[1] |= final_RL[GET_BYTE_IDX(63)]      & 0x02;
  msg_rev_IP[2] |= final_RL[GET_BYTE_IDX(62)] >> 1 & 0x02;
  msg_rev_IP[3] |= final_RL[GET_BYTE_IDX(61)] >> 2 & 0x02;
  msg_rev_IP[4] |= final_RL[GET_BYTE_IDX(60)] >> 3 & 0x02;
  msg_rev_IP[5] |= final_RL[GET_BYTE_IDX(59)] >> 4 & 0x02;
  msg_rev_IP[6] |= final_RL[GET_BYTE_IDX(58)] >> 5 & 0x02;
  msg_rev_IP[7] |= final_RL[GET_BYTE_IDX(57)] >> 6 & 0x02;

  msg_rev_IP[0] |= final_RL[GET_BYTE_IDX(32)]      & 0x01;
  msg_rev_IP[1] |= final_RL[GET_BYTE_IDX(31)] >> 1 & 0x01;
  msg_rev_IP[2] |= final_RL[GET_BYTE_IDX(30)] >> 2 & 0x01;
  msg_rev_IP[3] |= final_RL[GET_BYTE_IDX(29)] >> 3 & 0x01;
  msg_rev_IP[4] |= final_RL[GET_BYTE_IDX(28)] >> 4 & 0x01;
  msg_rev_IP[5] |= final_RL[GET_BYTE_IDX(27)] >> 5 & 0x01;
  msg_rev_IP[6] |= final_RL[GET_BYTE_IDX(26)] >> 6 & 0x01;
  msg_rev_IP[7] |= final_RL[GET_BYTE_IDX(25)] >> 7 & 0x01;
}

static void msg_get_LR(const uint8_t * const ipbuffer, uint8_t *retL, uint8_t *retR)
{
  memcpy(retL, ipbuffer, MSG_LR_SIZE);
  memcpy(retR, ipbuffer + MSG_LR_SIZE, MSG_LR_SIZE);
}

static void msg_copy_LR(const uint8_t * const from, uint8_t *to)
{
  memcpy(to, from, MSG_LR_SIZE);
}

static void msg_ebit_selection(const uint8_t * const R, uint8_t *ret)
{
  /*
    32     1    2     3     4    5
     4     5    6     7     8    9
     8     9   10    11    12   13
    12    13   14    15    16   17
    16    17   18    19    20   21
    20    21   22    23    24   25
    24    25   26    27    28   29
    28    29   30    31    32    1
  */
  
  ret[0] |= R[GET_BYTE_IDX(32)] << 7 & 0x80;
  ret[0] |= R[GET_BYTE_IDX(1) ] >> 1 & 0x40;
  ret[0] |= R[GET_BYTE_IDX(2) ] >> 1 & 0x20;
  ret[0] |= R[GET_BYTE_IDX(3) ] >> 1 & 0x10;
  ret[0] |= R[GET_BYTE_IDX(4) ] >> 1 & 0x08;
  ret[0] |= R[GET_BYTE_IDX(5) ] >> 1 & 0x04;

  ret[0] |= R[GET_BYTE_IDX(4) ] >> 3 & 0x02;
  ret[0] |= R[GET_BYTE_IDX(5) ] >> 3 & 0x01;
  ret[1] |= R[GET_BYTE_IDX(6) ] << 5 & 0x80;
  ret[1] |= R[GET_BYTE_IDX(7) ] << 5 & 0x40;
  ret[1] |= R[GET_BYTE_IDX(8) ] << 5 & 0x20;
  ret[1] |= R[GET_BYTE_IDX(9) ] >> 3 & 0x10;

  ret[1] |= R[GET_BYTE_IDX(8) ] << 3 & 0x08;
  ret[1] |= R[GET_BYTE_IDX(9) ] >> 5 & 0x04;
  ret[1] |= R[GET_BYTE_IDX(10)] >> 5 & 0x02;
  ret[1] |= R[GET_BYTE_IDX(11)] >> 5 & 0x01;
  ret[2] |= R[GET_BYTE_IDX(12)] << 3 & 0x80;
  ret[2] |= R[GET_BYTE_IDX(13)] << 3 & 0x40;
  
  ret[2] |= R[GET_BYTE_IDX(12)] << 1 & 0x20;
  ret[2] |= R[GET_BYTE_IDX(13)] << 1 & 0x10;
  ret[2] |= R[GET_BYTE_IDX(14)] << 1 & 0x08;
  ret[2] |= R[GET_BYTE_IDX(15)] << 1 & 0x04;
  ret[2] |= R[GET_BYTE_IDX(16)] << 1 & 0x02;
  ret[2] |= R[GET_BYTE_IDX(17)] >> 7 & 0x01;

  ret[3] |= R[GET_BYTE_IDX(16)] << 7 & 0x80;
  ret[3] |= R[GET_BYTE_IDX(17)] >> 1 & 0x40;
  ret[3] |= R[GET_BYTE_IDX(18)] >> 1 & 0x20;
  ret[3] |= R[GET_BYTE_IDX(19)] >> 1 & 0x10;
  ret[3] |= R[GET_BYTE_IDX(20)] >> 1 & 0x08;
  ret[3] |= R[GET_BYTE_IDX(21)] >> 1 & 0x04;

  ret[3] |= R[GET_BYTE_IDX(20)] >> 3 & 0x02;
  ret[3] |= R[GET_BYTE_IDX(21)] >> 3 & 0x01;
  ret[4] |= R[GET_BYTE_IDX(22)] << 5 & 0x80;
  ret[4] |= R[GET_BYTE_IDX(23)] << 5 & 0x40;
  ret[4] |= R[GET_BYTE_IDX(24)] << 5 & 0x20;
  ret[4] |= R[GET_BYTE_IDX(25)] >> 3 & 0x10;

  ret[4] |= R[GET_BYTE_IDX(24)] << 3 & 0x08;
  ret[4] |= R[GET_BYTE_IDX(25)] >> 5 & 0x04;
  ret[4] |= R[GET_BYTE_IDX(26)] >> 5 & 0x02;
  ret[4] |= R[GET_BYTE_IDX(27)] >> 5 & 0x01;
  ret[5] |= R[GET_BYTE_IDX(28)] << 3 & 0x80;
  ret[5] |= R[GET_BYTE_IDX(29)] << 3 & 0x40;

  ret[5] |= R[GET_BYTE_IDX(28)] << 1 & 0x20;
  ret[5] |= R[GET_BYTE_IDX(29)] << 1 & 0x10;
  ret[5] |= R[GET_BYTE_IDX(30)] << 1 & 0x08;
  ret[5] |= R[GET_BYTE_IDX(31)] << 1 & 0x04;
  ret[5] |= R[GET_BYTE_IDX(32)] << 1 & 0x02;
  ret[5] |= R[GET_BYTE_IDX(1) ] >> 7 & 0x01;
}

static const uint8_t g_sboxes[8][64] = {

  /* S1 */
  {
    14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
    0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
    4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
    15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13
  },

  /* S2 */
  {
    15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
    3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
    0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
    13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9
  },

  /* S3 */
  {
    10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
    13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
    13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
    1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12
  },

  /* S4 */
  {
    7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
    13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
    10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
    3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14
  },

  /* S5 */
  {
    2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
    14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
    4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
    11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3
  },

  /* S6 */
  {
    12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
    10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
    9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
    4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13
  },

  /* S7 */
  {
    4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
    13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
    1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
    6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12
  },

  /* S8 */
  {
    13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
    1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
    7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
    2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11
  }
};

static void msg_calc_b_indices(const uint8_t * const e_bit_key_xored, size_t key_xored_size, uint8_t *retB)
{
  /*
   *
   *  Every 6 bits from e_bit_key_xored needs to be placed
   *  int every byte in retB on last positions.
   *
   *  Given begining sequence of 011000   010001
   *  be obtain two bytes      00011000 00010001
   *
   */

  size_t b_idx = 0;
  size_t bit_cnt = 1;
  for(size_t i = 1; i <= key_xored_size * 8; ++i, ++bit_cnt)
  {
    uint8_t new_bit_map = 0;
    {
      switch(bit_cnt)
      {
        case 1:
          new_bit_map = 0x20;
          break;
        case 2:
          new_bit_map = 0x10;
          break;
        case 3:
          new_bit_map = 0x08;
          break;
        case 4:
          new_bit_map = 0x04;
          break;
        case 5:
          new_bit_map = 0x02;
          break;
        case 6:
          new_bit_map = 0x01;
          break;
      }
    }

    uint8_t old_bit_byte_idx = 0;
    {
      while((i + old_bit_byte_idx) % 8 != 0)
        ++old_bit_byte_idx;

      old_bit_byte_idx = 8 - old_bit_byte_idx;
    }

    const uint8_t new_bit_byte_idx = (uint8_t)bit_cnt + 2;
    const int shift = abs((int)new_bit_byte_idx - (int)old_bit_byte_idx);

    const uint8_t e_bit_byte = e_bit_key_xored[GET_BYTE_IDX(i)];
    if(new_bit_byte_idx == old_bit_byte_idx)
      retB[b_idx] |= e_bit_byte & new_bit_map;
    else if(new_bit_byte_idx < old_bit_byte_idx)
      retB[b_idx] |= e_bit_byte << shift & new_bit_map;
    else
      retB[b_idx] |= e_bit_byte >> shift & new_bit_map;

    if(bit_cnt % 6 == 0)
    {
      bit_cnt = 0;
      ++b_idx;
    }
  }
}

static uint8_t msg_b_row_num(uint8_t six_bit_byte)
{
  // 0x20 bit goes to 0x02 and 0x01 goes to 0x01

  uint8_t ret = 0x00;
  ret |= six_bit_byte >> 4 & 0x02;
  ret |= six_bit_byte & 0x01;

  return ret;
}

static uint8_t msg_b_col_num(uint8_t six_bit_byte)
{
  // 0x1e (0001 1110) goes to 0x0f
  return (uint8_t)six_bit_byte >> 1 & 0x0f;
}

static void msg_p_permut(const uint8_t * const sbox_result, uint8_t *ret)
{

  /*
   
    16   7  20  21
    29  12  28  17
    1  15  23  26
    5  18  31  10
    2   8  24  14
    32  27   3   9
    19  13  30   6
    22  11   4  25
  
  */
  
  ret[0] |= sbox_result[GET_BYTE_IDX(16)] << 7 & 0x80;
  ret[0] |= sbox_result[GET_BYTE_IDX(7) ] << 5 & 0x40;
  ret[0] |= sbox_result[GET_BYTE_IDX(20)] << 1 & 0x20;
  ret[0] |= sbox_result[GET_BYTE_IDX(21)] << 1 & 0x10;

  ret[0] |= sbox_result[GET_BYTE_IDX(29)]      & 0x08;
  ret[0] |= sbox_result[GET_BYTE_IDX(12)] >> 2 & 0x04;
  ret[0] |= sbox_result[GET_BYTE_IDX(28)] >> 3 & 0x02;
  ret[0] |= sbox_result[GET_BYTE_IDX(17)] >> 7 & 0x01;

  ret[1] |= sbox_result[GET_BYTE_IDX(1) ]      & 0x80;
  ret[1] |= sbox_result[GET_BYTE_IDX(15)] << 5 & 0x40;
  ret[1] |= sbox_result[GET_BYTE_IDX(23)] << 4 & 0x20;
  ret[1] |= sbox_result[GET_BYTE_IDX(26)] >> 2 & 0x10;

  ret[1] |= sbox_result[GET_BYTE_IDX(5) ]      & 0x08;
  ret[1] |= sbox_result[GET_BYTE_IDX(18)] >> 4 & 0x04;
  ret[1] |= sbox_result[GET_BYTE_IDX(31)]      & 0x02;
  ret[1] |= sbox_result[GET_BYTE_IDX(10)] >> 6 & 0x01;

  ret[2] |= sbox_result[GET_BYTE_IDX(2) ] << 1 & 0x80;
  ret[2] |= sbox_result[GET_BYTE_IDX(8) ] << 6 & 0x40;
  ret[2] |= sbox_result[GET_BYTE_IDX(24)] << 5 & 0x20;
  ret[2] |= sbox_result[GET_BYTE_IDX(14)] << 2 & 0x10;

  ret[2] |= sbox_result[GET_BYTE_IDX(32)] << 3 & 0x08;
  ret[2] |= sbox_result[GET_BYTE_IDX(27)] >> 3 & 0x04;
  ret[2] |= sbox_result[GET_BYTE_IDX(3) ] >> 4 & 0x02;
  ret[2] |= sbox_result[GET_BYTE_IDX(9) ] >> 7 & 0x01;

  ret[3] |= sbox_result[GET_BYTE_IDX(19)] << 2 & 0x80;
  ret[3] |= sbox_result[GET_BYTE_IDX(13)] << 3 & 0x40;
  ret[3] |= sbox_result[GET_BYTE_IDX(30)] << 3 & 0x20;
  ret[3] |= sbox_result[GET_BYTE_IDX(6) ] << 2 & 0x10;

  ret[3] |= sbox_result[GET_BYTE_IDX(22)] << 1 & 0x08;
  ret[3] |= sbox_result[GET_BYTE_IDX(11)] >> 3 & 0x04;
  ret[3] |= sbox_result[GET_BYTE_IDX(4) ] >> 3 & 0x02;
  ret[3] |= sbox_result[GET_BYTE_IDX(25)] >> 7 & 0x01;
}

static void msg_calc_Rn(const uint8_t * const L, const uint8_t * const R, key_subkey_t key_rot, uint8_t *out_R)
{
  uint8_t e_bit[MSG_E_BIT_SIZE] = {0};
  msg_ebit_selection(R, e_bit);

  uint8_t e_bit_key_xored[MSG_E_BIT_SIZE] = {0};
  for(size_t i = 0; i < MSG_E_BIT_SIZE && i < key_rot.size; ++i)
  {
    e_bit_key_xored[i] = e_bit[i] ^ key_rot.ptr[i];
  }

  uint8_t b_indices[MSG_B_INDICES_SIZE] = {0};
  msg_calc_b_indices(e_bit_key_xored, MSG_E_BIT_SIZE, b_indices);

  uint8_t sbox_selection[MSG_SBOX_SELECTION_SIZE] = {0};
  size_t sbox_selection_idx = 0;
  for(size_t i = 0; i < MSG_B_INDICES_SIZE && sbox_selection_idx < MSG_SBOX_SELECTION_SIZE; ++i)
  {
    const uint8_t *sbox = g_sboxes[i];

    const uint8_t row_num = msg_b_row_num(b_indices[i]);
    const uint8_t col_num = msg_b_col_num(b_indices[i]);
    const uint8_t s_num = sbox[MSG_SBOX_ROW_SIZE * row_num + col_num ];
    
    if((i + 1) % 2 == 0)
    {
      // place on the 0x0f plus increase counter
      sbox_selection[sbox_selection_idx] &= 0xf0; // most likely redundant
      sbox_selection[sbox_selection_idx] |= (s_num & 0x0f);
      ++sbox_selection_idx;
    }
    else
    {
      // place on the 0xf0 
      sbox_selection[sbox_selection_idx] &= 0x0f; // most likely redundant
      sbox_selection[sbox_selection_idx] |= (s_num << 4 & 0xf0);
    }

  }

  uint8_t p_permut[MSG_P_PERMUT_SIZE] = {0};
  msg_p_permut(sbox_selection, p_permut);

  for(size_t i = 0; i < MSG_P_PERMUT_SIZE && i < MSG_LR_SIZE; ++i)
    out_R[i] = L[i] ^ p_permut[i];

#ifdef LOG_MSG_LR_INTERNAL_DETAILS
  const size_t num = key_rot.it;
  char title_str[10 + 1] = {0};
  sdes_printf(title_str, "E%zu = ", num);
  print_bin_with_title(title_str, e_bit, MSG_E_BIT_SIZE, 6, 0);

  memset(title_str, 0x00, 10 + 1);
  sdes_printf(title_str, "K%zuE%zu = ", key_rot.it, num);
  print_bin_with_title(title_str, e_bit_key_xored, MSG_E_BIT_SIZE, 6, 0);

  memset(title_str, 0x00, 10 + 1);
  sdes_printf(title_str, "B%zu = ", key_rot.it);
  print_bin_with_title(title_str, b_indices, MSG_B_INDICES_SIZE, 8, 0);

  print_bin_with_title("S(B) = ", sbox_selection, MSG_SBOX_SELECTION_SIZE, 4, 0);
  print_bin_with_title("P(S) = ", p_permut, MSG_P_PERMUT_SIZE, 4, 0);
#endif
}

static void msg_combine_final_RL(const uint8_t * const L, const uint8_t * const R, uint8_t *final_RL)
{
  memcpy(final_RL, R, MSG_LR_SIZE);
  memcpy(final_RL + MSG_LR_SIZE, L, MSG_LR_SIZE);
}

static void msg_single_block(const uint8_t * const msg_single_block, key_rotation_t key_rot, enum operation op, uint8_t *out_single_block)
{
  uint8_t msg_ip_buff[MSG_IP_SIZE] = {0};
  msg_ip(msg_single_block, msg_ip_buff);

  uint8_t L[MSG_LR_SIZE] = {0}, R[MSG_LR_SIZE] = {0};
  msg_get_LR(msg_ip_buff, L, R);

#ifdef LOG_MSG_DETAILS
  print_as_hexstr_with_title("M  = ", msg_single_block, MSG_SINGLE_BLOCK_SIZE);
  print_bin_with_title("M  = ", msg_single_block, MSG_SINGLE_BLOCK_SIZE, 4, 0);
  print_bin_with_title("IP = ", msg_ip_buff, MSG_IP_SIZE, 4, 0);
#endif

#ifdef LOG_MSG_LR_INTERNAL_DETAILS 
  print_bin_with_title("L0 = ", L, MSG_LR_SIZE, 4, 0); 
  print_bin_with_title("R0 = ", R, MSG_LR_SIZE, 4, 0);
  des_printf("\n"); 
#endif

  key_get_iterator key_iterator = key_get_iterator_function(op);
  
  uint8_t Rn[MSG_LR_SIZE] = {0};
  for(size_t i=1; i <= 16; ++i)
  {
    msg_calc_Rn(L, R, key_iterator(key_rot, i), Rn);

    msg_copy_LR(R, L);
    msg_copy_LR(Rn, R);

#ifdef LOG_MSG_LR_INTERNAL_DETAILS
    char title_str[10 + 1] = {0};
    sdes_printf(title_str, "L%zu = ", i);
    print_bin_with_title(title_str, L, MSG_LR_SIZE, 4, 0);
   
    memset(title_str, 0x00, 10 + 1);
    sdes_printf(title_str, "R%zu = ", i);
    print_bin_with_title(title_str, R, MSG_LR_SIZE, 4, 0);

    des_printf("\n");
#endif
  }

  uint8_t final_RL[MSG_SINGLE_BLOCK_SIZE] = {0};
  msg_combine_final_RL(L, R, final_RL);

  msg_ip_reverse(final_RL, out_single_block);

#ifdef LOG_MSG_LR_DETAILS
  print_bin_8bit("R16L16 = ", final_RL, MSG_SINGLE_BLOCK_SIZE);
#endif

#ifdef LOG_MSG_DETAILS
  print_bin_8bit("IP-1 = ", out_single_block, MSG_SINGLE_BLOCK_SIZE); 
  print_as_hexstr_with_title("Cipher = ", out_single_block, MSG_SINGLE_BLOCK_SIZE);
  des_printf("\n");
#endif

}

int main(int argc, char **argv)
{
  g_app_arg = arg_process(argc, argv);
  if(!arg_valid(g_app_arg))
  {
    usage();
    return 0;
  }
 
  char *key_file_buffer = NULL;
  const unsigned long key_file_size = read_whole_file(g_app_arg.key_file, &key_file_buffer);
  if(!key_file_size || !key_file_buffer)
  {
    des_printf("Err readng key file size %lu\n", key_file_size);
    goto key_end;
  }

  // ------------------------------  + 1 cause line feed
  if(key_file_size != KEY_HEXSTR_LEN + 1)
  {
    des_printf("key file size is required to be hex string consisting 16 character\n");
    goto key_end;
  }

  if(!is_valid_hex_str(key_file_buffer, KEY_HEXSTR_LEN))
  {
    des_printf("%s does not contain valid hex str\n", g_app_arg.key_file);
    goto key_end;
  }


  uint8_t key_bytes[KEY_SIZE] = {0};
  hex_str_to_bytes(key_file_buffer, KEY_HEXSTR_LEN, key_bytes);

  uint8_t key_pc1_bytes[KEY_PC1_SIZE] = {0};
  key_pc1(key_bytes, key_pc1_bytes);

  const key_rotation_t key_rot = key_rotation(key_pc1_bytes);
  if(!key_rot.subkeys)
  {
    des_printf("couldn init subkeys");
    goto key_end;
  }

#ifdef LOG_KEY_DETAILS
  print_as_hexstr_with_title("K = ", key_bytes, KEY_SIZE);
  print_bin_8bit("K = ", key_bytes, KEY_SIZE);
  print_bin_bits("K PC1 = ", key_pc1_bytes, KEY_PC1_SIZE, 7);

  key_rotation_print(key_rot);
  des_printf("\n");
#endif
  
  // single block msg handling
  
  uint8_t *msg_file_buffer = NULL;
  const unsigned long msg_file_size = read_whole_file(g_app_arg.data_file, (char**)&msg_file_buffer);
  if(msg_file_size != MSG_SINGLE_BLOCK_SIZE)
  {
    des_printf("Only single block of data allowed, read [%lu]\n", msg_file_size);
    goto msg_end;
  }  

  uint8_t cipher[MSG_SINGLE_BLOCK_SIZE] = {0};
  msg_single_block(msg_file_buffer, key_rot, g_app_arg.op, cipher);

  // result file handling
  if(*g_app_arg.output_file)
  {
    FILE *result_file = fopen(g_app_arg.output_file, "w");
    if(result_file)
    {
      const unsigned long result_file_written = fwrite(cipher, 1, MSG_SINGLE_BLOCK_SIZE, result_file);
      des_printf("Written %lu bytes to %s\n", result_file_written, g_app_arg.output_file);
      fclose(result_file);
    }
    else
      des_printf("Can't open result file '%s'", g_app_arg.output_file);
  }

msg_end:
  free_key_rot(key_rot);
  if(msg_file_buffer)
    free(msg_file_buffer);

key_end:
  if(key_file_buffer)
    free(key_file_buffer);
 
  return 0;
}

int des_printf(const char* restrict format, ...)
{
  if(g_app_arg.prv_flags & ARG_APP_QUIET)
    return 0;

  va_list arg;
  va_start(arg, format);

  const int ret = vprintf(format, arg);

  va_end(arg);

  return ret;
}

void print_bin_detail(const uint8_t * const buffer, size_t size, size_t bit_word_len, size_t skip_beg)
{
  // this would have been much simpler if I wouldn't need to print various bit word bytes from time to time

  const size_t str_len = size * 8 * sizeof(char);
  char *str = (char*)malloc(str_len);
  for(size_t i = 0; i < size; ++i)
  {
    const uint8_t bt = buffer[i];
    const size_t idx = i * 8;

    str[idx + 0] = bt & 0x80 ? '1' : '0';
    str[idx + 1] = bt & 0x40 ? '1' : '0';
    str[idx + 2] = bt & 0x20 ? '1' : '0';
    str[idx + 3] = bt & 0x10 ? '1' : '0';
    str[idx + 4] = bt & 0x08 ? '1' : '0';
    str[idx + 5] = bt & 0x04 ? '1' : '0';
    str[idx + 6] = bt & 0x02 ? '1' : '0';
    str[idx + 7] = bt & 0x01 ? '1' : '0'; 
  }

  size_t cnt = 0;
  for(size_t i = 0; i < str_len; ++i)
  {
    if(i < skip_beg)
      continue;

    if(cnt % bit_word_len == 0 && cnt != 0)
      des_printf(" ");
    
    des_printf("%c", str[i]);
    ++cnt;
  }
  
  free(str);
  des_printf("\n"); 
}

void print_bin_with_title(const char *title, const uint8_t * const buffer, size_t size, size_t bit_word_len, size_t skip_beg)
{
  des_printf("%s", title);
  print_bin_detail(buffer, size, bit_word_len, skip_beg);
}

void print_bin_simple(const char *title, const uint8_t * const buffer, size_t size)
{
  print_bin_with_title(title, buffer, size, size * 8, 0);
}

void print_bin_bits(const char *title, const uint8_t * const buffer, size_t size, size_t bit_word_len)
{
  print_bin_with_title(title, buffer, size, bit_word_len, 0);
}

void print_bin_8bit(const char *title, const uint8_t * const buffer, size_t size)
{
  print_bin_bits(title, buffer, size, 8);
}

void print_buffer(const char * const buffer, unsigned long size)
{
  for(unsigned long i = 0; i < size; ++i)
   des_printf("%c", buffer[i]);

  des_printf("\n"); 
}

void print_as_hexstr(const uint8_t * const buffer, size_t size)
{
  for(size_t i = 0; i < size; ++i)
    des_printf("%02x ", buffer[i]);

  des_printf("\n");
}

void print_as_hexstr_with_title(const char *title, const uint8_t * const buffer, size_t size)
{
  des_printf("%s", title);
  print_as_hexstr(buffer, size);
}
