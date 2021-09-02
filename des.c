#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <ctype.h>
#include <assert.h>
#include <string.h>

#define KEY_SIZE 8 
#define KEY_PC1_SIZE 7
#define KEY_PC2_SIZE 6
#define KEY_HEXSTR_LEN (KEY_SIZE * 2)
#define KEY_ITER_SIZE KEY_PC2_SIZE
#define KEY_SUBKEYS_NUM 16
#define E_BIT_SIZE 6

#define MSG_SINGLE_BLOCK_SIZE 8
#define MSG_IP_SIZE 8
#define MSG_LR_SIZE 4

//#define LOG_KEY_DETAILS
//#define LOG_KEY_CD_DETAILS
//#define LOG_MSG_DETAILS
#define LOG_MSG_LR_DETAILS

#define GET_BYTE_IDX(bit_pos) ((size_t)(bit_pos - 1) / 8)

void print_bin_detail(const uint8_t * const buffer, size_t size, size_t bit_word_len, size_t skip_beg);
void print_bin_with_title(const char *title, const uint8_t * const buffer, size_t size, size_t bit_word_len, size_t skip_beg);
void print_bin_simple(const char *title, const uint8_t * const buffer, size_t size);
void print_bin_bits(const char *title, const uint8_t * const buffer, size_t size, size_t bit_word_len);
void print_bin_8bit(const char *title, const uint8_t * const buffer, size_t size);
void print_buffer(const char * const buffer, unsigned long size);
void print_as_hexstr(const uint8_t * const buffer, size_t size);

typedef struct key_rotation_t
{
  uint8_t *subkeys;
} key_rotation_t;

typedef struct key_rotation_iterator_t
{
  uint8_t *ptr;
  size_t size;
  size_t it;

} key_rotation_iterator_t;

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

static key_rotation_iterator_t key_get_iteration(key_rotation_t key_rot, size_t iteration)
{
  if(!iteration || iteration > KEY_SUBKEYS_NUM)
  {
    const key_rotation_iterator_t ret = { .ptr = NULL, .size = 0, .it = 0};
    return ret;
  }

  const key_rotation_iterator_t it = 
  {
    .ptr = key_rot.subkeys + ((iteration - 1) * KEY_ITER_SIZE),
    .size = KEY_ITER_SIZE,
    .it = iteration
  };

  return it;
}

static int key_is_iterator_valid(key_rotation_iterator_t it)
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
  key_rotation_iterator_t it = key_get_iteration(key_rot, idx);
  char title_str[10 + 1] = {0};
  for(; key_is_iterator_valid(it); ++idx, it = key_get_iteration(key_rot, idx))
  {
    sprintf(title_str, "K%lu =", idx);
    print_bin_with_title(title_str, it.ptr, it.size, 6, 0);
    memset(title_str, 0x00, sizeof title_str);
  }
}

static void usage(void)
{
  printf("c99_practice <file_with_hex_str_key> <binary_file>\n");
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
  printf("%s read size %lu buff size %lu\n", filename, actual_size, file_size); 
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
  size_t byteTbCnt = 0;

  for(unsigned long i = 0; i < size; ++i)
  {
    byte[byteTbCnt] = buffer[i];
    if(byteTbCnt == 1)
    {
      byteTbCnt = 0;

      const uint8_t lsb = hex_char_map(byte[1]);
      const uint8_t msb = hex_char_map(byte[0]);

      *ret |= lsb;
      *ret |= ((msb << 4) & 0xf0);

      ++ret;
      continue;
    }

    byteTbCnt += 1;
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

void static shift_left_cd_mv_bit(uint8_t *buffer, size_t size)
{
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

  buffer[0] &= 0x0f;
  buffer[size - 1] |= last_bit; 
}

static key_rotation_t key_rotation(const uint8_t * const key_pc1_buffer)
{
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
  print_bin_with_title("C0 =", c_i, 4, 7, 4);
  print_bin_with_title("D0 =", d_i, 4, 7, 4);
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
    sprintf(title_str, "C%lu =", i);
    print_bin_simple(title_str, c_i, 4);
    
    memset(title_str, 0x00, sizeof title_str);

    sprintf(title_str, "D%lu =", i);
    print_bin_simple(title_str, d_i, 4);
#endif

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
    print_bin_bits("CD =", cd, 7, 7);
#endif

    uint8_t K_pc2[KEY_PC2_SIZE] = {0};
    key_pc2(cd, K_pc2);

#if 0
#ifdef LOG_KEY_DETAILS
    sprintf(title_str, "K%lu =", i);
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

static void msg_get_LR(const uint8_t * const ipbuffer, uint8_t *retL, uint8_t *retR)
{
  memcpy(retL, ipbuffer, MSG_LR_SIZE);
  memcpy(retR, ipbuffer + MSG_LR_SIZE, MSG_LR_SIZE);
}

static void copy_LR(const uint8_t * const from, uint8_t *to)
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
  ret[2] |= R[GET_BYTE_IDX(12)] >> 1 & 0x80;
  ret[2] |= R[GET_BYTE_IDX(13)] >> 1 & 0x40;
  
  ret[2] |= R[GET_BYTE_IDX(12)] >> 3 & 0x20;
  ret[2] |= R[GET_BYTE_IDX(13)] >> 3 & 0x10;
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
  ret[5] |= R[GET_BYTE_IDX(28)] >> 1 & 0x80;
  ret[5] |= R[GET_BYTE_IDX(29)] >> 1 & 0x40;

  ret[5] |= R[GET_BYTE_IDX(28)] >> 3 & 0x20;
  ret[5] |= R[GET_BYTE_IDX(29)] >> 3 & 0x10;
  ret[5] |= R[GET_BYTE_IDX(30)] << 1 & 0x08;
  ret[5] |= R[GET_BYTE_IDX(31)] << 1 & 0x04;
  ret[5] |= R[GET_BYTE_IDX(32)] << 1 & 0x02;
  ret[5] |= R[GET_BYTE_IDX(1) ] >> 7 & 0x01;
}

static void calc_Rn(const uint8_t * const L, const uint8_t * const R, key_rotation_iterator_t key_rot, uint8_t *out_R)
{
  uint8_t e_bit[E_BIT_SIZE] = {0};
  msg_ebit_selection(R, e_bit);

#ifdef LOG_MSG_LR_DETAILS
  const size_t num = key_rot.it - 1;
  char title_str[10 + 1] = {0};
  sprintf(title_str, "E%zu =", num);
  print_bin_with_title(title_str, e_bit, E_BIT_SIZE, 6, 0); 
#endif
}

int main(int argc, char **argv)
{
  if(argc != 3)
  {
    usage();
    return 0;
  }
 
  char *key_file_buffer = NULL;
  const unsigned long key_file_size = read_whole_file(argv[1], &key_file_buffer);
  if(!key_file_size || !key_file_buffer)
  {
    printf("Err readng key file size %lu\n", key_file_size);
    goto key_end;
  }

  // ------------------------------  + 1 cause line feed
  if(key_file_size != KEY_HEXSTR_LEN + 1)
  {
    printf("key file size is required to be hex string consisting 16 character\n");
    goto key_end;
  }

  if(!is_valid_hex_str(key_file_buffer, KEY_HEXSTR_LEN))
  {
    printf("%s does not contain valid hex str\n", argv[1]);
    goto key_end;
  }

  //print_buffer(key_file_buffer, key_file_size);

  uint8_t key_bytes[KEY_SIZE] = {0};
  hex_str_to_bytes(key_file_buffer, KEY_HEXSTR_LEN, key_bytes);

#ifdef LOG_KEY_DETAILS
  //print_as_hexstr(key_bytes, sizeof key_bytes);
  print_bin_8bit("K =", key_bytes, KEY_SIZE);
#endif

  uint8_t key_pc1_bytes[KEY_PC1_SIZE] = {0};
  key_pc1(key_bytes, key_pc1_bytes);

#ifdef LOG_KEY_DETAILS
  print_bin_bits("K PC1 =", key_pc1_bytes, KEY_PC1_SIZE, 7);
#endif

  const key_rotation_t key_rot = key_rotation(key_pc1_bytes);
  if(!key_rot.subkeys)
  {
    printf("couldn init subkeys");
    goto key_end;
  }

#ifdef LOG_KEY_DETAILS
  key_rotation_print(key_rot);
#endif
  
  // single block msg handling
  
  uint8_t *msg_file_buffer = NULL;
  const unsigned long msg_file_size = read_whole_file(argv[2], (char**)&msg_file_buffer);
  if(msg_file_size != MSG_SINGLE_BLOCK_SIZE)
  {
    printf("Only single block of data allowed, read [%lu]\n", msg_file_size);
    goto msg_end;
  }  
 
  //printf("MSG ");
  //print_as_hexstr(msg_file_buffer, msg_file_size);

  
  uint8_t msg_ip_buff[MSG_IP_SIZE] = {0};
  msg_ip(msg_file_buffer, msg_ip_buff);

#ifdef LOG_MSG_DETAILS
  print_bin_with_title("M  =", msg_file_buffer, MSG_SINGLE_BLOCK_SIZE, 4, 0);
  print_bin_with_title("IP =", msg_ip_buff, MSG_IP_SIZE, 4, 0);
#endif

  uint8_t L[MSG_LR_SIZE] = {0}, R[MSG_LR_SIZE] = {0};
  msg_get_LR(msg_ip_buff, L, R);
#ifdef LOG_MSG_LR_DETAILS
  print_bin_with_title("L0 =", L, MSG_LR_SIZE, 4, 0); 
  print_bin_with_title("R0 =", R, MSG_LR_SIZE, 4, 0); 
#endif

  uint8_t R_tmp[MSG_LR_SIZE] = {0};
  for(size_t i=1; i <= 1; ++i)
  {
    calc_Rn(L, R, key_get_iteration(key_rot, i), R_tmp);

    copy_LR(R, L);
    copy_LR(R_tmp, R);
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
      printf(" ");
    
    printf("%c", str[i]);
    ++cnt;
  }
  
  free(str);
  printf("\n"); 
}

void print_bin_with_title(const char *title, const uint8_t * const buffer, size_t size, size_t bit_word_len, size_t skip_beg)
{
  printf("%s ", title);
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
   printf("%c", buffer[i]);

  printf("\n"); 
}

void print_as_hexstr(const uint8_t * const buffer, size_t size)
{
  for(size_t i = 0; i < size; ++i)
    printf("%2x ", buffer[i]);

  printf("\n");
}
