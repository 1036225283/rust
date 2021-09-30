
static void test_keccak_256() {
  unsigned char out[32] = {0};
  unsigned char in[256] = "testing";
  keccak_256(&out, 32, &in, 7);
  printf("\n\ntest keccak\n\n");

  for (int i = 0; i < 32; i++) {
    printf("%x ", out[i]);
  }

  printf("\n\n");
}

// 测试提取index
static void int_to_mnemonic(uchar *bytes32, uchar *mnemonic,
                            int *mnemonic_index_) {

  unsigned char in[256] = {0};

  // ulong mnemonic_lo = mnemonic_start_lo + idx;
  ulong mnemonic_hi = 123456755;

  uchar a = 1;     // 00000001
  uint16 b = 1;    // 00000010
  uint16 c = 2047; // 00000010
  b = (b << 12) | b;
  printf("this is test a|b = %x %d", b, b);

  // 16个字节共16*8=128位
  // 128位+校检和4位 = 132位
  // 将数据分散到128也就是8个字节,是为了计算校检和
  // 根据32个字节,按照11位提取index
  uchar mnemonic_hash[32];
  for (int i = 0; i < 32; i++) {
    in[i] = bytes32[i];
  }

  sha256(&in, 32, &mnemonic_hash);

  // printf("\n\nthe mnemonic_hash = \n");

  // for (int i = 0; i < 32; i++) {
  //   printf("%x", mnemonic_hash[i]);
  // }
  // printf("\nmnemonic_hash\n");

  // 计算每个单词的索引,共24个单词
  ushort indices[24] = {0};

  uint index = 1;
  indices[0] = (bytes32[0] << 8 | bytes32[1]) >> 5;        // 8+3
  indices[1] = ((bytes32[1] & 31) << 8 | bytes32[2]) >> 2; // 5+6

  // printf("step 1 = %x\n", (bytes32[1] & 31));
  // printf("step 2 = %x\n", (bytes32[1] & 31) | bytes32[2]);
  // printf("step 3 = %x\n", ((bytes32[1] & 31) | bytes32[2]) >> 2);
  // printf("ret = %d\n", indices[index]);

  indices[2] =
      ((bytes32[2] & 3) << 16 | bytes32[3] << 8 | bytes32[4]) >> 7; // 3+8
  indices[3] = ((bytes32[4] & 127) << 8 | bytes32[5]) >> 4;         //
  indices[4] = ((bytes32[5] & 15) << 8 | bytes32[6]) >> 1;
  indices[5] = ((bytes32[6] & 1) << 16 | bytes32[7] << 8 | bytes32[8]) >> 6;
  indices[6] = ((bytes32[8] & 63) << 8 | bytes32[9]) >> 3;
  indices[7] = (bytes32[9] & 7) << 8 | bytes32[10];

  // 重复操作,序号不一样
  indices[8] = (bytes32[11] << 8 | bytes32[12]) >> 5;
  indices[9] = ((bytes32[12] & 31) << 8 | bytes32[13]) >> 2;
  indices[10] = ((bytes32[13] & 3) << 16 | bytes32[14] << 8 | bytes32[15]) >> 7;
  indices[11] = ((bytes32[15] & 127) << 8 | bytes32[16]) >> 4;
  indices[12] = ((bytes32[16] & 15) << 8 | bytes32[17]) >> 1;
  indices[13] = ((bytes32[17] & 1) << 16 | bytes32[18] << 8 | bytes32[19]) >> 6;
  indices[14] = ((bytes32[19] & 63) << 8 | bytes32[20]) >> 3;
  indices[15] = (bytes32[20] & 7) << 8 | bytes32[21];

  // 重复操作,序号不一样
  indices[16] = (bytes32[22] << 8 | bytes32[23]) >> 5;
  indices[17] = ((bytes32[23] & 31) << 8 | bytes32[24]) >> 2;
  indices[18] = ((bytes32[24] & 3) << 16 | bytes32[25] << 8 | bytes32[26]) >> 7;
  indices[19] = ((bytes32[26] & 127) << 8 | bytes32[27]) >> 4;
  indices[20] = ((bytes32[27] & 15) << 8 | bytes32[28]) >> 1;
  indices[21] = ((bytes32[28] & 1) << 16 | bytes32[29] << 8 | bytes32[30]) >> 6;
  indices[22] = ((bytes32[30] & 63) << 8 | bytes32[31]) >> 3;
  indices[23] = ((bytes32[31] & 7) << 8 | mnemonic_hash[0]);

  int mnemonic_index = 0;

  // 拼接助记词
  for (int i = 0; i < 24; i++) {
    int word_index = indices[i];
    int word_length = word_lengths[word_index];

    for (int j = 0; j < word_length; j++) {
      mnemonic[mnemonic_index] = words[word_index][j];
      mnemonic_index++;
    }
    mnemonic[mnemonic_index] = 32;
    mnemonic_index++;
  }
  mnemonic[mnemonic_index - 1] = 0;

  *mnemonic_index_ = mnemonic_index - 1;
}

static void PBKDF2(unsigned char *input_word, unsigned int input_word_len,
                   unsigned char *salt, unsigned int saltLen,
                   unsigned char *seed) {

  uchar key[256] = {0};
  uchar sha512_result[64] = {0};
  uchar tmp[64] = {0};

  printf("\nstart\n");

  for (int i = 0; i < input_word_len; i++) {
    key[i] = input_word[i];
    printf("%c", key[i]);
  }

  printf("|end\n");

  for (int j = 0; j < 2048; j++) {
    if (j == 0) {
      hmac_sha512(&key, input_word_len, salt, saltLen, &sha512_result);
      // printf("j = %d \n", j);
      // print_seed(sha512_result);

    } else {
      hmac_sha512(&key, input_word_len, &tmp, 64, &sha512_result);
      // printf("j = %d \n", j);
    }
    for (int i = 0; i < 64; i++) {
      tmp[i] = sha512_result[i];
    }
    xor_seed_with_round(seed, &sha512_result);

    // print_seed(&seed);
  }

  // printf("last out \n");
  // print_seed(seed);
}

static void test_PBKDF2() {
  uchar seed[64] = {0};
  uchar tmp_word[256] =
      "cabbage style glare dutch traffic spend minute finger twin hedgehog "
      "gossip butter bean river debris dance congress orient escape smart "
      "mixture garlic random mule";
  uchar pass[12] = {109, 110, 101, 109, 111, 110, 105, 99, 0, 0, 0, 1};
  PBKDF2(&tmp_word, 161, &pass, 12, &seed);
  // printf("\nseed = \n");
  print_seed(&seed);
}

__kernel void int_to_address(ulong mnemonic_start_hi, ulong mnemonic_start_lo,
                             __global uchar *target_mnemonic,
                             __global uchar *found_mnemonic) {
  ulong idx = get_global_id(0);
  printf("this is start\n");
  uchar mnemonic[256] = {0};
  uchar seed[64] = {0};
  int mnemonic_length = 0;
  uchar pass[12] = {109, 110, 101, 109, 111, 110, 105, 99, 0, 0, 0, 1};
  // test_PBKDF2();
  test_PBKDF2();
  printf("\n\nGPU the input entropy = \n");

  uchar test[32] = {0};
  for (int i = 0; i < 32; i++) {
    test[i] = target_mnemonic[i];
    printf("%x,", test[i]);
  }

  int_to_mnemonic(&test, &mnemonic, &mnemonic_length);
  printf("\nGPU mnemonic_length = %d", mnemonic_length);

  printf("\nGPU mnemonic\n");

  for (int i = 0; i < mnemonic_length; i++) {
    printf("%c", mnemonic[i]);
  }

  printf("\n\n");

  PBKDF2(&mnemonic, mnemonic_length, &pass, 12, &seed);
  print_seed(&seed);
  // ulong mnemonic_lo = mnemonic_start_lo + idx;
  // ulong mnemonic_hi = mnemonic_start_hi;

  uchar network = BITCOIN_MAINNET;
  extended_private_key_t master_private;

  new_master_from_seed(network, &seed, &master_private);

  // printf("\nmaster private key = \n");
  // for (int i = 0; i <= 32; i++) {
  //   printf("%x", master_private.private_key.key[i]);
  // }

  uchar pub_key[64] = {0};
  uchar address[32] = {0};
  extended_private_key_t target_key;
  extended_public_key_t target_public_key;
  hardened_private_child_from_private(&master_private, &target_key, 44);
  hardened_private_child_from_private(&target_key, &target_key, 60);
  hardened_private_child_from_private(&target_key, &target_key, 0);
  normal_private_child_from_private(&target_key, &target_key, 0);
  normal_private_child_from_private(&target_key, &target_key, 0);
  public_from_private(&target_key, &target_public_key);

  // printf("\n\npub_key = \n");
  // for (int i = 0; i < 64; i++) {
  //   pub_key[i] = target_public_key.public_key.key.data[i];
  //   printf("%x", pub_key[i]);
  // }

  unsigned char out[32] = {0};
  unsigned char in[256] = "testing";
  keccak_256(&address, 32, &pub_key, 64);

  printf("\n\nGPU address =0x");

  for (int i = 12; i < 32; i++) {
    printf("%x", address[i]);
  }

  uchar target_address[25] = {0x05, 0xAD, 0xA1, 0x2B, 0x11, 0x3D, 0x9B,
                              0x19, 0x61, 0x47, 0x57, 0xD1, 0x9F, 0xC0,
                              0x8D, 0xDD, 0x53, 0x4B, 0xF0, 0x22, 0x76,
                              0xBD, 0x3A, 0x31, 0x46};

  // bool found_target = 1;
  // for (int i = 0; i < 25; i++) {
  //   if (raw_address[i] != target_address[i]) {
  //     found_target = 0;
  //   }
  // }

  // if (found_target == 1) {
  //   found_mnemonic[0] = 0x01;
  //   for (int i = 0; i < mnemonic_index; i++) {
  //     target_mnemonic[i] = mnemonic[i];
  //   }
  // }
}
