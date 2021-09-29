
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
static void int_to_mnemonic(uchar *bytes32) {

  unsigned char out[32] = {0};
  unsigned char in[256] = "testing";

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

  printf("\n\nthe mnemonic_hash = \n");

  sha256(bytes32, 32, &mnemonic_hash);

  uchar checksum = 2;

  // 计算每个单词的索引,共24个单词
  ushort indices[24] = {0};

  uint index = 1;
  indices[0] = (bytes32[0] << 8 | bytes32[1]) >> 5;        // 8+3
  indices[1] = ((bytes32[1] & 63) << 8 | bytes32[2]) >> 2; // 5+6

  printf("\n bytes32[0].start = %x\n", bytes32[0]);
  printf("indices[0] = %x\n", bytes32[index]);
  printf("indices[0] = %x\n", (bytes32[1] & 63));
  printf("indices[0] = %x\n", (bytes32[1] & 63) | bytes32[2]);
  printf("indices[0] = %x\n", ((bytes32[1] & 63) | bytes32[2]) >> 2);
  printf("bytes32[0].end = %x\n", bytes32[index]);
  printf("indices[0].end = %d\n", indices[index]);

  indices[2] =
      ((bytes32[2] & 3) << 16 | bytes32[3] << 8 | bytes32[4]) >> 7; // 3+8
  indices[3] = ((bytes32[4] & 127) << 8 | bytes32[5]) >> 4;         //
  indices[4] = ((bytes32[5] & 15) << 8 | bytes32[6]) >> 1;
  indices[5] = ((bytes32[6] & 1) << 16 | bytes32[7] << 8 | bytes32[8]) >> 6;
  indices[6] = ((bytes32[8] & 63) << 8 | bytes32[9]) >> 3;
  indices[7] = (bytes32[9] & 7) << 8 | bytes32[10];

  // 重复操作,序号不一样
  indices[8] = (bytes32[11] << 8 | bytes32[12]) >> 5;
  indices[9] = ((bytes32[12] & 63) << 8 | bytes32[13]) >> 2;
  indices[10] = ((bytes32[13] & 3) << 16 | bytes32[14] << 8 | bytes32[15]) >> 7;
  indices[11] = ((bytes32[15] & 127) << 8 | bytes32[16]) >> 4;
  indices[12] = ((bytes32[16] & 15) << 8 | bytes32[17]) >> 1;
  indices[13] = ((bytes32[17] & 1) << 16 | bytes32[18] << 8 | bytes32[19]) >> 6;
  indices[14] = ((bytes32[19] & 63) << 8 | bytes32[20]) >> 3;
  indices[15] = (bytes32[20] & 7) << 8 | bytes32[21];

  // 重复操作,序号不一样
  indices[16] = (bytes32[22] << 8 | bytes32[23]) >> 5;
  indices[17] = ((bytes32[23] & 63) << 8 | bytes32[24]) >> 2;
  indices[18] = ((bytes32[24] & 3) << 16 | bytes32[25] << 8 | bytes32[26]) >> 7;
  indices[19] = ((bytes32[26] & 127) << 8 | bytes32[27]) >> 4;
  indices[20] = ((bytes32[27] & 15) << 8 | bytes32[28]) >> 1;
  indices[21] = ((bytes32[28] & 1) << 16 | bytes32[29] << 8 | bytes32[30]) >> 6;
  indices[22] = ((bytes32[30] & 63) << 8 | bytes32[31]) >> 3;
  indices[23] = (bytes32[31] << 8 | bytes32[23]) >> 5;
  indices[23] = ((bytes32[31] & 7) << 8 | mnemonic_hash[0]);

  uchar mnemonic[256] = {0};
  uchar mnemonic_length =
      11 + word_lengths[indices[0]] + word_lengths[indices[1]] +
      word_lengths[indices[2]] + word_lengths[indices[3]] +
      word_lengths[indices[4]] + word_lengths[indices[5]] +
      word_lengths[indices[6]] + word_lengths[indices[7]] +
      word_lengths[indices[8]] + word_lengths[indices[9]] +
      word_lengths[indices[10]] + word_lengths[indices[11]] +
      word_lengths[indices[12]] + word_lengths[indices[13]] +
      word_lengths[indices[14]] + word_lengths[indices[15]] +
      word_lengths[indices[16]] + word_lengths[indices[17]] +
      word_lengths[indices[18]] + word_lengths[indices[19]] +
      word_lengths[indices[20]] + word_lengths[indices[21]] +
      word_lengths[indices[22]] + word_lengths[indices[23]];
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

  printf("\nmnemonic_word\n");

  for (int i = 0; i < mnemonic_index; i++) {
    printf("%c", mnemonic[i]);
  }

  printf("\nmnemonic_word\n");
}

static void PBKDF2(unsigned char *words, unsigned int wordsLen,
                   unsigned char *salt, unsigned int saltLen,
                   unsigned char *seed) {

  uchar key[256] = {0};
  uchar sha512_result[64] = {0};
  uchar tmp[64] = {0};

  int len = 155;
  int hLen = 20;
  int dkLen = 64;

  printf("\nstart\n");

  for (int i = 0; i < wordsLen; i++) {
    key[i] = words[i];
    printf("%c", key[i]);
  }

  printf("|end\n");

  for (int j = 0; j < 2048; j++) {
    if (j == 0) {
      hmac_sha512(&key, len, salt, saltLen, &sha512_result);
      // printf("j = %d \n", j);
      // print_seed(sha512_result);

    } else {
      hmac_sha512(&key, len, &tmp, 64, &sha512_result);
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

__kernel void int_to_address(ulong mnemonic_start_hi, ulong mnemonic_start_lo,
                             __global uchar *target_mnemonic,
                             __global uchar *found_mnemonic) {
  ulong idx = get_global_id(0);
  printf("this is start\n");
  uchar seed[64] = {0};
  uchar words[256] = "rhythm bulk shoulder shy mix finger fog artefact update "
                     "obtain fresh clown tent inspire answer unaware teach "
                     "action two captain street mammal rather fossil";
  uchar pass[12] = {109, 110, 101, 109, 111, 110, 105, 99, 0, 0, 0, 1};
  PBKDF2(&words, 155, &pass, 12, &seed);
  print_seed(&seed);
  // ulong mnemonic_lo = mnemonic_start_lo + idx;
  // ulong mnemonic_hi = mnemonic_start_hi;

  // uchar bytes[16];
  // bytes[15] = mnemonic_lo & 0xFF;
  // bytes[14] = (mnemonic_lo >> 8) & 0xFF;
  // bytes[13] = (mnemonic_lo >> 16) & 0xFF;
  // bytes[12] = (mnemonic_lo >> 24) & 0xFF;
  // bytes[11] = (mnemonic_lo >> 32) & 0xFF;
  // bytes[10] = (mnemonic_lo >> 40) & 0xFF;
  // bytes[9] = (mnemonic_lo >> 48) & 0xFF;
  // bytes[8] = (mnemonic_lo >> 56) & 0xFF;

  // bytes[7] = mnemonic_hi & 0xFF;
  // bytes[6] = (mnemonic_hi >> 8) & 0xFF;
  // bytes[5] = (mnemonic_hi >> 16) & 0xFF;
  // bytes[4] = (mnemonic_hi >> 24) & 0xFF;
  // bytes[3] = (mnemonic_hi >> 32) & 0xFF;
  // bytes[2] = (mnemonic_hi >> 40) & 0xFF;
  // bytes[1] = (mnemonic_hi >> 48) & 0xFF;
  // bytes[0] = (mnemonic_hi >> 56) & 0xFF;

  // uchar mnemonic_hash[32];
  // sha256(&bytes, 16, &mnemonic_hash);
  // uchar checksum = (mnemonic_hash[0] >> 4) & ((1 << 4) - 1);

  // ushort indices[12];
  // indices[0] = (mnemonic_hi >> 53) & 2047;
  // indices[1] = (mnemonic_hi >> 42) & 2047;
  // indices[2] = (mnemonic_hi >> 31) & 2047;
  // indices[3] = (mnemonic_hi >> 20) & 2047;
  // indices[4] = (mnemonic_hi >> 9) & 2047;
  // indices[5] =
  //     ((mnemonic_hi & ((1 << 9) - 1)) << 2) | ((mnemonic_lo >> 62) & 3);
  // indices[6] = (mnemonic_lo >> 51) & 2047;
  // indices[7] = (mnemonic_lo >> 40) & 2047;
  // indices[8] = (mnemonic_lo >> 29) & 2047;
  // indices[9] = (mnemonic_lo >> 18) & 2047;
  // indices[10] = (mnemonic_lo >> 7) & 2047;
  // indices[11] = ((mnemonic_lo & ((1 << 7) - 1)) << 4) | checksum;

  // uchar mnemonic[180] = {0};
  // uchar mnemonic_length = 11 + word_lengths[indices[0]] +
  //                         word_lengths[indices[1]] + word_lengths[indices[2]]
  //                         + word_lengths[indices[3]] +
  //                         word_lengths[indices[4]] + word_lengths[indices[5]]
  //                         + word_lengths[indices[6]] +
  //                         word_lengths[indices[7]] + word_lengths[indices[8]]
  //                         + word_lengths[indices[9]] +
  //                         word_lengths[indices[10]] +
  //                         word_lengths[indices[11]];
  // int mnemonic_index = 0;

  // for (int i = 0; i < 12; i++) {
  //   int word_index = indices[i];
  //   int word_length = word_lengths[word_index];

  //   for (int j = 0; j < word_length; j++) {
  //     mnemonic[mnemonic_index] = words[word_index][j];
  //     mnemonic_index++;
  //   }
  //   mnemonic[mnemonic_index] = 32;
  //   mnemonic_index++;
  // }
  // mnemonic[mnemonic_index - 1] = 0;

  uchar network = BITCOIN_MAINNET;
  extended_private_key_t master_private;

  new_master_from_seed(network, &seed, &master_private);

  printf("\nmaster private key = \n");
  for (int i = 0; i <= 32; i++) {
    printf("%x", master_private.private_key.key[i]);
  }

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

  printf("\n\npub_key = \n");
  for (int i = 0; i < 64; i++) {
    pub_key[i] = target_public_key.public_key.key.data[i];
    printf("%x", pub_key[i]);
  }

  unsigned char out[32] = {0};
  unsigned char in[256] = "testing";
  keccak_256(&address, 32, &pub_key, 64);

  printf("\n\n last public key = \n");

  for (int i = 12; i < 32; i++) {
    printf("%x,", address[i]);
  }

  printf("\n\nthe input mnemonic = \n");

  uchar test[32] = {0};
  for (int i = 0; i < 32; i++) {
    test[i] = target_mnemonic[i];
    printf("%x,", test[i]);
  }

  uchar mnemonic_hash[32];

  printf("\n\nthe mnemonic_hash = \n");

  sha256(&test, 32, &mnemonic_hash);
  for (int i = 0; i < 32; i++) {
    printf("%x", mnemonic_hash[i]);
  }
  printf("\nmnemonic_hash\n");

  uchar checksum = (mnemonic_hash[0] >> 8) & ((1 << 8) - 1);
  printf("\nhecksum = %x\n", checksum);
  int_to_mnemonic(&test);

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
