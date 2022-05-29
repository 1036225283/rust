
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
// 比对地址
static void check_address(uchar *address, uchar *input_address, uchar index,
                          bool *flag) {
  for (int i = 12; i < 32; i++) {
    if (address[i] != input_address[20 * index + (i - 12)]) {
      *flag = 0;
      return;
    }
  }
  *flag = 1;
}
// 测试提取index
static void int_to_mnemonic(ushort *indices, uchar *mnemonic,
                            int *mnemonic_index_) {

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

  // printf("\nstart\n");

  for (int i = 0; i < input_word_len; i++) {
    key[i] = input_word[i];
    // printf("%c", key[i]);
  }

  // printf("|end\n");

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

__kernel void int_to_address(ulong input_index, __global uchar *input_entropy,
                             __global uchar *input_address,
                             __global uchar *out_mnemonic) {
  ulong idx = get_global_id(0);
  if (idx > 8589934592) {
    return;
  }
  printf("GPU idx = %d", idx);

  uchar mnemonic[256] = {0};
  uchar seed[64] = {0};
  int mnemonic_length = 0;
  uchar pass[12] = {109, 110, 101, 109, 111, 110, 105, 99, 0, 0, 0, 1};
  // test_PBKDF2();
  // test_PBKDF2();
  // printf("\n\nGPU the input entropy = \n");
  ulong index = input_index;
  ushort indices[24] = {0};
  for (int i = 0; i < 24; i++) {
    indices[i] = input_entropy[i];
  }

  ulong word1 = idx / 2048 / 2048;
  ulong word2 = idx / 2048 % 2048;
  ulong word3 = idx % 2048;
  indices[index] = word1;
  indices[index + 1] = word2;
  indices[index + 2] = word3;
  int_to_mnemonic(&indices, &mnemonic, &mnemonic_length);
  // printf("\nGPU mnemonic_length = %d", mnemonic_length);

  // printf("\nGPU mnemonic\n");

  // for (int i = 0; i < mnemonic_length; i++) {
  // printf("%c", mnemonic[i]);
  // }

  // printf("\n\n");

  PBKDF2(&mnemonic, mnemonic_length, &pass, 12, &seed);
  // print_seed(&seed);
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
  uchar input_address_copy[80] = {0};
  extended_private_key_t target_key;
  extended_public_key_t target_public_key;
  hardened_private_child_from_private(&master_private, &target_key, 44);
  hardened_private_child_from_private(&target_key, &target_key, 60);
  hardened_private_child_from_private(&target_key, &target_key, 0);
  normal_private_child_from_private(&target_key, &target_key, 0);
  normal_private_child_from_private(&target_key, &target_key, 0);
  public_from_private(&target_key, &target_public_key);

  // printf("\npub_key = \n");
  for (int i = 0; i < 64; i++) {
    pub_key[i] = target_public_key.public_key.key.data[i];
    // printf("%x", pub_key[i]);
  }

  keccak_256(&address, 32, &pub_key, 64);
  // printf("\n\nGPU address = 0x");
  for (int i = 0; i < 80; i++) {
    input_address_copy[i] = input_address[i];
    // printf("%x", input_address[i]);
  }

  bool flag = 0;
  for (int i = 0; i < 4; i++) {
    check_address(&address, &input_address_copy, i, &flag);

    if (flag == 1) {
      for (int i = 0; i < mnemonic_length; i++) {
        out_mnemonic[i] = mnemonic[i];
      }
    }
  }
}
