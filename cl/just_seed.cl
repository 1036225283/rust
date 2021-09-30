
static void test_sha512() {
  printf("\n this is test sha256 \n");

  uchar test1[256] = {0};
  uchar test[80] = "123456";
  for (int i = 0; i < 6; i++) {
    test1[i] = test[i];
    printf("%c", test[i]);
  }

  uchar sha512_result[64] = {0};
  sha512(&test1, 6, &sha512_result);
  printf("[");
  for (int x = 0; x < 64; x++) {
    printf("%x", sha512_result[x]);
    if (x < 64 - 1) {
      printf(", ");
    }
  }
  printf("]\n");
}

static void testSize() { printf("size long = %d  \n", sizeof(unsigned long)); }

// 测试HMAC-SHA512
static void testHmac() {

  uchar key[90] = {0};
  uchar seed[128] = "abcderfas";
  uchar pass[128] = "123456890";

  int len = 5;
  int passLen = 5;
  for (int i = 0; i < len; i++) {
    key[i] = seed[i];
  }

  uchar ipad_key[128];
  uchar opad_key[128];
  for (int x = 0; x < 128; x++) {
    ipad_key[x] = 0x36;
    opad_key[x] = 0x5c;
  }

  for (int x = 0; x < len; x++) {
    ipad_key[x] = ipad_key[x] ^ key[x];
    opad_key[x] = opad_key[x] ^ key[x];
  }

  uchar sha512_result[64] = {0};
  uchar key_previous_concat[256] = {0};
  uchar salt[8] = {109, 110, 101, 109, 111, 110, 105, 99};

  for (int x = 0; x < 128; x++) {
    key_previous_concat[x] = ipad_key[x];
  }
  for (int x = 0; x < passLen; x++) {
    key_previous_concat[x + 128] = pass[x];
    printf("ipad_key[%d] = %x \n", x, key_previous_concat[x + 128]);
  }

  sha512(&key_previous_concat, 128 + passLen, &sha512_result);
  for (int x = 0; x < 64; x++) {
    printf("%x", sha512_result[x]);
    if (x < 64 - 1) {
      printf(", ");
    }
  }

  printf("\n\n");
  copy_pad_previous(&opad_key, &sha512_result, &key_previous_concat);
  sha512(&key_previous_concat, 192, &sha512_result);

  // hmac_sha512(&key, 12, &seed, 64, &hmacsha512_result);
  for (int x = 0; x < 64; x++) {
    printf("%x", sha512_result[x]);
    if (x < 64 - 1) {
      printf(", ");
    }
  }
}

static void testHmac_long() {

  uchar key[256] = {0};
  uchar sha512_result[64] = {0};

  uchar seed[256] = "abandon ability able about above absent absorb abstract "
                    "absurd abuse access accident account accuse achieve acid "
                    "acoustic acquire across act action actor";
  uchar pass[128] = "123456890";

  int len = 129;
  int passLen = 5;

  printf("\nstart\n");

  for (int i = 0; i < len; i++) {
    key[i] = seed[i];
    printf("%c", key[i]);
  }

  printf("|end\n");

  // if len > 128
  if (len > 128) {
    sha512(&key, len, &sha512_result);
    len = 64;
    for (int i = 0; i < len; i++) {
      key[i] = sha512_result[i];
    }
  }

  uchar ipad_key[128];
  uchar opad_key[128];
  for (int x = 0; x < 128; x++) {
    ipad_key[x] = 0x36;
    opad_key[x] = 0x5c;
  }

  for (int x = 0; x < len; x++) {
    ipad_key[x] = ipad_key[x] ^ key[x];
    opad_key[x] = opad_key[x] ^ key[x];
  }

  uchar key_previous_concat[256] = {0};
  uchar salt[8] = {109, 110, 101, 109, 111, 110, 105, 99};

  for (int x = 0; x < 128; x++) {
    key_previous_concat[x] = ipad_key[x];
  }
  for (int x = 0; x < passLen; x++) {
    key_previous_concat[x + 128] = pass[x];
  }

  sha512(&key_previous_concat, 128 + passLen, &sha512_result);
  for (int x = 0; x < 64; x++) {
    printf("%x", sha512_result[x]);
    if (x < 64 - 1) {
      printf(", ");
    }
  }

  printf("\n\n");
  copy_pad_previous(&opad_key, &sha512_result, &key_previous_concat);
  sha512(&key_previous_concat, 192, &sha512_result);

  for (int x = 0; x < 64; x++) {
    printf("%x", sha512_result[x]);
    if (x < 64 - 1) {
      printf(", ");
    }
  }
}

static void test_sha512_long(uchar *target_mnemonic, ulong mnemonic_start_hi) {
  uchar mnemonic[256] = {0};
  int length = mnemonic_start_hi;

  int times = 205;
  printf("length = %d \n", mnemonic_start_hi);
  for (int i = 0; i < times; i++) {
    mnemonic[i] = target_mnemonic[i];
    printf("%c", mnemonic[i]);
  }
  uchar sha512_result[64] = {0};
  sha512(&mnemonic, times, &sha512_result);
  printf("[");
  for (int x = 0; x < 64; x++) {
    printf("%x", sha512_result[x]);
    if (x < 64 - 1) {
      printf(", ");
    }
  }
  printf("]\n");
}

// sha512_result[64]
static void hmac_sha512(unsigned char *keyInput, unsigned int keyLen,
                        unsigned char *pass, unsigned int passLen,
                        unsigned char *sha512_result) {
  uchar key[256] = {0};

  // printf("\nhmac_sha512 start keyLen = %d, passLen = %d\n", keyLen, passLen);

  // printf("\nkeyInput = ");
  for (int i = 0; i < keyLen; i++) {
    // printf("%c", keyInput[i]);
  }

  // printf("|\npass = ");
  for (int i = 0; i < passLen; i++) {
    // printf("%c", pass[i]);
  }

  // printf("|\n");
  for (int i = 0; i < keyLen; i++) {
    key[i] = keyInput[i];
  }

  if (keyLen > 128) {
    sha512(&key, keyLen, sha512_result);
    keyLen = 64;
    for (int i = 0; i < keyLen; i++) {
      key[i] = sha512_result[i];
    }
  }

  uchar ipad_key[128];
  uchar opad_key[128];
  for (int x = 0; x < 128; x++) {
    ipad_key[x] = 0x36;
    opad_key[x] = 0x5c;
  }

  for (int x = 0; x < keyLen; x++) {
    ipad_key[x] = ipad_key[x] ^ key[x];
    opad_key[x] = opad_key[x] ^ key[x];
  }

  uchar key_previous_concat[256] = {0};

  for (int x = 0; x < 128; x++) {
    key_previous_concat[x] = ipad_key[x];
  }
  for (int x = 0; x < passLen; x++) {
    key_previous_concat[x + 128] = pass[x];
  }
  sha512(&key_previous_concat, 128 + passLen, sha512_result);
  copy_pad_previous(&opad_key, sha512_result, &key_previous_concat);
  sha512(&key_previous_concat, 192, sha512_result);
}

// test function hmac_sha512
static void test_hmac_sha512() {
  uchar seeds[256] = "urban play middle desk reform ski yellow cram film "
                     "square garage describe fox melody amazing warm wedding "
                     "present deliver audit there focus machine agree";
  uchar pass[8] = "mnemonic";
  uchar seed[64] = {0};
  hmac_sha512(&seeds, 153, &pass, 8, &seed);
  print_seed(&seed);
}

static void PBKDF2(unsigned char *input_word, unsigned int input_word_len,
                   unsigned char *salt, unsigned int saltLen,
                   unsigned char *seed) {

  uchar key[256] = {0};
  uchar sha512_result[64] = {0};
  uchar tmp[64] = {0};

  int len = 155;

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

__kernel void just_seed(ulong mnemonic_start_hi, ulong mnemonic_start_lo,
                        __global uchar *target_mnemonic,
                        __global uchar *found_mnemonic) {
  ulong idx = get_global_id(0);

  // test_seed(&mnemonic, 77);

  // testHmac();
  // testHmac_long();
  // test_sha512(); //较短数据测试
  // test_sha512_long(&mnemonic, mnemonic_start_hi);
  // test_seed();
  test_PBKDF2();

  // test_hmac_sha512();
  // testSize();
}
