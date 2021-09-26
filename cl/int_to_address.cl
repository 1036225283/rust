

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
  print_seed(&seed); // ulong mnemonic_lo = mnemonic_start_lo + idx;
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

  // printf("\nmaster private key = \n");
  // for (int i = 0; i <= 32; i++) {
  //   printf("%x", master_private.private_key.key[i]);
  // }

  uchar pub_key[64] = {0};
  extended_private_key_t target_key;
  extended_public_key_t target_public_key;
  hardened_private_child_from_private(&master_private, &target_key, 44);
  hardened_private_child_from_private(&target_key, &target_key, 60);
  hardened_private_child_from_private(&target_key, &target_key, 0);
  normal_private_child_from_private(&target_key, &target_key, 0);
  normal_private_child_from_private(&target_key, &target_key, 0);
  public_from_private(&target_key, &target_public_key);
  for (int i = 0; i < 64; i++) {
    pub_key[i] = target_public_key.public_key.key.data[i];
  }
  // sha256(&pub_key, 64, &pub_key);

  printf("\n\n last public key = \n");

  for (int i = 0; i < 64; i++) {
    printf("%x,", pub_key[i]);
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
