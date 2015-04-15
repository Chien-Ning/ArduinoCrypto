/*
 * SPECKkey_C.cpp
 *
 * Created: Jan 15th, 2015
 *  Author: Chien-Ning CHEN

 1) read SPECK_AVR.h for how to use this SPECK implementation

 2) 

 * Chien-Ning CHEN
 * Physical Analysis and Cryptographic Engineering
 * Nanyang Technological University
 */


#include<stdint.h>
#include "SPECK_AVR.h"


// n = 16, m = 4
void SpeckKey16C() {
  uint16_t speckTemp[SpeckT + SpeckM - 2];
  uint16_t L, K;
  
  speckTemp[2] =  (uint16_t) speckTxtKey[4] << 8;  // L2
  speckTemp[2] += speckTxtKey[5];
  speckTemp[1] =  (uint16_t) speckTxtKey[6] << 8;  // L1
  speckTemp[1] += speckTxtKey[7];
  speckTemp[0] =  (uint16_t) speckTxtKey[8] << 8;  // L0
  speckTemp[0] += speckTxtKey[9];
  
  speckTxtKey[5] = speckTxtKey[10];  // BIG -> LITTLE endian
  speckTxtKey[4] = speckTxtKey[11];
  
  K =   speckTxtKey[5];
  K <<= 8;
  K +=  speckTxtKey[4];

  for (int i = 0; i < SpeckT - 1; i++) {
    L =  (speckTemp[i] >> 7) | (speckTemp[i] << 9);
    L += K;
    L ^= (uint16_t) i;
    
    speckTemp[i + SpeckM - 1] = L;
    K = (K << 2) | (K >> 14);
    K ^= L;
    
    speckTxtKey[7 + 2*i] = (uint8_t) (K >> 8);
    speckTxtKey[6 + 2*i] = (uint8_t) (K & 0xff);
  }
}


void SpeckKey24C() {
}


void SpeckKey32C() {
}


// n = 48, m = 2 or 3
void SpeckKey48C() {
  uint64_t speckTemp[(SpeckT + SpeckM - 2)];
  uint64_t L, K;

  uint8_t i = SpeckM - 1;
  uint8_t j = 12;  // SpeckTxtLen / 8;

  while (i) {
    i--;
      
    speckTemp[i] =  (uint64_t) speckTxtKey[j++] << 40;  // L1 then L0, or L0 only
    speckTemp[i] += (uint64_t) speckTxtKey[j++] << 32;
    speckTemp[i] += (uint64_t) speckTxtKey[j++] << 24;
    speckTemp[i] += (uint64_t) speckTxtKey[j++] << 16;
    speckTemp[i] += (uint64_t) speckTxtKey[j++] << 8;
    speckTemp[i] += (uint64_t) speckTxtKey[j++];
  }
  
  speckTxtKey[17] = speckTxtKey[j++];  // BIG -> LITTLE endian
  speckTxtKey[16] = speckTxtKey[j++];
  speckTxtKey[15] = speckTxtKey[j++];
  speckTxtKey[14] = speckTxtKey[j++];
  speckTxtKey[13] = speckTxtKey[j++];
  speckTxtKey[12] = speckTxtKey[j++];
  
  K =  speckTxtKey[17];
  K <<= 8;
  K += speckTxtKey[16];
  K <<= 8;
  K += speckTxtKey[15];
  K <<= 8;
  K += speckTxtKey[14];
  K <<= 8;
  K += speckTxtKey[13];
  K <<= 8;
  K += speckTxtKey[12];

  for (int i = 0; i < SpeckT - 1; i++) {
    L = speckTemp[i];
    L = (L >> 8) | ((L & 0xff) << 40);
    L += K;
    L &= 0x0000ffffffffffff;
    L ^= (uint64_t) i;
    
    speckTemp[i + SpeckM - 1] = L;
    K = ((K << 3) & 0x0000ffffffffffff) | (K >> 45);

    K ^= L;
    
    // k[i+1]
    speckTxtKey[23 + 6*i] = (uint8_t) (K >> 40);
    speckTxtKey[22 + 6*i] = (uint8_t) (K >> 32);
    speckTxtKey[21 + 6*i] = (uint8_t) (K >> 24);
    speckTxtKey[20 + 6*i] = (uint8_t) (K >> 16);
    speckTxtKey[19 + 6*i] = (uint8_t) (K >> 8);
    speckTxtKey[18 + 6*i] = (uint8_t) K;
  }
}


void SpeckKey64C() {
}


