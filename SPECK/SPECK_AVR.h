/*
 * SPECK_AVR.h
 *
 * Created: Jan 14th, 2015
 *  Author: Chien-Ning CHEN

 1) include this file (SPECK_AVR.h) to use this SPECK implementation 

 2) specify the block and key size by SpeckTxtLen and SpeckKeyLen
 3) store the plaintext followed by the key in the array speckTxtKey[]
    Ex: PlainText:     6574 694c
        Key:                                   1918 1110 0908 0100
        speckTxtKey[]: 0x65, 0x74, 0x69, 0x4c, 0x19, 0x18, 0x11, 0x10, 0x09, 0x08, 0x01, 0x00

 4) call speckKey ONCE to generate the round keys, 
    round keys will be stored in the same array (speckTxtKey[])
 5) call speckEnc to encrypt, the plaintext in speckTxtKey[] will be replaced by ciphertext

 6) SpeckTestTxt and SpeckTestKey are the test vector of plaintext and key 
    they will automatically map to the test vector according to the block and key size 


 *) speckEnc is implemented only in AVRASM
    speckKey is implemented in both AVRASM and C, 
    but the key length 48/64/128 of the implementation in C is not finished.
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^     

 * Chien-Ning CHEN
 * Physical Analysis and Cryptographic Engineering
 * Nanyang Technological University
 */


#ifndef SPECK_AVR_H_
#define SPECK_AVR_H_

#include<stdint.h>
#include "SPECK_spec.h"


#define SpeckTxtLen  96
#define SpeckKeyLen  144

#define KeyLan  AVRASM
#define EncLan  AVRASM


/* don't touch the code below                                                 */
/* -------------------------------------------------------------------------- */

extern uint8_t speckTxtKey[];

#define speckKey  _SpeckKey(SpeckN, KeyLan)
#define speckEnc  _SpeckEnc(SpeckN, EncLan)

#define SpeckN        _SpeckN(SpeckTxtLen)
#define SpeckM        (SpeckKeyLen / (SpeckTxtLen / 2))
#define SpeckT        _SpeckT(SpeckTxtLen, SpeckKeyLen)
#define SpeckTestTxt  _SpeckTestTxt(SpeckTxtLen, SpeckKeyLen)
#define SpeckTestKey  _SpeckTestKey(SpeckTxtLen, SpeckKeyLen)

#define _SpeckKey_(u,v)  SpeckKey##u##v
#define _SpeckKey(u,v)  _SpeckKey_(u,v)
#define _SpeckEnc_(u,v)  SpeckEnc##u##v
#define _SpeckEnc(u,v)  _SpeckEnc_(u,v)


// checking parameter (key length, txt length)
#if (SpeckTxtLen == 32)
  #if (SpeckKeyLen != 64)
    #error Incorrect Key Length (should be 64)
  #endif
  
#elif (SpeckTxtLen == 48)
  #if (SpeckKeyLen != 72) & (SpeckKeyLen != 96)
    #error Incorrect Key Length (should be 72 or 96)
  #endif
    
#elif (SpeckTxtLen == 64)
  #if (SpeckKeyLen != 96) & (SpeckKeyLen != 128)
    #error Incorrect Key Length (should be 96 or 128)
  #endif

#elif (SpeckTxtLen == 96)
  #if (SpeckKeyLen != 96) & (SpeckKeyLen != 144)
    #error Incorrect Key Length (should be 96 or 144)
  #endif

#elif (SpeckTxtLen == 128)
  #if (SpeckKeyLen != 128) & (SpeckKeyLen != 192) & (SpeckKeyLen != 256)
    #error Incorrect Key Length (should be one of 128, 192, and 256)
  #endif

#else
  #error Incorrect Text Length
#endif


void SpeckKey16C();
void SpeckKey24C();
void SpeckKey32C();
void SpeckKey48C();
void SpeckKey64C();

void SpeckKey16AVRASM() __attribute__ ((noinline, naked));
void SpeckKey24AVRASM() __attribute__ ((noinline, naked));
void SpeckKey32AVRASM() __attribute__ ((noinline, naked));
void SpeckKey48AVRASM() __attribute__ ((noinline, naked));
void SpeckKey64AVRASM() __attribute__ ((noinline, naked));

void SpeckEnc16AVRASM() __attribute__ ((noinline, naked));
void SpeckEnc24AVRASM() __attribute__ ((noinline, naked));
void SpeckEnc32AVRASM() __attribute__ ((noinline, naked));
void SpeckEnc48AVRASM() __attribute__ ((noinline, naked));
void SpeckEnc64AVRASM() __attribute__ ((noinline, naked));


#endif /* SPECK_AVR_H_ */
