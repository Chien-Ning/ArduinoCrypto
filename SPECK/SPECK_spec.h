/*
 * SPECK_spec.h
 *
 * Created: Jan 14th, 2015
 *  Author: Chien-Ning CHEN

 1) read SPECK_AVR.h for how to use this SPECK implementation
 
 2) this file contain 


 * Chien-Ning CHEN
 * Physical Analysis and Cryptographic Engineering
 * Nanyang Technological University
 */


#ifndef SPECK_spec_H_
#define SPECK_spec_H_


// Speck 32/64: n = 16, m = 4, alpha = 7, beta = 2, T = 22
// Key: 1918 1110 0908 0100  --> k0 = 0x1918, l0 = 0x1110, l1 = 0x0908, l2 = 00100
// Plaintext:  6574 694c     --> x  = 0x6574,  y = 0x694c
// Ciphertext: a868 42f2
#define SpeckTestKey32x64  0x19, 0x18, 0x11, 0x10, 0x09, 0x08, 0x01, 0x00
#define SpeckTestTxt32x64  0x65, 0x74, 0x69, 0x4c

// Speck 48/72: n = 24, m = 3, alpha = 8, beta = 3, T = 22 
// Key: 121110 0a0908 020100
// Plaintext: 20796c 6c6172
// Ciphertext: c049a5 385adc
#define SpeckTestKey48x72  0x12, 0x11, 0x10, 0x0a, 0x09, 0x08, 0x02, 0x01, 0x00
#define SpeckTestTxt48x72  0x20, 0x79, 0x6c, 0x6c, 0x61, 0x72

// Speck 48/96: n = 24, m = 4, alpha = 8, beta = 3, T = 23
// Key: 1a1918 121110 0a0908 020100
// Plaintext: 6d2073 696874
// Ciphertext: 735e10 b6445d
#define SpeckTestKey48x96  0x1a, 0x19, 0x18, 0x12, 0x11, 0x10, 0x0a, 0x09, 0x08, 0x02, 0x01, 0x00
#define SpeckTestTxt48x96  0x6d, 0x20, 0x73, 0x69, 0x68, 0x74

// Speck 64/96: n = 32, m = 3, alpha = 8, beta = 3, T = 26
// Key: 13121110 0b0a0908 03020100
// Plaintext: 74614620 736e6165
// Ciphertext: 9f7952ec 4175946c
#define SpeckTestKey64x96  0x13, 0x12, 0x11, 0x10, 0x0b, 0x0a, 0x09, 0x08, \
                           0x03, 0x02, 0x01, 0x00
#define SpeckTestTxt64x96  0x74, 0x61, 0x46, 0x20, 0x73, 0x6e, 0x61, 0x65

// Speck 64/128: n = 32, m = 4, alpha = 8, beta = 3, T = 27
// Key: 1b1a1918 13121110 0b0a0908 03020100 
// Plaintext: 3b726574 7475432d
// Ciphertext: 8c6fa548 454e028b
#define SpeckTestKey64x128  0x1b, 0x1a, 0x19, 0x18, 0x13, 0x12, 0x11, 0x10, \
                            0x0b, 0x0a, 0x09, 0x08, 0x03, 0x02, 0x01, 0x00
#define SpeckTestTxt64x128  0x3b, 0x72, 0x65, 0x74, 0x74, 0x75, 0x43, 0x2d

// Speck 96/96: n = 48, m = 2, alpha = 8, beta = 3, T = 28
// Key: 0d0c0b0a0908 050403020100
// Plaintext: 65776f68202c 656761737520
// Ciphertext: 9e4d09ab7178 62bdde8f79aa
#define SpeckTestKey96x96  0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, \
                           0x05, 0x04, 0x03, 0x02, 0x01, 0x00
#define SpeckTestTxt96x96  0x65, 0x77, 0x6f, 0x68, 0x20, 0x2c, \
                           0x65, 0x67, 0x61, 0x73, 0x75, 0x20

// Speck 96/144: n = 48, m = 3, alpha = 8, beta = 3, T = 29
// Key: 151413121110 0d0c0b0a0908 050403020100
// Plaintext: 656d6974206e 69202c726576
// Ciphertext: 2bf31072228a 7ae440252ee6
#define SpeckTestKey96x144  0x15, 0x14, 0x13, 0x12, 0x11, 0x10, \
                            0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, \
                            0x05, 0x04, 0x03, 0x02, 0x01, 0x00
#define SpeckTestTxt96x144  0x65, 0x6d, 0x69, 0x74, 0x20, 0x6e, \
                            0x69, 0x20, 0x2c, 0x72, 0x65, 0x76

// Speck 128/128: n = 64, m = 2, alpha = 8, beta = 3, T = 32
// Key: 0f0e0d0c0b0a0908 0706050403020100
// Plaintext: 6c61766975716520 7469206564616d20
// Ciphertext: a65d985179783265 7860fedf5c570d18
#define SpeckTestKey128x128  0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, \
                             0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
#define SpeckTestTxt128x128  0x6c, 0x61, 0x76, 0x69, 0x75, 0x71, 0x65, 0x20, \
                             0x74, 0x69, 0x20, 0x65, 0x64, 0x61, 0x6d, 0x20

// Speck 128/192: n = 64, m = 3, alpha = 8, beta = 3, T = 33
// Key: 1716151413121110 0f0e0d0c0b0a0908 0706050403020100
// Plaintext: 7261482066656968 43206f7420746e65
// Ciphertext: 1be4cf3a13135566 f9bc185de03c1886
#define SpeckTestKey128x192  0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10, \
                             0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, \
                             0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
#define SpeckTestTxt128x192  0x72, 0x61, 0x48, 0x20, 0x66, 0x65, 0x69, 0x68, \
                             0x43, 0x20, 0x6f, 0x74, 0x20, 0x74, 0x6e, 0x65

// Speck 128/256: n = 64, m = 4, alpha = 8, beta = 3, T = 34
// Key: 1f1e1d1c1b1a1918 1716151413121110 0f0e0d0c0b0a0908 0706050403020100
// Plaintext: 65736f6874206e49 202e72656e6f6f70
// Ciphertext: 4109010405c0f53e 4eeeb48d9c188f43
#define SpeckTestKey128x256  0x1f, 0x1e, 0x1d, 0x1c, 0x1b, 0x1a, 0x19, 0x18, \
                             0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10, \
                             0x0f, 0x0e, 0x0d, 0x0c, 0x0b, 0x0a, 0x09, 0x08, \
                             0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00
#define SpeckTestTxt128x256  0x65, 0x73, 0x6f, 0x68, 0x74, 0x20, 0x6e, 0x49, \
                             0x20, 0x2e, 0x72, 0x65, 0x6e, 0x6f, 0x6f, 0x70

#define _SpeckTestTxt_(u,v)  SpeckTestTxt##u##x##v
#define _SpeckTestTxt(u,v)  _SpeckTestTxt_(u,v)
#define _SpeckTestKey_(u,v)  SpeckTestKey##u##x##v
#define _SpeckTestKey(u,v)  _SpeckTestKey_(u,v)


 // rounds T
#define SpeckT32x64  22
#define SpeckT48x72  22
#define SpeckT48x96  23
#define SpeckT64x96   26
#define SpeckT64x128  27
#define SpeckT96x96   28
#define SpeckT96x144  29
#define SpeckT128x128  32
#define SpeckT128x192  33
#define SpeckT128x256  34

#define _SpeckT_(u,v)  SpeckT##u##x##v
#define _SpeckT(u,v)  _SpeckT_(u,v)


// word size N
#define SpeckN32   16
#define SpeckN48   24
#define SpeckN64   32
#define SpeckN96   48
#define SpeckN128  64

#define _SpeckN_(u)  SpeckN##u
#define _SpeckN(u)  _SpeckN_(u)

#endif /* SPECK_spec_H_ */
