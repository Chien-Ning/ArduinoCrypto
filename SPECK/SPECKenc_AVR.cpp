/*
 * SPECKenc_AVR.cpp
 *
 * Created: Jan 14th, 2015
 *  Author: Chien-Ning CHEN

 1) read SPECK_AVR.h for how to use this SPECK implementation


 * Chien-Ning CHEN
 * Physical Analysis and Cryptographic Engineering
 * Nanyang Technological University
 */


#include<stdint.h>
#include "SPECK_AVR.h"


uint8_t speckTxtKey[SpeckTxtLen/8 + SpeckTxtLen/16 * SpeckT] = {SpeckTestTxt, SpeckTestKey};


void __attribute__ ((noinline, naked)) SpeckEnc16AVRASM() {
asm volatile(
// r21:r20  speck-X (high 16 bits)
// r22:r21  speck-X with 7-bit right rotation (avoid real rotation)
//
// r19:r18  speck-Y (low  16 bits)
// r22      temp
// r23      number of rounds (SpeckT)

  "LDI r30, lo8(%[TxtKey])"  "\n\t"
  "LDI r31, hi8(%[TxtKey])"  "\n\t"  // Z -> speckTxtKey[]

  "LD r21, Z+"  "\n\t"  // load X, BIG endian
  "LD r20, Z+"  "\n\t"
  "LD r19, Z+"  "\n\t"  // load Y, BIG endian
  "LD r18, Z+"  "\n\t"

  "LDI r23, %[T]"  "\n\t"

"SpeckEnc16Loop%=:"
// 7-bit right rotation      c      r22      r21      r20
//                             ******** fedcba98 76543210 <-- x
  "MOV r22, r20"  "\n\t"  // ? 76543210 fedcba98 76543210
  "LSL r20"       "\n\t"  // 7 76543210 fedcba98 65432100
  "ROL r21"       "\n\t"  // f 76543210 edcba987 ********
  "ROL r22"       "\n\t"  // 7 6543210f edcba987 <-- x

// X = X + Y  
  "ADD r21, r18"  "\n\t"
  "ADC r22, r19"  "\n\t"

// XOR with round key, and 8-bit rotation, 
// round key is in LITTLE endian
//                      x = r22:r21 
//                           H   L   ?
  "LD  r20, Z+"   "\n\t"  //        r20
  "EOR r20, r21"  "\n\t"  // H   L   L*
  "LD  r21, Z+"   "\n\t"
  "EOR r21, r22"  "\n\t"  // H   H*  L*
//                          x = r21:r20

// 2-bit left rotation
  "LSL r18"  "\n\t"
  "ROL r19"  "\n\t"
  "ADC r18, __zero_reg__"  "\n\t"
  "LSL r18"  "\n\t"
  "ROL r19"  "\n\t"
  "ADC r18, __zero_reg__"  "\n\t"

// Y = Y XOR X  
  "EOR r19, r21"  "\n\t"
  "EOR r18, r20"  "\n\t"

// T rounds, r23 = T, T-1, ... ..., 1 
  "DEC r23"  "\n\t"
  "BRNE SpeckEnc16Loop%="  "\n\t"

  "LDI r30, lo8(%[TxtKey])"  "\n\t"
  "LDI r31, hi8(%[TxtKey])"  "\n\t"  // Z -> speckTxtKey[]

  "ST Z+, r21"  "\n\t"  // store X, BIG endian
  "ST Z+, r20"  "\n\t"
  "ST Z+, r19"  "\n\t"  // store Y, BIG endian
  "ST Z+, r18"  "\n\t"
  
  "RET"  "\n\t"
  : 
  : [T] "i" (SpeckT), 
    [TxtKey] "i" (speckTxtKey)
  : "cc", "memory"
);
}


void __attribute__ ((noinline, naked)) SpeckEnc24AVRASM() {
asm volatile(
// r24:r23:r22  speck-X (high 24 bits)
// r21:r24:r23  speck-X with 8-bit right rotation (avoid real rotation)
//
// r20:r19:r18  speck-Y (low  24 bits)
// r21      temp
// r25      number of rounds (SpeckT)

  "LDI r30, lo8(%[TxtKey])"  "\n\t"
  "LDI r31, hi8(%[TxtKey])"  "\n\t"  // Z -> speckTxtKey[]

  "LD r24, Z+"  "\n\t"  // load X, BIG endian
  "LD r23, Z+"  "\n\t"
  "LD r22, Z+"  "\n\t"
  "LD r20, Z+"  "\n\t"  // load Y, BIG endian
  "LD r19, Z+"  "\n\t"
  "LD r18, Z+"  "\n\t"

  "LDI r25, %[T]"  "\n\t"
  
"SpeckEnc24Loop%=:"
// 8-bit (1-byte) right rotation
//                           x = r24:r23:r22
//                                A   B   C
  "MOV r21, r22"  "\n\t"  //  C   A   B   C
//                       x = r21:r24:r23

// X = X + Y
  "ADD r23, r18"  "\n\t"
  "ADC r24, r19"  "\n\t"
  "ADC r21, r20"  "\n\t"
  
// XOR with round key, and 8-bit rotation, 
// round key is in LITTLE endian
//                      x = r21:r24:r23
//                           C   A   B   ?
  "LD  r22, Z+"   "\n\t"  //            r22
  "EOR r22, r23"  "\n\t"  // C   A   B   B*
  "LD  r23, Z+"   "\n\t"
  "EOR r23, r24"  "\n\t"  // C   A   A*  B*
  "LD  r24, Z+"   "\n\t"
  "EOR r24, r21"  "\n\t"  // C   C*  A*  B*
//                          x = r24:r23:r22

// 3-bit left rotation
  "LSL r18"  "\n\t"
  "ROL r19"  "\n\t"
  "ROL r20"  "\n\t"
  "ADC r18, __zero_reg__"  "\n\t"
  "LSL r18"  "\n\t"
  "ROL r19"  "\n\t"
  "ROL r20"  "\n\t"
  "ADC r18, __zero_reg__"  "\n\t"
  "LSL r18"  "\n\t"
  "ROL r19"  "\n\t"
  "ROL r20"  "\n\t"
  "ADC r18, __zero_reg__"  "\n\t"

// Y = Y XOR X
  "EOR r20, r24"  "\n\t"
  "EOR r19, r23"  "\n\t"
  "EOR r18, r22"  "\n\t"
  
// T rounds, r25 = T, T-1, ... ..., 1
  "DEC r25"  "\n\t"
  "BRNE SpeckEnc24Loop%="  "\n\t"
  
  "LDI r30, lo8(%[TxtKey])"  "\n\t"
  "LDI r31, hi8(%[TxtKey])"  "\n\t"  // Z -> speckTxtKey[]

  "ST Z+, r24"  "\n\t"  // store X, BIG endian
  "ST Z+, r23"  "\n\t"
  "ST Z+, r22"  "\n\t"
  "ST Z+, r20"  "\n\t"  // store Y, BIG endian
  "ST Z+, r19"  "\n\t"
  "ST Z+, r18"  "\n\t"

  "RET"  "\n\t"
  :
  : [T] "i" (SpeckT), 
    [TxtKey] "i" (speckTxtKey)
  : "cc", "memory"
);
}


void __attribute__ ((noinline, naked)) SpeckEnc32AVRASM() {
asm volatile(
// r25:r24:r23:r22  speck-X (high 32 bits)
// r26:r25:r24:r23  speck-X with 8-bit right rotation (avoid real rotation)
//
// r21:r20:r19:r18  speck-Y (low  32 bits)
// r26      temp
// r27      number of rounds (SpeckT)

  "LDI r30, lo8(%[TxtKey])"  "\n\t"
  "LDI r31, hi8(%[TxtKey])"  "\n\t"  // Z -> speckTxtKey[]

  "LD r25, Z+"  "\n\t"  // load X, BIG endian
  "LD r24, Z+"  "\n\t"
  "LD r23, Z+"  "\n\t"
  "LD r22, Z+"  "\n\t"
  "LD r21, Z+"  "\n\t"  // load Y, BIG endian
  "LD r20, Z+"  "\n\t"
  "LD r19, Z+"  "\n\t"
  "LD r18, Z+"  "\n\t"

  "LDI r27, %[T]"  "\n\t"
  
"SpeckEnc32Loop%=:"
// 8-bit (1-byte) right rotation
//                           x = r25:r24:r23:r22
//                                A   B   C   D
  "MOV r26, r22"  "\n\t"  //  D   A   B   C   D
//                       x = r26:r25:r24:r23

// X = X + Y
  "ADD r23, r18"  "\n\t"
  "ADC r24, r19"  "\n\t"
  "ADC r25, r20"  "\n\t"
  "ADC r26, r21"  "\n\t"
  
// XOR with round key, and 8-bit rotation, 
// round key is in LITTLE endian
//                      x = r26:r25:r24:r23
//                           D   A   B   C   ?
  "LD  r22, Z+"   "\n\t"  //                r22
  "EOR r22, r23"  "\n\t"  // D   A   B   C   C*
  "LD  r23, Z+"   "\n\t"
  "EOR r23, r24"  "\n\t"  // D   A   B   B*  C*
  "LD  r24, Z+"   "\n\t"
  "EOR r24, r25"  "\n\t"  // D   A   A*  B*  C*
  "LD  r25, Z+"   "\n\t"
  "EOR r25, r26"  "\n\t"  // D   F*  A*  B*  C*
//                          x = r25:r24:r23:r22

// 3-bit left rotation
  "LSL r18"  "\n\t"
  "ROL r19"  "\n\t"
  "ROL r20"  "\n\t"
  "ROL r21"  "\n\t"
  "ADC r18, __zero_reg__"  "\n\t"
  "LSL r18"  "\n\t"
  "ROL r19"  "\n\t"
  "ROL r20"  "\n\t"
  "ROL r21"  "\n\t"
  "ADC r18, __zero_reg__"  "\n\t"
  "LSL r18"  "\n\t"
  "ROL r19"  "\n\t"
  "ROL r20"  "\n\t"
  "ROL r21"  "\n\t"
  "ADC r18, __zero_reg__"  "\n\t"

// Y = Y XOR X
  "EOR r21, r25"  "\n\t"
  "EOR r20, r24"  "\n\t"
  "EOR r19, r23"  "\n\t"
  "EOR r18, r22"  "\n\t"
  
// T rounds, r27 = T, T-1, ... ..., 1
  "DEC r27"  "\n\t"
  "BRNE SpeckEnc32Loop%="  "\n\t"
  
  "LDI r30, lo8(%[TxtKey])"  "\n\t"
  "LDI r31, hi8(%[TxtKey])"  "\n\t"  // Z -> speckTxtKey[]

  "ST Z+, r25"  "\n\t"  // store X, BIG endian
  "ST Z+, r24"  "\n\t"
  "ST Z+, r23"  "\n\t"
  "ST Z+, r22"  "\n\t"
  "ST Z+, r21"  "\n\t"  // store Y, BIG endian
  "ST Z+, r20"  "\n\t"
  "ST Z+, r19"  "\n\t"
  "ST Z+, r18"  "\n\t"

  "RET"  "\n\t"
  :
  : [T] "i" (SpeckT), 
    [TxtKey] "i" (speckTxtKey)
  : "cc", "memory"
);
}


void __attribute__ ((noinline, naked)) SpeckEnc48AVRASM() {
asm volatile(
  "PUSH r17"  "\n\t"
  "PUSH r16"  "\n\t"
  "PUSH r15"  "\n\t"
  "PUSH r14"  "\n\t"
// r25:r24:r23:r22:r21:r20  speck-X (high 48 bits)
// r26:r25:r24:r23:r22:r21  speck-X with 8-bit right rotation (avoid real rotation)
//
// r19:r18:r17:r16:r15:r14  speck-Y (low  48 bits)
// r26      temp
// r27      number of rounds (SpeckT)
  
  "LDI r30, lo8(%[TxtKey])"  "\n\t"
  "LDI r31, hi8(%[TxtKey])"  "\n\t"  // Z -> speckTxtKey[]

  "LD r25, Z+"  "\n\t"  // load X, BIG endian
  "LD r24, Z+"  "\n\t"
  "LD r23, Z+"  "\n\t"
  "LD r22, Z+"  "\n\t"
  "LD r21, Z+"  "\n\t"
  "LD r20, Z+"  "\n\t"
  "LD r19, Z+"  "\n\t"  // load Y, BIG endian
  "LD r18, Z+"  "\n\t"
  "LD r17, Z+"  "\n\t"
  "LD r16, Z+"  "\n\t"
  "LD r15, Z+"  "\n\t"
  "LD r14, Z+"  "\n\t"

  "LDI r27, %[T]"  "\n\t"

"SpeckEnc48Loop%=:"
// 8-bit (1-byte) right rotation
//                           x = r25:r24:r23:r22:r21:r20
//                                A   B   C   D   E   F
  "MOV r26, r20"  "\n\t"  //  F   A   B   C   D   E   F
//                       x = r26:r25:r24:r23:r22:r21

// X = X + Y
  "ADD r21, r14"  "\n\t"
  "ADC r22, r15"  "\n\t"
  "ADC r23, r16"  "\n\t"
  "ADC r24, r17"  "\n\t"
  "ADC r25, r18"  "\n\t"
  "ADC r26, r19"  "\n\t"

// XOR with round key, and 8-bit rotation, 
// round key is in LITTLE endian
//                      x = r26:r25:r24:r23:r22:r21
//                           F   A   B   C   D   E   ?
  "LD  r20, Z+"   "\n\t"  //                        r20
  "EOR r20, r21"  "\n\t"  // F   A   B   C   D   E   E*
  "LD  r21, Z+"   "\n\t"
  "EOR r21, r22"  "\n\t"  // F   A   B   C   D   D*  E*
  "LD  r22, Z+"   "\n\t"
  "EOR r22, r23"  "\n\t"  // F   A   B   C   C*  D*  E*
  "LD  r23, Z+"   "\n\t"
  "EOR r23, r24"  "\n\t"  // F   A   B   B*  C*  D*  E*
  "LD  r24, Z+"   "\n\t"
  "EOR r24, r25"  "\n\t"  // F   A   A*  B*  C*  D*  E*
  "LD  r25, Z+"   "\n\t"
  "EOR r25, r26"  "\n\t"  // F   F*  A*  B*  C*  D*  E*
//                          x = r25:r24:r23:r22:r21:r20

// 3-bit left rotation
  "LSL r14"  "\n\t"
  "ROL r15"  "\n\t"
  "ROL r16"  "\n\t"
  "ROL r17"  "\n\t"
  "ROL r18"  "\n\t"
  "ROL r19"  "\n\t"
  "ADC r14, __zero_reg__"  "\n\t"
  "LSL r14"  "\n\t"
  "ROL r15"  "\n\t"
  "ROL r16"  "\n\t"
  "ROL r17"  "\n\t"
  "ROL r18"  "\n\t"
  "ROL r19"  "\n\t"
  "ADC r14, __zero_reg__"  "\n\t"
  "LSL r14"  "\n\t"
  "ROL r15"  "\n\t"
  "ROL r16"  "\n\t"
  "ROL r17"  "\n\t"
  "ROL r18"  "\n\t"
  "ROL r19"  "\n\t"
  "ADC r14, __zero_reg__"  "\n\t"

// Y = Y XOR X
  "EOR r19, r25"  "\n\t"
  "EOR r18, r24"  "\n\t"
  "EOR r17, r23"  "\n\t"
  "EOR r16, r22"  "\n\t"
  "EOR r15, r21"  "\n\t"
  "EOR r14, r20"  "\n\t"
  
// T rounds, r27 = T, T-1, ... ..., 1
  "DEC r27"  "\n\t"
  "BRNE SpeckEnc48Loop%="  "\n\t"

  "LDI r30, lo8(%[TxtKey])"  "\n\t"
  "LDI r31, hi8(%[TxtKey])"  "\n\t"  // Z -> speckTxtKey[]
  
  "ST Z+, r25"  "\n\t"  // store X, BIG endian
  "ST Z+, r24"  "\n\t"
  "ST Z+, r23"  "\n\t"
  "ST Z+, r22"  "\n\t"
  "ST Z+, r21"  "\n\t"
  "ST Z+, r20"  "\n\t"
  "ST Z+, r19"  "\n\t"  // store Y, BIG endian
  "ST Z+, r18"  "\n\t"
  "ST Z+, r17"  "\n\t"
  "ST Z+, r16"  "\n\t"
  "ST Z+, r15"  "\n\t"
  "ST Z+, r14"  "\n\t"
  
  "POP r14"  "\n\t"
  "POP r15"  "\n\t"
  "POP r16"  "\n\t"
  "POP r17"  "\n\t"
  "RET"  "\n\t"
  :
  : [T] "i" (SpeckT), 
    [TxtKey] "i" (speckTxtKey)
  : "cc", "memory"
);
}


void __attribute__ ((noinline, naked)) SpeckEnc64AVRASM() {
asm volatile(
  "PUSH r17"  "\n\t"
  "PUSH r16"  "\n\t"
  "PUSH r15"  "\n\t"
  "PUSH r14"  "\n\t"
  "PUSH r13"  "\n\t"
  "PUSH r12"  "\n\t"
  "PUSH r11"  "\n\t"
  "PUSH r10"  "\n\t"
// r25:r24:r23:r22:r21:r20:r19:r18  speck-X (high 64 bits)
// r26:r25:r24:r23:r22:r21:r20:r19  speck-X with 8-bit right rotation (avoid real rotation)
//
// r17:r16:r15:r14:r13:r12:r11:r10  speck-Y (low  64 bits)
// r26      temp
// r27      number of rounds (SpeckT)
  
  "LDI r30, lo8(%[TxtKey])"  "\n\t"
  "LDI r31, hi8(%[TxtKey])"  "\n\t"  // Z -> speckTxtKey[]

  "LD r25, Z+"  "\n\t"  // load X, BIG endian
  "LD r24, Z+"  "\n\t"
  "LD r23, Z+"  "\n\t"
  "LD r22, Z+"  "\n\t"
  "LD r21, Z+"  "\n\t"
  "LD r20, Z+"  "\n\t"
  "LD r19, Z+"  "\n\t"
  "LD r18, Z+"  "\n\t"
  "LD r17, Z+"  "\n\t"  // load Y, BIG endian
  "LD r16, Z+"  "\n\t"
  "LD r15, Z+"  "\n\t"
  "LD r14, Z+"  "\n\t"
  "LD r13, Z+"  "\n\t"
  "LD r12, Z+"  "\n\t"
  "LD r11, Z+"  "\n\t"
  "LD r10, Z+"  "\n\t"

  "LDI r27, %[T]"  "\n\t"
  
"SpeckEnc64Loop%=:"
// 8-bit (1-byte) right rotation
//                           x = r25:r24:r23:r22:r21:r20:r19:r18
//                                A   B   C   D   E   F   G   H
  "MOV r26, r18"  "\n\t"  //  H   A   B   C   D   E   F   G   H
//                       x = r26:r25:r24:r23:r22:r21:r20:r19
  
// X = X + Y
  "ADD r19, r10"  "\n\t"
  "ADC r20, r11"  "\n\t"
  "ADC r21, r12"  "\n\t"
  "ADC r22, r13"  "\n\t"
  "ADC r23, r14"  "\n\t"
  "ADC r24, r15"  "\n\t"
  "ADC r25, r16"  "\n\t"
  "ADC r26, r17"  "\n\t"

// XOR with round key, and 8-bit rotation, 
// round key is in LITTLE endian
//                      x = r26:r25:r24:r23:r22:r21:r20:r19 
//                           H   A   B   C   D   E   F   G   ?
  "LD  r18, Z+"   "\n\t"  //                                r18
  "EOR r18, r19"  "\n\t"  // H   A   B   C   D   E   F   G   G*
  "LD  r19, Z+"   "\n\t"
  "EOR r19, r20"  "\n\t"  // H   A   B   C   D   E   F   F*  G*
  "LD  r20, Z+"   "\n\t"
  "EOR r20, r21"  "\n\t"  // H   A   B   C   D   E   E*  F*  G*
  "LD  r21, Z+"   "\n\t"
  "EOR r21, r22"  "\n\t"  // H   A   B   C   D   D*  E*  F*  G*
  "LD  r22, Z+"   "\n\t"
  "EOR r22, r23"  "\n\t"  // H   A   B   C   C*  D*  E*  F*  G*
  "LD  r23, Z+"   "\n\t"
  "EOR r23, r24"  "\n\t"  // H   A   B   B*  C*  D*  E*  F*  G*
  "LD  r24, Z+"   "\n\t"
  "EOR r24, r25"  "\n\t"  // H   A   A*  B*  C*  D*  E*  F*  G*
  "LD  r25, Z+"   "\n\t"
  "EOR r25, r26"  "\n\t"  // H   H*  A*  B*  C*  D*  E*  F*  G*
//                          x = r25:r24:r23:r22:r21:r20:r19:r18

// 3-bit left rotation
  "LSL r10"  "\n\t"
  "ROL r11"  "\n\t"
  "ROL r12"  "\n\t"
  "ROL r13"  "\n\t"
  "ROL r14"  "\n\t"
  "ROL r15"  "\n\t"
  "ROL r16"  "\n\t"
  "ROL r17"  "\n\t"
  "ADC r10, __zero_reg__"  "\n\t"
  "LSL r10"  "\n\t"
  "ROL r11"  "\n\t"
  "ROL r12"  "\n\t"
  "ROL r13"  "\n\t"
  "ROL r14"  "\n\t"
  "ROL r15"  "\n\t"
  "ROL r16"  "\n\t"
  "ROL r17"  "\n\t"
  "ADC r10, __zero_reg__"  "\n\t"
  "LSL r10"  "\n\t"
  "ROL r11"  "\n\t"
  "ROL r12"  "\n\t"
  "ROL r13"  "\n\t"
  "ROL r14"  "\n\t"
  "ROL r15"  "\n\t"
  "ROL r16"  "\n\t"
  "ROL r17"  "\n\t"
  "ADC r10, __zero_reg__"  "\n\t"

// Y = Y XOR X
  "EOR r17, r25"  "\n\t"
  "EOR r16, r24"  "\n\t"
  "EOR r15, r23"  "\n\t"
  "EOR r14, r22"  "\n\t"
  "EOR r13, r21"  "\n\t"
  "EOR r12, r20"  "\n\t"
  "EOR r11, r19"  "\n\t"
  "EOR r10, r18"  "\n\t"
  
// T rounds, r27 = T, T-1, ... ..., 1
  "DEC r27"  "\n\t"
  "BRNE SpeckEnc64Loop%="  "\n\t"
  
  "LDI r30, lo8(%[TxtKey])"  "\n\t"
  "LDI r31, hi8(%[TxtKey])"  "\n\t"  // Z -> speckTxtKey[]
  
  "ST Z+, r25"  "\n\t"  // store X, BIG endian
  "ST Z+, r24"  "\n\t"
  "ST Z+, r23"  "\n\t"
  "ST Z+, r22"  "\n\t"
  "ST Z+, r21"  "\n\t"
  "ST Z+, r20"  "\n\t"
  "ST Z+, r19"  "\n\t"
  "ST Z+, r18"  "\n\t"
  "ST Z+, r17"  "\n\t"  // store Y, BIG endian
  "ST Z+, r16"  "\n\t"
  "ST Z+, r15"  "\n\t"
  "ST Z+, r14"  "\n\t"
  "ST Z+, r13"  "\n\t"
  "ST Z+, r12"  "\n\t"
  "ST Z+, r11"  "\n\t"
  "ST Z+, r10"  "\n\t"

  "POP r10"  "\n\t"
  "POP r11"  "\n\t"
  "POP r12"  "\n\t"
  "POP r13"  "\n\t"
  "POP r14"  "\n\t"
  "POP r15"  "\n\t"
  "POP r16"  "\n\t"
  "POP r17"  "\n\t"
  "RET"  "\n\t"
  :
  : [T] "i" (SpeckT), 
    [TxtKey] "i" (speckTxtKey)
  : "cc", "memory"
);
}
