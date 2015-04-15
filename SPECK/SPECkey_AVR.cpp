/*
 * SPECKkey_AVR.cpp
 *
 * Created: Jan 15th, 2015
 *  Author: Chien-Ning CHEN

 1) read SPECK_AVR.h for how to use this SPECK implementation

 2) the input key, L2:L1:L0:K0 (m=4) / L1:L0:K0 (m=3) / L0:K0 (m=2), should be stored 
    in speckTxtKey[] after the reserved space of plaintext/ciphertext (i.e., block size 2n / 8).
    the input key is stored in BIG endian
 3) after the round key function, the round key (K0, K1, K2, ......) 
    will be stored in speckTxtKey[] after the reserved space of plaintext / chipertext
    (i.e., the original input key will be overwritten)
    each of the round key is stored in LITTLE endian  (to optimize the encryption function)
 4) the round key function will automatically consider the key words m, 
    e.g, SpeckKey64AVRASM() for all of SPECK 128/128, 128/192, 128/256

 * Chien-Ning CHEN
 * Physical Analysis and Cryptographic Engineering
 * Nanyang Technological University
 */
 

#include<stdint.h>
#include "SPECK_AVR.h"

uint8_t SpeckL[(SpeckM - 1) * (SpeckN / 8)];


// n = 16, m = 4
void __attribute__ ((noinline, naked)) SpeckKey16AVRASM() {
asm volatile(
// r21:r20  L[i] (or L[i + M-1]
// r19:r18  K[i]
// r25  counter

  "LDI r26, lo8(%[TxtKeyX])"  "\n\t"
  "LDI r27, hi8(%[TxtKeyX])"  "\n\t"
  "LDI r30, lo8(%[L])"  "\n\t"
  "LDI r31, hi8(%[L])"  "\n\t"

// load K[0], BIG endian  
  "LD r18, -X"  "\n\t"
  "LD r19, -X"  "\n\t"

  "LDI r25, %[M1]"  "\n\t"
"SpeckKey16LoopA%=:"  // counter = M-1, ..., 1
// load L[0] ~ L[m-2] from speckTxtKey, BIG endian
  "LD r20, -X"  "\n\t"  
  "LD r21, -X"  "\n\t"

// store L[0] ~ L[m-2] to SpeckL, LITTLE endian
  "ST Z+, r20"  "\n\t"
  "ST Z+, r21"  "\n\t"

  "DEC r25"  "\n\t"
  "BRNE SpeckKey16LoopA%="  "\n\t"

// store K[0] to TxtKey[12 ~ 17], LITTLE endian
  "ST X+, r18"  "\n\t"
  "ST X+, r19"  "\n\t"

//  "EOR r25, r25"  "\n\t"  // r25 should be 0 here
"SpeckKey16LoopB%=:"  // counter = 0, ..., T-2
  "CPI r30, lo8(%[LX])"  "\n\t"  // only compare low byte, because size of L = 6 bytes
  "BRNE SpeckKey16LoopBx%="  "\n\t"
  "LDI r30, lo8(%[L])"  "\n\t"   // back to L[0]
  "LDI r31, hi8(%[L])"  "\n\t"

"SpeckKey16LoopBx%=:"
// load L[i mod (m-1)] with 8-bit right rotation
  "LDD r21, Z+0"  "\n\t"
  "LDD r20, Z+1"  "\n\t"

// 1-bit left rotation
  "LSL r20"  "\n\t"
  "ROL r21"  "\n\t"
  "ADC r20, __zero_reg__"  "\n\t"
  
// L[i] += K[i]
  "ADD r20, r18"  "\n\t"
  "ADC r21, r19"  "\n\t"

// L[i] ^= i
  "EOR r20, r25"  "\n\t"

// store L[i mod (m-1)]
  "ST Z+, r20"  "\n\t"
  "ST Z+, r21"  "\n\t"

// 2-bit left rotation K[i]
  "LSL r18"  "\n\t"
  "ROL r19"  "\n\t"
  "ADC r18, __zero_reg__"  "\n\t"
  "LSL r18"  "\n\t"
  "ROL r19"  "\n\t"
  "ADC r18, __zero_reg__"  "\n\t"

// K ^= L
  "EOR r19, r21"  "\n\t"
  "EOR r18, r20"  "\n\t"

// store K[i], LITTLE endian
  "ST X+, r18"  "\n\t"
  "ST X+, r19"  "\n\t"

  "INC r25"  "\n\t"
  "CPI r25, %[T1]"  "\n\t"
  "BRCS SpeckKey16LoopB%="  "\n\t"

  "RET"  "\n\t"
  :
  : [T] "i" (SpeckT), 
    [T1] "i" (SpeckT - 1),
    [M1] "i" (SpeckM - 1), 
    [TxtKey] "i" (speckTxtKey), 
    [TxtKeyX] "i" (speckTxtKey + (SpeckM+2)*2),
    [L] "i" (SpeckL), 
    [LX] "i" (SpeckL + (SpeckM-1)*2)
  : "cc", "memory"
);
}


// n = 24, m = 3 or 4
void __attribute__ ((noinline, naked)) SpeckKey24AVRASM() {
asm volatile(
// r24:r23:r22  L[i] (or L[i + M-1]
// r20:r19:r18  K[i]
// r25  counter

  "LDI r26, lo8(%[TxtKeyX])"  "\n\t"
  "LDI r27, hi8(%[TxtKeyX])"  "\n\t"
  "LDI r30, lo8(%[L])"  "\n\t"
  "LDI r31, hi8(%[L])"  "\n\t"

// load K[0], BIG endian  
  "LD r18, -X"  "\n\t"
  "LD r19, -X"  "\n\t"
  "LD r20, -X"  "\n\t"

  "LDI r25, %[M1]"  "\n\t"
"SpeckKey24LoopA%=:"  // counter = M-1, ..., 1
// load L[0] ~ L[m-2] from speckTxtKey, BIG endian
  "LD r22, -X"  "\n\t"  
  "LD r23, -X"  "\n\t"  
  "LD r24, -X"  "\n\t"

// store L[0] ~ L[m-2] to SpeckL, LITTLE endian
  "ST Z+, r22"  "\n\t"
  "ST Z+, r23"  "\n\t"
  "ST Z+, r24"  "\n\t"

  "DEC r25"  "\n\t"
  "BRNE SpeckKey24LoopA%="  "\n\t"

// store K[0] to TxtKey[12 ~ 17], LITTLE endian
  "ST X+, r18"  "\n\t"
  "ST X+, r19"  "\n\t"
  "ST X+, r20"  "\n\t"

//  "EOR r25, r25"  "\n\t"  // r25 should be 0 here
"SpeckKey24LoopB%=:"  // counter = 0, ..., T-2
  "CPI r30, lo8(%[LX])"  "\n\t"  // only compare low byte, because size of L <= 9 bytes
  "BRNE SpeckKey24LoopBx%="  "\n\t"
  "LDI r30, lo8(%[L])"  "\n\t"   // back to L[0]
  "LDI r31, hi8(%[L])"  "\n\t"

"SpeckKey24LoopBx%=:"
// load L[i mod (m-1)] with 8-bit right rotation
  "LDD r24, Z+0"  "\n\t"
  "LDD r22, Z+1"  "\n\t"
  "LDD r23, Z+2"  "\n\t"

// L[i] += K[i]
  "ADD r22, r18"  "\n\t"
  "ADC r23, r19"  "\n\t"
  "ADC r24, r20"  "\n\t"

// L[i] ^= i
  "EOR r22, r25"  "\n\t"

// store L[i mod (m-1)]
  "ST Z+, r22"  "\n\t"
  "ST Z+, r23"  "\n\t"
  "ST Z+, r24"  "\n\t"

// 3-bit left rotation K[i]
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

// K ^= L
  "EOR r20, r24"  "\n\t"
  "EOR r19, r23"  "\n\t"
  "EOR r18, r22"  "\n\t"

// store K[i], LITTLE endian
  "ST X+, r18"  "\n\t"
  "ST X+, r19"  "\n\t"
  "ST X+, r20"  "\n\t"

  "INC r25"  "\n\t"
  "CPI r25, %[T1]"  "\n\t"
  "BRCS SpeckKey24LoopB%="  "\n\t"

  "RET"  "\n\t"
  :
  : [T] "i" (SpeckT), 
    [T1] "i" (SpeckT - 1),
    [M1] "i" (SpeckM - 1), 
    [TxtKey] "i" (speckTxtKey), 
    [TxtKeyX] "i" (speckTxtKey + (SpeckM+2)*3),
    [L] "i" (SpeckL), 
    [LX] "i" (SpeckL + (SpeckM-1)*3)
  : "cc", "memory"
);
}


// n = 32, m = 3 or 4
void __attribute__ ((noinline, naked)) SpeckKey32AVRASM() {
asm volatile(
  "PUSH r29"  "\n\t"

// r25:r24:r23:r22  L[i] (or L[i + M-1]
// r21:r20:r19:r18  K[i]
// r29  counter

  "LDI r26, lo8(%[TxtKeyX])"  "\n\t"
  "LDI r27, hi8(%[TxtKeyX])"  "\n\t"
  "LDI r30, lo8(%[L])"  "\n\t"
  "LDI r31, hi8(%[L])"  "\n\t"

// load K[0], BIG endian  
  "LD r18, -X"  "\n\t"
  "LD r19, -X"  "\n\t"
  "LD r20, -X"  "\n\t"
  "LD r21, -X"  "\n\t"

  "LDI r29, %[M1]"  "\n\t"
"SpeckKey32LoopA%=:"  // counter = M-1, ..., 1
// load L[0] ~ L[m-2] from speckTxtKey, BIG endian
  "LD r22, -X"  "\n\t"  
  "LD r23, -X"  "\n\t"  
  "LD r24, -X"  "\n\t"
  "LD r25, -X"  "\n\t"  

// store L[0] ~ L[m-2] to SpeckL, LITTLE endian
  "ST Z+, r22"  "\n\t"
  "ST Z+, r23"  "\n\t"
  "ST Z+, r24"  "\n\t"
  "ST Z+, r25"  "\n\t"

  "DEC r29"  "\n\t"
  "BRNE SpeckKey32LoopA%="  "\n\t"

// store K[0] to TxtKey[12 ~ 17], LITTLE endian
  "ST X+, r18"  "\n\t"
  "ST X+, r19"  "\n\t"
  "ST X+, r20"  "\n\t"
  "ST X+, r21"  "\n\t"  


//  "EOR r29, r29"  "\n\t"  // r29 should be 0 here
"SpeckKey32LoopB%=:"  // counter = 0, ..., T-2
  "CPI r30, lo8(%[LX])"  "\n\t"  // only compare low byte, because size of L <= 12 bytes
  "BRNE SpeckKey32LoopBx%="  "\n\t"
  "LDI r30, lo8(%[L])"  "\n\t"   // back to L[0]
  "LDI r31, hi8(%[L])"  "\n\t"

"SpeckKey32LoopBx%=:"
// load L[i mod (m-1)] with 8-bit right rotation
  "LDD r25, Z+0"  "\n\t"
  "LDD r22, Z+1"  "\n\t"
  "LDD r23, Z+2"  "\n\t"
  "LDD r24, Z+3"  "\n\t"

// L[i] += K[i]
  "ADD r22, r18"  "\n\t"
  "ADC r23, r19"  "\n\t"
  "ADC r24, r20"  "\n\t"
  "ADC r25, r21"  "\n\t"

// L[i] ^= i
  "EOR r22, r29"  "\n\t"

// store L[i mod (m-1)]
  "ST Z+, r22"  "\n\t"
  "ST Z+, r23"  "\n\t"
  "ST Z+, r24"  "\n\t"
  "ST Z+, r25"  "\n\t"

// 3-bit left rotation K[i]
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

// K ^= L
  "EOR r21, r25"  "\n\t"
  "EOR r20, r24"  "\n\t"
  "EOR r19, r23"  "\n\t"
  "EOR r18, r22"  "\n\t"

// store K[i], LITTLE endian
  "ST X+, r18"  "\n\t"
  "ST X+, r19"  "\n\t"
  "ST X+, r20"  "\n\t"
  "ST X+, r21"  "\n\t"

  "INC r29"  "\n\t"
  "CPI r29, %[T1]"  "\n\t"
  "BRCS SpeckKey32LoopB%="  "\n\t"

  "POP r29"  "\n\t"
  "RET"  "\n\t"
  :
  : [T] "i" (SpeckT), 
    [T1] "i" (SpeckT - 1),
    [M1] "i" (SpeckM - 1), 
    [TxtKey] "i" (speckTxtKey), 
    [TxtKeyX] "i" (speckTxtKey + (SpeckM+2)*4),
    [L] "i" (SpeckL), 
    [LX] "i" (SpeckL + (SpeckM-1)*4)
  : "cc", "memory"
);
}


// n = 48, m = 2 or 3
void __attribute__ ((noinline, naked)) SpeckKey48AVRASM() {
asm volatile(
  "PUSH r29"  "\n\t"

  "PUSH r17"  "\n\t"
  "PUSH r16"  "\n\t"
  "PUSH r15"  "\n\t"
  "PUSH r14"  "\n\t"
// r25:r24:r23:r22:r21:r20  L[i] (or L[i + M-1]
// r19:r18:r17:r16:r15:r14  K[i]
// r29  counter

  "LDI r26, lo8(%[TxtKeyX])"  "\n\t"
  "LDI r27, hi8(%[TxtKeyX])"  "\n\t"
  "LDI r30, lo8(%[L])"  "\n\t"
  "LDI r31, hi8(%[L])"  "\n\t"

// load K[0], BIG endian  
  "LD r14, -X"  "\n\t"
  "LD r15, -X"  "\n\t"
  "LD r16, -X"  "\n\t"
  "LD r17, -X"  "\n\t"
  "LD r18, -X"  "\n\t"
  "LD r19, -X"  "\n\t"

  "LDI r29, %[M1]"  "\n\t"
"SpeckKey48LoopA%=:"  // counter = M-1, ..., 1
// load L[0] ~ L[m-2] from speckTxtKey, BIG endian
  "LD r20, -X"  "\n\t"  
  "LD r21, -X"  "\n\t"  
  "LD r22, -X"  "\n\t"  
  "LD r23, -X"  "\n\t"  
  "LD r24, -X"  "\n\t"
  "LD r25, -X"  "\n\t"  

// store L[0] ~ L[m-2] to SpeckL, LITTLE endian
  "ST Z+, r20"  "\n\t"
  "ST Z+, r21"  "\n\t"
  "ST Z+, r22"  "\n\t"
  "ST Z+, r23"  "\n\t"
  "ST Z+, r24"  "\n\t"
  "ST Z+, r25"  "\n\t"

  "DEC r29"  "\n\t"
  "BRNE SpeckKey48LoopA%="  "\n\t"

// store K[0] to TxtKey[12 ~ 17], LITTLE endian
  "ST X+, r14"  "\n\t"
  "ST X+, r15"  "\n\t"
  "ST X+, r16"  "\n\t"
  "ST X+, r17"  "\n\t"  
  "ST X+, r18"  "\n\t"
  "ST X+, r19"  "\n\t"


//  "EOR r29, r29"  "\n\t"  // r29 should be 0 here
"SpeckKey48LoopB%=:"  // counter = 0, ..., T-2
  "CPI r30, lo8(%[LX])"  "\n\t"  // only compare low byte, because size of L <= 12 bytes
  "BRNE SpeckKey48LoopBx%="  "\n\t"
  "LDI r30, lo8(%[L])"  "\n\t"   // back to L[0]
  "LDI r31, hi8(%[L])"  "\n\t"

"SpeckKey48LoopBx%=:"
// load L[i mod (m-1)] with 8-bit right rotation
  "LDD r25, Z+0"  "\n\t"
  "LDD r20, Z+1"  "\n\t"
  "LDD r21, Z+2"  "\n\t"
  "LDD r22, Z+3"  "\n\t"
  "LDD r23, Z+4"  "\n\t"
  "LDD r24, Z+5"  "\n\t"

// L[i] += K[i]
  "ADD r20, r14"  "\n\t"
  "ADC r21, r15"  "\n\t"
  "ADC r22, r16"  "\n\t"
  "ADC r23, r17"  "\n\t"
  "ADC r24, r18"  "\n\t"
  "ADC r25, r19"  "\n\t"

// L[i] ^= i
  "EOR r20, r29"  "\n\t"

// store L[i mod (m-1)]
  "ST Z+, r20"  "\n\t"
  "ST Z+, r21"  "\n\t"
  "ST Z+, r22"  "\n\t"
  "ST Z+, r23"  "\n\t"
  "ST Z+, r24"  "\n\t"
  "ST Z+, r25"  "\n\t"

// 3-bit left rotation K[i]
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

// K ^= L
  "EOR r19, r25"  "\n\t"
  "EOR r18, r24"  "\n\t"
  "EOR r17, r23"  "\n\t"
  "EOR r16, r22"  "\n\t"
  "EOR r15, r21"  "\n\t"
  "EOR r14, r20"  "\n\t"

// store K[i], LITTLE endian
  "ST X+, r14"  "\n\t"
  "ST X+, r15"  "\n\t"
  "ST X+, r16"  "\n\t"
  "ST X+, r17"  "\n\t"
  "ST X+, r18"  "\n\t"
  "ST X+, r19"  "\n\t"
  
  "INC r29"  "\n\t"
  "CPI r29, %[T1]"  "\n\t"
  "BRCS SpeckKey48LoopB%="  "\n\t"

  "POP r14"  "\n\t"
  "POP r15"  "\n\t"
  "POP r16"  "\n\t"
  "POP r17"  "\n\t"

  "POP r29"  "\n\t"
  "RET"  "\n\t"
  :
  : [T] "i" (SpeckT), 
    [T1] "i" (SpeckT - 1),
    [M1] "i" (SpeckM - 1), 
    [TxtKey] "i" (speckTxtKey), 
    [TxtKeyX] "i" (speckTxtKey + (SpeckM+2)*6),
    [L] "i" (SpeckL), 
    [LX] "i" (SpeckL + (SpeckM-1)*6)
  : "cc", "memory"
);
}


// n = 64, m = 2, 3, or 4
void __attribute__ ((noinline, naked)) SpeckKey64AVRASM() {
asm volatile(
  "PUSH r29"  "\n\t"

  "PUSH r17"  "\n\t"
  "PUSH r16"  "\n\t"
  "PUSH r15"  "\n\t"
  "PUSH r14"  "\n\t"
  "PUSH r13"  "\n\t"
  "PUSH r12"  "\n\t"
  "PUSH r11"  "\n\t"
  "PUSH r10"  "\n\t"
// r25:r24:r23:r22:r21:r20:r19:r18  L[i] (or L[i + M-1]
// r17:r16:r15:r14:r13:r12:r11:r10  K[i]
// r29  counter
  
  "LDI r26, lo8(%[TxtKeyX])"  "\n\t"
  "LDI r27, hi8(%[TxtKeyX])"  "\n\t"
  "LDI r30, lo8(%[L])"  "\n\t"
  "LDI r31, hi8(%[L])"  "\n\t"

// load K[0], BIG endian  
  "LD r10, -X"  "\n\t"
  "LD r11, -X"  "\n\t"
  "LD r12, -X"  "\n\t"
  "LD r13, -X"  "\n\t"
  "LD r14, -X"  "\n\t"
  "LD r15, -X"  "\n\t"
  "LD r16, -X"  "\n\t"
  "LD r17, -X"  "\n\t"

  "LDI r29, %[M1]"  "\n\t"
"SpeckKey64LoopA%=:"  // counter = M-1, ..., 1
// load L[0] ~ L[m-2] from speckTxtKey, BIG endian
  "LD r18, -X"  "\n\t"
  "LD r19, -X"  "\n\t"
  "LD r20, -X"  "\n\t"  
  "LD r21, -X"  "\n\t"  
  "LD r22, -X"  "\n\t"  
  "LD r23, -X"  "\n\t"  
  "LD r24, -X"  "\n\t"
  "LD r25, -X"  "\n\t"  

// store L[0] ~ L[m-2] to SpeckL, LITTLE endian
  "ST Z+, r18"  "\n\t"
  "ST Z+, r19"  "\n\t"
  "ST Z+, r20"  "\n\t"
  "ST Z+, r21"  "\n\t"
  "ST Z+, r22"  "\n\t"
  "ST Z+, r23"  "\n\t"
  "ST Z+, r24"  "\n\t"
  "ST Z+, r25"  "\n\t"

  "DEC r29"  "\n\t"
  "BRNE SpeckKey64LoopA%="  "\n\t"
  
// store K[0] to TxtKey[16 ~ 23], LITTLE endian
  "ST X+, r10"  "\n\t"
  "ST X+, r11"  "\n\t"
  "ST X+, r12"  "\n\t"
  "ST X+, r13"  "\n\t"
  "ST X+, r14"  "\n\t"
  "ST X+, r15"  "\n\t"
  "ST X+, r16"  "\n\t"
  "ST X+, r17"  "\n\t"  


//  "EOR r29, r29"  "\n\t"  // r29 should be 0 here
"SpeckKey64LoopB%=:"  // counter = 0, ..., T-2
  "CPI r30, lo8(%[LX])"  "\n\t"  // only compare low byte, because size of L <= 24 bytes
  "BRNE SpeckKey64LoopBx%="  "\n\t"
  "LDI r30, lo8(%[L])"  "\n\t"   // back to L[0]
  "LDI r31, hi8(%[L])"  "\n\t"

"SpeckKey64LoopBx%=:"
// load L[i mod (m-1)] with 8-bit right rotation
  "LDD r25, Z+0"  "\n\t"
  "LDD r18, Z+1"  "\n\t"
  "LDD r19, Z+2"  "\n\t"
  "LDD r20, Z+3"  "\n\t"
  "LDD r21, Z+4"  "\n\t"
  "LDD r22, Z+5"  "\n\t"
  "LDD r23, Z+6"  "\n\t"
  "LDD r24, Z+7"  "\n\t"

// L[i] += K[i]
  "ADD r18, r10"  "\n\t"
  "ADC r19, r11"  "\n\t"
  "ADC r20, r12"  "\n\t"
  "ADC r21, r13"  "\n\t"
  "ADC r22, r14"  "\n\t"
  "ADC r23, r15"  "\n\t"
  "ADC r24, r16"  "\n\t"
  "ADC r25, r17"  "\n\t"

// L[i] ^= i
  "EOR r18, r29"  "\n\t"
  
// store L[i mod (m-1)]
  "ST Z+, r18"  "\n\t"  
  "ST Z+, r19"  "\n\t"
  "ST Z+, r20"  "\n\t"
  "ST Z+, r21"  "\n\t"
  "ST Z+, r22"  "\n\t"
  "ST Z+, r23"  "\n\t"
  "ST Z+, r24"  "\n\t"
  "ST Z+, r25"  "\n\t"

// 3-bit left rotation K[i]
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

// K ^= L
  "EOR r17, r25"  "\n\t"
  "EOR r16, r24"  "\n\t"
  "EOR r15, r23"  "\n\t"
  "EOR r14, r22"  "\n\t"
  "EOR r13, r21"  "\n\t"
  "EOR r12, r20"  "\n\t"
  "EOR r11, r19"  "\n\t"
  "EOR r10, r18"  "\n\t"
  
// store K[i], LITTLE endian
  "ST X+, r10"  "\n\t"
  "ST X+, r11"  "\n\t"
  "ST X+, r12"  "\n\t"
  "ST X+, r13"  "\n\t"
  "ST X+, r14"  "\n\t"
  "ST X+, r15"  "\n\t"
  "ST X+, r16"  "\n\t"
  "ST X+, r17"  "\n\t"
  
  "INC r29"  "\n\t"
  "CPI r29, %[T1]"  "\n\t"
  "BRCC SpeckKey64LoopBExit%="  "\n\t"
  "JMP SpeckKey64LoopB%="  "\n\t"

"SpeckKey64LoopBExit%=:"
  "POP r10"  "\n\t"
  "POP r11"  "\n\t"
  "POP r12"  "\n\t"
  "POP r13"  "\n\t"
  "POP r14"  "\n\t"
  "POP r15"  "\n\t"
  "POP r16"  "\n\t"
  "POP r17"  "\n\t"

  "POP r29"  "\n\t"
  "RET"  "\n\t"
  :
  : [T] "i" (SpeckT), 
    [T1] "i" (SpeckT - 1),
    [M1] "i" (SpeckM - 1), 
    [TxtKey] "i" (speckTxtKey), 
    [TxtKeyX] "i" (speckTxtKey + (SpeckM+2)*8),
    [L] "i" (SpeckL), 
    [LX] "i" (SpeckL + (SpeckM-1)*8)
  : "cc", "memory"
);
}
