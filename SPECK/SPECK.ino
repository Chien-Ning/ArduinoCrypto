


#include "SPECK_AVR.h"

void setup() {
  // put your setup code here, to run once:

  speckKey();

  Serial.begin(115200);  

  speckEnc();
  
//  Serial.println("");
//  for (int i = 0; i < SpeckTxtLen/8; i++){
//    if ((i & 7) == 0) Serial.println("");
//    if (speckTxtKey[i] < 16) Serial.print("0");
//    Serial.print(speckTxtKey[i], HEX);
//    Serial.print(", ");
//  }
}

void loop() {
  // put your main code here, to run repeatedly:

}
