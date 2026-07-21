#include <SPI.h>
#include <MFRC522.h>

#define RST_PIN 9
#define SS_PIN 10

MFRC522 rfid(SS_PIN, RST_PIN);

// Replace with your current working Key B
MFRC522::MIFARE_Key keyB = {
  .keyByte = {0x85, 0xA0, 0x56, 0xBD, 0x52, 0xCD}
};

void setup() {
  Serial.begin(9600);
  SPI.begin();
  rfid.PCD_Init();
  Serial.println("Scan your card to WRITE sector trailer using Key B");
}

void loop() {
  if (!rfid.PICC_IsNewCardPresent() || !rfid.PICC_ReadCardSerial()) {
    return;
  }

  byte trailerBlock = 3; // Block 3 is trailer of sector 0

  // Authenticate with Key B
  MFRC522::StatusCode status = rfid.PCD_Authenticate(
    MFRC522::PICC_CMD_MF_AUTH_KEY_B,
    trailerBlock,
    &keyB,
    &(rfid.uid)
  );

  if (status != MFRC522::STATUS_OK) {
    Serial.print(" Authentication failed: ");
    Serial.println(rfid.GetStatusCodeName(status));
    rfid.PICC_HaltA();
    rfid.PCD_StopCrypto1();
    return;
  }

  // Data to write to the trailer
  // Format: [Key A (6 bytes)] [Access Bits (4 bytes)] [Key B (6 bytes)]
  byte newTrailerBlock[16] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,   // New Key A
    0xFF, 0x07, 0x80, 0x69,               // Default Access Bits (full access)
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF    // New Key B (same as current)
  };

  status = rfid.MIFARE_Write(trailerBlock, newTrailerBlock, 16);

  if (status != MFRC522::STATUS_OK) {
    Serial.print(" Write failed: ");
    Serial.println(rfid.GetStatusCodeName(status));
  } else {
    Serial.println("Sector trailer written successfully (block 3)");
  }
  rfid.PICC_HaltA();
  rfid.PCD_StopCrypto1();
  delay(3000);
}
