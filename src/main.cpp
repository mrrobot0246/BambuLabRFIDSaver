#include <Arduino.h>
#include <SPI.h>
#include <Wire.h>
#include <MFRC522.h>
#include <Adafruit_PN532.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/error.h>
#include <string.h>


#define RC522_SS_PIN   5
#define RC522_RST_PIN  27

#define PN532_IRQ      4
#define PN532_RESET    15

MFRC522 mfrc522(RC522_SS_PIN, RC522_RST_PIN);
Adafruit_PN532 nfc(PN532_IRQ, PN532_RESET);

const uint8_t masterKey[16] = {
  0x9a, 0x75, 0x9c, 0xf2, 0xc4, 0xf7, 0xca, 0xff,
  0x22, 0x2c, 0xb9, 0x76, 0x9b, 0x41, 0xbc, 0x96
};
const uint8_t kdfContext[7] = {'R', 'F', 'I', 'D', '-', 'B', 0x00};

uint8_t defaultKey[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
uint8_t zeroKey[6]    = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

uint8_t factoryTrailer[16] = {
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
  0xFF, 0x07, 0x80, 0x69,
  0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
};

const int MAX_AUTH_RETRIES = 5;


int mbedtls_hkdf(const mbedtls_md_info_t *md, const unsigned char *salt,
                  size_t salt_len, const unsigned char *ikm, size_t ikm_len,
                  const unsigned char *info, size_t info_len,
                  unsigned char *okm, size_t okm_len)
{
  int ret = MBEDTLS_ERR_ERROR_CORRUPTION_DETECTED;
  unsigned char prk[MBEDTLS_MD_MAX_SIZE];

  ret = mbedtls_hkdf_extract(md, salt, salt_len, ikm, ikm_len, prk);

  if (ret == 0) {
    ret = mbedtls_hkdf_expand(md, prk, mbedtls_md_get_size(md),
                               info, info_len, okm, okm_len);
  }

  mbedtls_platform_zeroize(prk, sizeof(prk));

  return ret;
}

int mbedtls_hkdf_extract(const mbedtls_md_info_t *md,
                          const unsigned char *salt, size_t salt_len,
                          const unsigned char *ikm, size_t ikm_len,
                          unsigned char *prk)
{
  unsigned char null_salt[MBEDTLS_MD_MAX_SIZE] = { '\0' };

  if (salt == NULL) {
    size_t hash_len;

    if (salt_len != 0) {
      return MBEDTLS_ERR_HKDF_BAD_INPUT_DATA;
    }

    hash_len = mbedtls_md_get_size(md);

    if (hash_len == 0) {
      return MBEDTLS_ERR_HKDF_BAD_INPUT_DATA;
    }

    salt = null_salt;
    salt_len = hash_len;
  }

  return mbedtls_md_hmac(md, salt, salt_len, ikm, ikm_len, prk);
}

int mbedtls_hkdf_expand(const mbedtls_md_info_t *md, const unsigned char *prk,
                         size_t prk_len, const unsigned char *info,
                         size_t info_len, unsigned char *okm, size_t okm_len)
{
  size_t hash_len;
  size_t where = 0;
  size_t n;
  size_t t_len = 0;
  size_t i;
  int ret = 0;
  mbedtls_md_context_t ctx;
  unsigned char t[MBEDTLS_MD_MAX_SIZE];

  if (okm == NULL) {
    return MBEDTLS_ERR_HKDF_BAD_INPUT_DATA;
  }

  hash_len = mbedtls_md_get_size(md);

  if (prk_len < hash_len || hash_len == 0) {
    return MBEDTLS_ERR_HKDF_BAD_INPUT_DATA;
  }

  if (info == NULL) {
    info = (const unsigned char *) "";
    info_len = 0;
  }

  n = okm_len / hash_len;

  if (okm_len % hash_len != 0) {
    n++;
  }

  if (n > 255) {
    return MBEDTLS_ERR_HKDF_BAD_INPUT_DATA;
  }

  mbedtls_md_init(&ctx);

  if ((ret = mbedtls_md_setup(&ctx, md, 1)) != 0) {
    goto exit;
  }

  memset(t, 0, hash_len);

  for (i = 1; i <= n; i++) {
    size_t num_to_copy;
    unsigned char c = i & 0xff;

    ret = mbedtls_md_hmac_starts(&ctx, prk, prk_len);
    if (ret != 0) goto exit;

    ret = mbedtls_md_hmac_update(&ctx, t, t_len);
    if (ret != 0) goto exit;

    ret = mbedtls_md_hmac_update(&ctx, info, info_len);
    if (ret != 0) goto exit;

    ret = mbedtls_md_hmac_update(&ctx, &c, 1);
    if (ret != 0) goto exit;

    ret = mbedtls_md_hmac_finish(&ctx, t);
    if (ret != 0) goto exit;

    num_to_copy = i != n ? hash_len : okm_len - where;
    memcpy(okm + where, t, num_to_copy);
    where += hash_len;
    t_len = hash_len;
  }

exit:
  mbedtls_md_free(&ctx);
  mbedtls_platform_zeroize(t, sizeof(t));

  return ret;
}


bool deriveKeys(const uint8_t *uid, size_t uidLen, uint8_t outKeys[16][6]) {
  uint8_t okm[96];

  const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
  if (md == nullptr) return false;

  int ret = mbedtls_hkdf(
    md,
    masterKey, sizeof(masterKey),
    uid, uidLen,
    kdfContext, sizeof(kdfContext),
    okm, sizeof(okm)
  );

  if (ret != 0) return false;

  for (int i = 0; i < 16; i++) {
    memcpy(outKeys[i], okm + (i * 6), 6);
  }
  return true;
}

void printHexBlock(const char *label, uint8_t *data, int len) {
  Serial.print(label);
  for (int i = 0; i < len; i++) {
    Serial.print(data[i] < 0x10 ? " 0" : " ");
    Serial.print(data[i], HEX);
  }
  Serial.println();
}



bool pn532AuthKeyB(uint8_t *uid, uint8_t *uidLength, int block, uint8_t *keyData, int *attemptsOut) {
  bool ok = false;
  int attempts = 0;

  while (!ok && attempts < MAX_AUTH_RETRIES) {
    if (!nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, uidLength, 1000)) {
      attempts++;
      delay(200);
      continue;
    }

    ok = nfc.mifareclassic_AuthenticateBlock(uid, *uidLength, block, 1 /* Key B */, keyData);
    attempts++;

    if (!ok) delay(200);
  }

  if (attemptsOut != nullptr) *attemptsOut = attempts;
  return ok;
}

void pn532Dump() {
  Serial.println(F("[pn532Dump] Tap a card..."));

  uint8_t uid[7];
  uint8_t uidLength;

  while (!nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength, 3000)) {
    
  }

  printHexBlock("UID:", uid, uidLength);

  for (int sector = 0; sector < 16; sector++) {
    int trailer = (sector * 4) + 3;
    int attempts = 0;

    bool ok = pn532AuthKeyB(uid, &uidLength, trailer, defaultKey, &attempts);

    Serial.print(F("Sector "));
    Serial.print(sector);

    if (!ok) {
      Serial.print(F(": auth failed after "));
      Serial.print(attempts);
      Serial.println(F(" attempts"));
      continue;
    }

    Serial.print(F(": auth OK after "));
    Serial.print(attempts);
    Serial.println(F(" attempt(s)"));

    for (int off = 0; off < 4; off++) {
      int block = (sector * 4) + off;
      uint8_t data[16];
      if (nfc.mifareclassic_ReadDataBlock(block, data)) {
        char label[16];
        snprintf(label, sizeof(label), "  Block %2d:", block);
        printHexBlock(label, data, 16);
      } else {
        Serial.print(F("  Block "));
        Serial.print(block);
        Serial.println(F(": read failed"));
      }
    }
  }

  Serial.println(F("[pn532Dump] Done."));
}

void pn532Reset() {
  Serial.println(F("[pn532Reset] Tap a card..."));

  uint8_t uid[7];
  uint8_t uidLength;

  while (!nfc.readPassiveTargetID(PN532_MIFARE_ISO14443A, uid, &uidLength, 3000)) {

  }

  printHexBlock("UID:", uid, uidLength);

  uint8_t derivedKeys[16][6];
  if (!deriveKeys(uid, uidLength, derivedKeys)) {
    Serial.println(F("Key derivation failed"));
    return;
  }

  for (int sector = 0; sector < 16; sector++) {
    int trailer = (sector * 4) + 3;
    int attempts = 0;

    bool derivedOk = pn532AuthKeyB(uid, &uidLength, trailer, derivedKeys[sector], &attempts);

    if (derivedOk) {
      Serial.print(F("Sector "));
      Serial.print(sector);
      Serial.println(F(": derived key OK - writing factory trailer"));

      bool writeOk = nfc.mifareclassic_WriteDataBlock(trailer, factoryTrailer);
      Serial.println(writeOk ? F("  -> Reset OK") : F("  -> Write failed"));

    } else {
      int defAttempts = 0;
      bool defOk = pn532AuthKeyB(uid, &uidLength, trailer, defaultKey, &defAttempts);

      if (defOk) {
        Serial.print(F("Sector "));
        Serial.print(sector);
        Serial.println(F(": already reset (default key OK)"));
      } else {
        int zeroAttempts = 0;
        bool zeroOk = pn532AuthKeyB(uid, &uidLength, trailer, zeroKey, &zeroAttempts);

        Serial.print(F("Sector "));
        Serial.print(sector);
        Serial.println(zeroOk ? F(": zero key OK") : F(": no key worked"));
      }
    }

    delay(50);
  }

  Serial.println(F("[pn532Reset] Done."));
}


bool rc522Reselect() {
  byte bufferATQA[2];
  byte bufferSize = sizeof(bufferATQA);

  MFRC522::StatusCode result = mfrc522.PICC_WakeupA(bufferATQA, &bufferSize);
  if (result != MFRC522::STATUS_OK && result != MFRC522::STATUS_COLLISION) {
    return false;
  }

  return mfrc522.PICC_Select(&(mfrc522.uid)) == MFRC522::STATUS_OK;
}

bool rc522AuthKeyB(int block, uint8_t *keyData, int *attemptsOut) {
  MFRC522::MIFARE_Key key;
  memcpy(key.keyByte, keyData, 6);

  bool ok = false;
  int attempts = 0;

  while (!ok && attempts < MAX_AUTH_RETRIES) {
    if (attempts > 0) {
      mfrc522.PICC_HaltA();
      if (!rc522Reselect()) {
        attempts++;
        delay(200);
        continue;
      }
    }

    MFRC522::StatusCode status = mfrc522.PCD_Authenticate(
      MFRC522::PICC_CMD_MF_AUTH_KEY_B, block, &key, &(mfrc522.uid)
    );
    ok = (status == MFRC522::STATUS_OK);
    attempts++;

    if (!ok) delay(200);
  }

  if (attemptsOut != nullptr) *attemptsOut = attempts;
  return ok;
}

void rc522Dump() {
  Serial.println(F("[rc522Dump] Tap a card..."));

  while (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
    delay(50);
  }

  printHexBlock("UID:", mfrc522.uid.uidByte, mfrc522.uid.size);

  for (int sector = 0; sector < 16; sector++) {
    int trailer = (sector * 4) + 3;
    int attempts = 0;

    bool ok = rc522AuthKeyB(trailer, defaultKey, &attempts);

    Serial.print(F("Sector "));
    Serial.print(sector);

    if (!ok) {
      Serial.print(F(": auth failed after "));
      Serial.print(attempts);
      Serial.println(F(" attempts"));
      continue;
    }

    Serial.print(F(": auth OK after "));
    Serial.print(attempts);
    Serial.println(F(" attempt(s)"));

    for (int off = 0; off < 4; off++) {
      int block = (sector * 4) + off;
      byte data[18];
      byte size = sizeof(data);

      MFRC522::StatusCode status = mfrc522.MIFARE_Read(block, data, &size);
      if (status == MFRC522::STATUS_OK) {
        char label[16];
        snprintf(label, sizeof(label), "  Block %2d:", block);
        printHexBlock(label, data, 16);
      } else {
        Serial.print(F("  Block "));
        Serial.print(block);
        Serial.println(F(": read failed"));
      }
    }

    mfrc522.PCD_StopCrypto1();
  }

  mfrc522.PICC_HaltA();
  Serial.println(F("[rc522Dump] Done."));
}

void rc522Reset() {
  Serial.println(F("[rc522Reset] Tap a card..."));

  while (!mfrc522.PICC_IsNewCardPresent() || !mfrc522.PICC_ReadCardSerial()) {
    delay(50);
  }

  printHexBlock("UID:", mfrc522.uid.uidByte, mfrc522.uid.size);

  uint8_t derivedKeys[16][6];
  if (!deriveKeys(mfrc522.uid.uidByte, mfrc522.uid.size, derivedKeys)) {
    Serial.println(F("Key derivation failed"));
    return;
  }

  for (int sector = 0; sector < 16; sector++) {
    int trailer = (sector * 4) + 3;
    int attempts = 0;

    bool derivedOk = rc522AuthKeyB(trailer, derivedKeys[sector], &attempts);

    if (derivedOk) {
      Serial.print(F("Sector "));
      Serial.print(sector);
      Serial.println(F(": derived key OK - writing factory trailer"));

      MFRC522::StatusCode status = mfrc522.MIFARE_Write(trailer, factoryTrailer, 16);
      Serial.println(status == MFRC522::STATUS_OK ? F("  -> Reset OK") : F("  -> Write failed"));

      mfrc522.PCD_StopCrypto1();

    } else {
      int defAttempts = 0;
      bool defOk = rc522AuthKeyB(trailer, defaultKey, &defAttempts);

      if (defOk) {
        Serial.print(F("Sector "));
        Serial.print(sector);
        Serial.println(F(": already reset (default key OK)"));
        mfrc522.PCD_StopCrypto1();
      } else {
        int zeroAttempts = 0;
        bool zeroOk = rc522AuthKeyB(trailer, zeroKey, &zeroAttempts);

        Serial.print(F("Sector "));
        Serial.print(sector);
        Serial.println(zeroOk ? F(": zero key OK") : F(": no key worked"));

        if (zeroOk) mfrc522.PCD_StopCrypto1();
      }
    }

    delay(50);
  }

  mfrc522.PICC_HaltA();
  Serial.println(F("[rc522Reset] Done."));
}


void printMenu() {
  Serial.println();
  Serial.println(F("Commands: rc522Dump | rc522Reset | pn532Dump | pn532Reset"));
}

void setup() {
  Serial.begin(115200);
  while (!Serial);

  SPI.begin();
  mfrc522.PCD_Init();

  Wire.begin();
  nfc.begin();

  uint32_t versiondata = nfc.getFirmwareVersion();
  if (!versiondata) {
    Serial.println(F("WARNING: PN532 not detected - pn532Dump/pn532Reset won't work"));
  } else {
    nfc.SAMConfig();
  }

  Serial.println(F("Ready."));
  printMenu();
}

void loop() {
  if (!Serial.available()) return;

  String cmd = Serial.readStringUntil('\n');
  cmd.trim();

  if (cmd == "rc522Dump") {
    rc522Dump();
  } else if (cmd == "rc522Reset") {
    rc522Reset();
  } else if (cmd == "pn532Dump") {
    pn532Dump();
  } else if (cmd == "pn532Reset") {
    pn532Reset();
  } else if (cmd.length() > 0) {
    Serial.print(F("Unknown command: "));
    Serial.println(cmd);
  }

  printMenu();
}