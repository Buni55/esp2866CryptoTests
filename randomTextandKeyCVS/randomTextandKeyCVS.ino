#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <WiFiClient.h>
#include <FS.h>

#include <Crypto.h>
#include <AES.h>
#include <string.h>


const char* ssid = "name";
const char* password = "password";

ESP8266WebServer server(80);
void handleRoot();
void handleGetData();

////// Start cryptographie code //////

struct TestVector
{
    const char *name;
    byte key[32];
    byte plaintext[16];
    byte ciphertext[16];
};

static TestVector const testVectorAES128 = {
    .name        = "AES-128-ECB",
    .key         = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F},
    .plaintext   = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
    .ciphertext  = {0x69, 0xC4, 0xE0, 0xD8, 0x6A, 0x7B, 0x04, 0x30,
                    0xD8, 0xCD, 0xB7, 0x80, 0x70, 0xB4, 0xC5, 0x5A}
};
static TestVector const testVectorAES192 = {
    .name        = "AES-192-ECB",
    .key         = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17},
    .plaintext   = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
    .ciphertext  = {0xDD, 0xA9, 0x7C, 0xA4, 0x86, 0x4C, 0xDF, 0xE0,
                    0x6E, 0xAF, 0x70, 0xA0, 0xEC, 0x0D, 0x71, 0x91}
};
static TestVector const testVectorAES256 = {
    .name        = "AES-256-ECB",
    .key         = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                    0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
                    0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
                    0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F},
    .plaintext   = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                    0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF},
    .ciphertext  = {0x8E, 0xA2, 0xB7, 0xCA, 0x51, 0x67, 0x45, 0xBF,
                    0xEA, 0xFC, 0x49, 0x90, 0x4B, 0x49, 0x60, 0x89}
};

AES128 aes128;
AES192 aes192;
AES256 aes256;

byte buffer[16];
byte key[32];

void perfRandomTextAndKeyCipher(BlockCipher *cipher, int keySize, const char *name) {
    unsigned long totalEncryptTime = 0;
    unsigned long totalDecryptTime = 0;
    int numIterations = 100;

    File file = SPIFFS.open("/data.txt", "a");
    if (!file) {
      Serial.println("Failed to open /data.txt for writing");
    }

    Serial.println(name);
    file.print(name);
    file.print(" ");

    for (int i = 0; i < numIterations; ++i)
    {
        for (int j = 0; j < 16; ++j)
        {
            buffer[j] = random(256);
        }

        for (int j = 0; j < 16; ++j) {
            buffer[j] = random(256);
        }

        cipher->setKey(key, keySize);

        unsigned long startEncrypt = micros();
        cipher->encryptBlock(buffer, buffer);
        unsigned long elapsedEncrypt = micros() - startEncrypt;
        file.print(elapsedEncrypt);
        file.print("e ");
        totalEncryptTime += elapsedEncrypt;
     
        unsigned long startDecrypt = micros();
        cipher->decryptBlock(buffer, buffer);
        unsigned long elapsedDecrypt = micros() - startDecrypt;
        totalDecryptTime += elapsedDecrypt;
        file.print(elapsedEncrypt);
        file.print("d ");
    }

    file.close();

    Serial.print("Average Encryption Time: ");
    Serial.print(totalEncryptTime / numIterations);
    Serial.println(" microseconds");


    Serial.print("Average Decryption Time: ");
    Serial.print(totalDecryptTime / numIterations);
    Serial.println(" microseconds");
    Serial.println();
}


void testCipher(BlockCipher *cipher, const struct TestVector *test) {
    //crypto_feed_watchdog();
    Serial.print(test->name);
    Serial.print(" Encryption ... ");
    cipher->setKey(test->key, cipher->keySize());
    cipher->encryptBlock(buffer, test->plaintext);
    if (memcmp(buffer, test->ciphertext, 16) == 0)
        Serial.println("Passed");
    else
        Serial.println("Failed");

    Serial.print(test->name);
    Serial.print(" Decryption ... ");
    cipher->decryptBlock(buffer, test->ciphertext);
    if (memcmp(buffer, test->plaintext, 16) == 0)
        Serial.println("Passed");
    else
        Serial.println("Failed");
}





////// End cryptographie code //////


void setup() {
  Serial.begin(115200);
  delay(7000);
  Serial.println();
  WiFi.begin(ssid, password);
  while (WiFi.status() != WL_CONNECTED) {
      delay(1000);
      Serial.println("Connecting to WiFi...");
  }
  
  Serial.println("Connected to WiFi");
  Serial.print("ESP8266 IP Address: ");
  Serial.println(WiFi.localIP());

  SPIFFS.begin();
  File file = SPIFFS.open("/data.txt", "w");
  if (!file) {
    Serial.println("Failed to open /data.txt for writing");
  }
  file.print("");
  file.close();
  // start crypto
  Serial.println();
  Serial.println("State Sizes:");
  Serial.print("AES128 ... ");
  Serial.println(sizeof(AES128));
  Serial.print("AES192 ... ");
  Serial.println(sizeof(AES192));
  Serial.print("AES256 ... ");
  Serial.println(sizeof(AES256));
  Serial.println();

  Serial.println("Test Vectors:");
  testCipher(&aes128, &testVectorAES128);
  testCipher(&aes192, &testVectorAES192);
  testCipher(&aes256, &testVectorAES256);
  
  Serial.println("Random plaintext and key");
  perfRandomTextAndKeyCipher(&aes128, 16, "AES-128");
  perfRandomTextAndKeyCipher(&aes192, 24, "AES-192");
  perfRandomTextAndKeyCipher(&aes256, 32, "AES-256"); 
  // end crypto
  
  server.on("/", HTTP_GET, handleRoot);
  server.on("/getdata", HTTP_GET, handleGetData);
  server.begin();
  Serial.println("HTTP server started");

}

void loop() {
  server.handleClient();
}

void handleGetData() {
  File file = SPIFFS.open("/data.txt", "r");
  if (!file) {
    server.send(500, "text/plain", "500: Internal Server Error");
    return;
  }

  String fileContent = "";
  while (file.available()) {
    fileContent += (char)file.read();
  }
  file.close();
  server.send(200, "text/plain", fileContent);
}

void handleRoot() {
  server.send(200, "text/html", "<h1>ESP8266 NodeMCU V2>");
}
