#include <Arduino.h>
#include <NimBLEDevice.h>
#include <mbedtls/aes.h>
#include <vector>
#include <stdexcept>

#define SCAN_TIME 5 // Scan time in seconds

// AES key (16 bytes for AES-128)
const uint8_t key[16] = {108, 101, 97, 103, 101, 110, 100, 255, 254, 48, 49, 48, 48, 48, 48, 57}; 

struct BM6Data {
  float voltage;
  int temperature;
  int power;
};

BM6Data bm6_data = {0, 0, 0};

struct Config {  
  std::vector<String> devices;
};

Config config = {
    {"50:54:7B:5E:89:A9"}  // Initialize vector with a list of device MAC addresses
};

// Precomputed encrypted command
uint8_t encryptedCommandBytes[16];

// Function to decrypt data using AES
String decrypt(uint8_t* crypted, size_t length) {
    if (length != 16) {
        Serial.println("Error: Decrypt function received incorrect length data.");
        return "";
    }

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_dec(&aes, key, 128); // Set key for decryption

    uint8_t decrypted[16]; // Buffer for decrypted data
    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, crypted, decrypted);

    mbedtls_aes_free(&aes); // Clean up

    // Convert decrypted data to a hex string
    String decryptedHex = "";
    for (int i = 0; i < 16; i++) {
        if (decrypted[i] < 0x10) {
            decryptedHex += '0';
        }
        decryptedHex += String(decrypted[i], HEX);
    }

    return decryptedHex;
}

void encrypt(uint8_t* plaintext, size_t length, uint8_t* outputBuffer) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mbedtls_aes_setkey_enc(&aes, key, 128); // Set key for encryption

    mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, plaintext, outputBuffer);
    mbedtls_aes_free(&aes); // Clean up
}

void precomputeEncryptedCommand() {
    // The d15507 command tells the BM6 to start sending voltage/temp notifications
    uint8_t command[] = {0xd1, 0x55, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    
    // Encrypt the command once and store it in the global encryptedCommandBytes array
    encrypt(command, sizeof(command), encryptedCommandBytes);
    Serial.println("Encrypted command precomputed.");
}

// Notification handler for receiving BM6 data
void notificationHandler(BLERemoteCharacteristic* characteristic, uint8_t* data, size_t length, bool isNotify) {
  if (data == NULL || length == 0) {
    Serial.println("Received NULL data in notification.");
    return;
  }
  
  String message = decrypt(data, length);
  Serial.println("Message received: " + message);

  if (message.startsWith("d15507")) {
    bm6_data.voltage = strtol(message.substring(15, 18).c_str(), NULL, 16) / 100.0;
    bm6_data.temperature = strtol(message.substring(8, 10).c_str(), NULL, 16);
    bm6_data.power = strtol(message.substring(12, 14).c_str(), NULL, 16);
  }    
}

void getBM6Data(const char* address) {
  
  Serial.println("Starting BM6 data retrieval...");
  bm6_data.voltage = 0;
  bm6_data.temperature = 0;
  bm6_data.power = 0;

  BLEClient* client = nullptr;
  try {
    client = BLEDevice::createClient();
    BLEAddress bleAddress(address);

    Serial.print("Connecting to BLE device at address: ");
    Serial.println(address);

    if (!client->connect(bleAddress)) {
      Serial.println("Failed to connect to the BLE device.");      
      return;
    }

    Serial.println("Connected to BLE device.");

    NimBLERemoteService* service = client->getService("FFF0");
    if (service == nullptr) {
      Serial.println("Failed to find the service with UUID FFF0.");
      client->disconnect();
      delay(1000);      
      return;
    }

    NimBLERemoteCharacteristic* charFF3 = service->getCharacteristic("FFF3");
    NimBLERemoteCharacteristic* charFF4 = service->getCharacteristic("FFF4");
    if (charFF3 == nullptr || charFF4 == nullptr) {
      Serial.println("Failed to find the characteristics with UUID FFF3 or FFF4.");
      client->disconnect();
      delay(1000);      
      return;
    }

    // Write the precomputed encrypted command to the characteristic
    charFF3->writeValue(encryptedCommandBytes, sizeof(encryptedCommandBytes), true);
    Serial.println("Sent encrypted command to start sending notifications.");

    // Subscribe to notifications
    if (charFF4->canNotify()) {
        charFF4->subscribe(true, notificationHandler);
        Serial.println("Subscribed to notifications.");
    }

    // Wait for data
    unsigned long startTime = millis();
    while (bm6_data.voltage == 0 && bm6_data.temperature == 0) {
      if (millis() - startTime > 10000) {
        Serial.println("Timeout: No data received.");
        client->disconnect();
        delay(1000);        
        return;
      }
      delay(100);
    }
    Serial.println("Data received.");
    Serial.print("Voltage: ");
    Serial.println(bm6_data.voltage);
    Serial.print("Temp: ");
    Serial.println(bm6_data.temperature);
    Serial.print("Power: ");
    Serial.println(bm6_data.power);

    // Unsubscribe from notifications before disconnecting
    if(charFF4->canNotify()) {
        charFF4->unsubscribe();
        Serial.println("Unsubscribed from notifications.");
        delay(1000); // Wait for the unsubscribe operation to complete
    }

  } catch (const std::exception& e) {
    Serial.print("Exception: ");
    Serial.println(e.what());
    if (client) {
      client->disconnect();
      delay(1000);
    }
  } catch (...) {
    Serial.println("An unknown error occurred.");
    if (client) {
      client->disconnect();
      delay(1000);
    }
  }

  if (client) {
    if (client->isConnected()) {
      client->disconnect();
    }    
    client = nullptr;
    Serial.println("Disconnected from BLE device.");    
    delay(2000); // Wait for the deinit and disconnect to complete
  } 
}

void setup() {
  Serial.begin(115200);
  NimBLEDevice::init("");  
  precomputeEncryptedCommand(); // Precompute the encrypted command 
}

void loop() {   
  
  for (String& device : config.devices) {
    Serial.print("Processing device: ");
    Serial.println(device);
    getBM6Data(device.c_str());
    delay(1000); // Small delay between each device poll
  }
  delay(10000); // Wait for a minute before polling again
}
