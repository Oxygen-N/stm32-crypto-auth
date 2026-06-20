#include "main.h"
#include "usb_device.h"
#include "gpio.h"
#include "string.h"
#include "usbd_cdc_if.h"
#include <stdint.h>
#include <stdlib.h>
#include "stm32l5xx_hal_flash.h"

// Константы HMAC-SHA256
#define BLOCK_SIZE 64
#define HMAC_DIGEST_SIZE 32
#define KEY_FLASH_ADDR 0x08080000

// Структура для хранения ключа
typedef struct {
    uint8_t key[32];
    uint8_t valid;
} KeyStorage;

// Макросы SHA-256
#define ROTR(x, n) ((x >> n) | (x << (32 - n)))
#define CH(x, y, z) ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define SIG0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define SIG1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define LSIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3))
#define LSIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10))

// Глобальные переменные
volatile KeyStorage key_storage __attribute__((section(".key_section")));
uint64_t current_time = 0;
uint8_t USBRXDataReady = 0;
uint8_t* USBRXDataBuffer;
uint8_t USBRXDataLength = 0;

// Константы SHA-256
static const uint32_t k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1,
    0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786,
    0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147,
    0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
    0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a,
    0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

// Прототипы функций
void sha256_transform(uint32_t* state, const uint8_t* data);
void sha256(const uint8_t* message, uint32_t len, uint8_t* digest);
void compute_hmac(const uint8_t* msg, uint32_t msg_len, uint8_t* hmac);
uint32_t generate_totp(uint32_t interval);
void write_key_to_flash(const uint8_t* new_key);
void read_key_from_flash();
void SystemClock_Config(void);

// Обработчик USB
void USBRxHandler(uint8_t* buf, uint32_t len) {
    USBRXDataBuffer = buf;
    USBRXDataLength = len;
    USBRXDataReady = 1;
}

int main(void) {
    HAL_Init();
    SystemClock_Config();
    MX_GPIO_Init();
    MX_USB_Device_Init();
    read_key_from_flash();

    while(1) {
        if(USBRXDataReady) {
            // Приведение типа для строковых операций
            char* cmd = (char*)USBRXDataBuffer;

            // Обработка CHECK_KEY
            if(strncmp(cmd, "CHECK_KEY", 9) == 0) {
                if(key_storage.valid) {
                    CDC_Transmit_FS((uint8_t*)"KEY_OK\r\n", 8);
                } else {
                    CDC_Transmit_FS((uint8_t*)"KEY_NOT_FOUND\r\n", 15);
                }
            }

            // Обработка SET_KEY
            else if(strncmp(cmd, "SET_KEY ", 8) == 0) {
                uint8_t new_key[32];
                char hex_str[65] = {0};
                strncpy(hex_str, cmd + 8, 64);

                for(int i = 0; i < 32; i++) {
                    new_key[i] = strtol(hex_str + 2*i, NULL, 16);
                }

                write_key_to_flash(new_key);
                CDC_Transmit_FS((uint8_t*)"KEY_OK\r\n", 8);
            }

            // Обработка GET_HMAC
            else if(strncmp(cmd, "GET_HMAC ", 9) == 0) {
                uint8_t hmac[HMAC_DIGEST_SIZE];
                uint32_t msg_len = USBRXDataLength - 9;

                // Обрезка \r\n
                if(msg_len >= 2 && cmd[msg_len+7] == '\r' && cmd[msg_len+8] == '\n') {
                    msg_len -= 2;
                }

                compute_hmac(USBRXDataBuffer + 9, msg_len, hmac);
                char hex_buffer[65];
                for(int i = 0; i < 32; i++) {
                    sprintf(hex_buffer + i*2, "%02x", hmac[i]);
                }
                CDC_Transmit_FS((uint8_t*)hex_buffer, 64);
            }

            // Обработка SET_TIME
            else if(strncmp(cmd, "SET_TIME ", 9) == 0) {
                current_time = strtoull(cmd + 9, NULL, 10);
                CDC_Transmit_FS((uint8_t*)"TIME_OK\r\n", 9);
            }

            // Обработка GET_TOTP
            else if(strncmp(cmd, "GET_TOTP", 8) == 0) {
                if(current_time == 0) {
                    CDC_Transmit_FS((uint8_t*)"TIME_NOT_SET\r\n", 14);
                } else {
                    uint32_t code = generate_totp(current_time / 30);
                    char code_str[7];
                    snprintf(code_str, sizeof(code_str), "%06lu", code);
                    CDC_Transmit_FS((uint8_t*)code_str, 6);
                }
            }

            USBRXDataReady = 0;
        }
        HAL_Delay(10);
    }
}

void write_key_to_flash(const uint8_t* new_key) {
    HAL_FLASH_Unlock();

    FLASH_EraseInitTypeDef erase = {
        .TypeErase = FLASH_TYPEERASE_PAGES,
        .Banks = FLASH_BANK_1,
        .Page = (KEY_FLASH_ADDR - FLASH_BASE) / FLASH_PAGE_SIZE,
        .NbPages = 1
    };

    uint32_t PageError;
    HAL_FLASHEx_Erase(&erase, &PageError);

    for(int i = 0; i < sizeof(KeyStorage); i += 8) {
        uint64_t data;
        memcpy(&data, new_key + i, 8);
        HAL_FLASH_Program(FLASH_TYPEPROGRAM_DOUBLEWORD, KEY_FLASH_ADDR + i, data);
    }

    HAL_FLASH_Lock();
    key_storage.valid = 1;
}

void read_key_from_flash() {
    volatile KeyStorage* flash_ptr = (volatile KeyStorage*)KEY_FLASH_ADDR;
    key_storage = *flash_ptr;

    if(key_storage.valid != 1) {
        memset((void*)key_storage.key, 0, 32);
        key_storage.valid = 0;
    }
}


void sha256_transform(uint32_t* state, const uint8_t* data) {
    uint32_t w[64], a, b, c, d, e, f, g, h, t1, t2;
    for(int i = 0; i < 16; i++)
        w[i] = __builtin_bswap32(((uint32_t*)data)[i]);

    for(int i = 16; i < 64; i++)
        w[i] = LSIG1(w[i-2]) + w[i-7] + LSIG0(w[i-15]) + w[i-16];

    a = state[0]; b = state[1]; c = state[2]; d = state[3];
    e = state[4]; f = state[5]; g = state[6]; h = state[7];

    for(int i = 0; i < 64; i++){
        t1 = h + SIG1(e) + CH(e,f,g) + k[i] + w[i];
        t2 = SIG0(a) + MAJ(a,b,c);
        h = g; g = f; f = e; e = d + t1;
        d = c; c = b; b = a; a = t1 + t2;
    }

    state[0] += a; state[1] += b; state[2] += c; state[3] += d;
    state[4] += e; state[5] += f; state[6] += g; state[7] += h;
}


void sha256(const uint8_t* message, uint32_t len, uint8_t* digest) {
    uint32_t state[8] = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    uint8_t block[64];
    uint64_t bit_len = (uint64_t)len * 8;
    uint32_t offset = 0;

    while(len >= 64){
        sha256_transform(state, message + offset);
        offset += 64;
        len -= 64;
    }

    memcpy(block, message + offset, len);
    block[len++] = 0x80;

    if(64 - len < 8){
        memset(block + len, 0, 64 - len);
        sha256_transform(state, block);
        len = 0;
    }

    memset(block + len, 0, 56 - len);
    for(int i = 0; i < 8; i++)
        block[63 - i] = (bit_len >> (i * 8)) & 0xFF;

    sha256_transform(state, block);

    for(int i = 0; i < 8; i++)
        ((uint32_t*)digest)[i] = __builtin_bswap32(state[i]);
}


// --- Реализация HMAC-SHA256 ---
void compute_hmac(const uint8_t* msg, uint32_t msg_len, uint8_t* hmac) {
    uint8_t k_ipad[BLOCK_SIZE] = {0};
    uint8_t k_opad[BLOCK_SIZE] = {0};
    uint8_t temp_key[BLOCK_SIZE] = {0};

    // 1. Подготовка ключа из энергонезависимой памяти
    if(key_storage.valid) {
        // Если ключ короче размера блока - дополняем нулями
        memcpy(temp_key, (const void*)key_storage.key, 32);
        memset(temp_key + 32, 0, 32);
    } else {
        // Обработка случая отсутствия ключа
        memset(temp_key, 0, BLOCK_SIZE);
    }

    // 2. Если ключ длиннее размера блока - хешируем его
    uint8_t key_hash[32];
    if(BLOCK_SIZE < 32) { // Для SHA-256 размер блока 64, это условие никогда не выполнится
        sha256(temp_key, BLOCK_SIZE, key_hash);
        memcpy(temp_key, key_hash, 32);
        memset(temp_key + 32, 0, 32);
    }

    // 3. Генерация pads
    for(int i = 0; i < BLOCK_SIZE; i++) {
        k_ipad[i] = temp_key[i] ^ 0x36;
        k_opad[i] = temp_key[i] ^ 0x5C;
    }

    // 4. Внутренний хеш: SHA256(K_ipad || message)
    uint8_t inner_hash[32];
    uint8_t inner_data[BLOCK_SIZE + msg_len];

    memcpy(inner_data, k_ipad, BLOCK_SIZE);
    memcpy(inner_data + BLOCK_SIZE, msg, msg_len);

    sha256(inner_data, BLOCK_SIZE + msg_len, inner_hash);

    // 5. Внешний хеш: SHA256(K_opad || inner_hash)
    uint8_t outer_data[BLOCK_SIZE + 32];

    memcpy(outer_data, k_opad, BLOCK_SIZE);
    memcpy(outer_data + BLOCK_SIZE, inner_hash, 32);

    sha256(outer_data, BLOCK_SIZE + 32, hmac);

    // 6. Очистка чувствительных данных
    memset(k_ipad, 0, BLOCK_SIZE);
    memset(k_opad, 0, BLOCK_SIZE);
    memset(temp_key, 0, BLOCK_SIZE);
    memset(inner_hash, 0, 32);
}

// --- Генерация TOTP ---
uint32_t generate_totp(uint32_t interval){

	if(!key_storage.valid) return 0;


	uint8_t counter[8];
	for(int i = 0; i < 8; i++)
	        counter[7 - i] = (interval >> (i * 8)) & 0xFF;


    uint8_t hmac[32];
    compute_hmac(counter, 8, hmac);

    uint32_t offset = hmac[31] & 0x0F;
    return (hmac[offset] << 24 | hmac[offset+1] << 16 |
           hmac[offset+2] << 8 | hmac[offset+3]) % 1000000;
}


void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  if (HAL_PWREx_ControlVoltageScaling(PWR_REGULATOR_VOLTAGE_SCALE1) != HAL_OK)
  {
    Error_Handler();
  }

  HAL_PWR_EnableBkUpAccess();
  __HAL_RCC_LSEDRIVE_CONFIG(RCC_LSEDRIVE_LOW);

  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE|RCC_OSCILLATORTYPE_LSE
                              |RCC_OSCILLATORTYPE_MSI;
  RCC_OscInitStruct.HSEState = RCC_HSE_ON;
  RCC_OscInitStruct.LSEState = RCC_LSE_ON;
  RCC_OscInitStruct.MSIState = RCC_MSI_ON;
  RCC_OscInitStruct.MSICalibrationValue = RCC_MSICALIBRATION_DEFAULT;
  RCC_OscInitStruct.MSIClockRange = RCC_MSIRANGE_6;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
  RCC_OscInitStruct.PLL.PLLM = 5;
  RCC_OscInitStruct.PLL.PLLN = 16;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV7;
  RCC_OscInitStruct.PLL.PLLQ = RCC_PLLQ_DIV2;
  RCC_OscInitStruct.PLL.PLLR = RCC_PLLR_DIV2;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV1;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_1) != HAL_OK)
  {
    Error_Handler();
  }

  HAL_RCCEx_EnableMSIPLLMode();
}

void Error_Handler(void)
{
  __disable_irq();
  while (1)
  {
  }
}

#ifdef  USE_FULL_ASSERT

void assert_failed(uint8_t *file, uint32_t line)
{
}
#endif
