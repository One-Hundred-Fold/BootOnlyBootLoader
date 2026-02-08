/* USER CODE BEGIN Header */
/**
  ******************************************************************************
  * @file           : main.c
  * @brief          : Main program body - Boot-only bootloader
  ******************************************************************************
  * @attention
  *
  * Copyright (c) 2026 STMicroelectronics.
  * All rights reserved.
  *
  * This software is licensed under terms that can be found in the LICENSE file
  * in the root directory of this software component.
  * If no LICENSE file comes with this software, it is provided AS-IS.
  *
  ******************************************************************************
  */
/* USER CODE END Header */
/* Includes ------------------------------------------------------------------*/
#include "main.h"

/* Private includes ----------------------------------------------------------*/
/* USER CODE BEGIN Includes */
#include <string.h>
#include <stdio.h>
/* USER CODE END Includes */

/* Private typedef -----------------------------------------------------------*/
/* USER CODE BEGIN PTD */

/* Bootloader metadata structure - 8-byte aligned */
typedef struct __attribute__((packed, aligned(8))) {
  char magic[8];           /* 0xdeadbeefcafebabe */
  char inverted_magic[8];  /* 0x2152411035014542 */
  char validation[8];      /* 0xffffffff00000000 */
  char invalidation[8];    /* 0x00ffffffffffffff */
  uint8_t  sha256[32];     /* SHA256 of sector from start to this field */
} AppMetadata_t;

/* USER CODE END PTD */

/* Private define ------------------------------------------------------------*/
/* USER CODE BEGIN PD */

/* Bootloader debug output - set to 1 to enable diagnostic messages via USART1 */
#ifndef BOOTLOADER_DEBUG_ENABLE
#define BOOTLOADER_DEBUG_ENABLE  0
#endif

/* STM32F401RE flash sector addresses (sectors 1-7, sector 0 = bootloader) */
#define FLASH_BASE             0x08000000UL
#define APP_METADATA_MAGIC     "\xde\xad\xbe\xef\xca\xfe\xba\xbe"
#define APP_METADATA_INV_MAGIC "\x21\x52\x41\x10\x35\x01\x45\x42"
#define APP_METADATA_VALID     "\xff\xff\xff\xff\x00\x00\x00\x00"
#define APP_METADATA_INVALID   "\x00\xff\xff\xff\xff\xff\xff\xff"
#define APP_METADATA_FIELD_LEN 8

/* Sector start addresses and sizes for STM32F401RE */
static const struct {
  uint32_t start;
  uint32_t size;
} SECTOR_INFO[] = {
  { 0x08004000UL, 16*1024 },   /* Sector 1: 16KB */
  { 0x08008000UL, 16*1024 },   /* Sector 2: 16KB */
  { 0x0800C000UL, 16*1024 },   /* Sector 3: 16KB */
  { 0x08010000UL, 64*1024 },   /* Sector 4: 64KB */
  { 0x08020000UL, 128*1024 },  /* Sector 5: 128KB */
  { 0x08040000UL, 128*1024 },  /* Sector 6: 128KB */
  { 0x08060000UL, 128*1024 },  /* Sector 7: 128KB */
};

#define NUM_APP_SECTORS (sizeof(SECTOR_INFO)/sizeof(SECTOR_INFO[0]))

/* USER CODE END PD */

/* Private macro -------------------------------------------------------------*/
/* USER CODE BEGIN PM */

/* USER CODE END PM */

/* Private variables ---------------------------------------------------------*/
UART_HandleTypeDef huart1;
UART_HandleTypeDef huart2;

/* USER CODE BEGIN PV */

/* USER CODE END PV */

/* Private function prototypes -----------------------------------------------*/
void SystemClock_Config(void);
static void MX_GPIO_Init(void);
static void MX_USART2_UART_Init(void);
static void MX_USART1_UART_Init(void);
/* USER CODE BEGIN PFP */

static void sha256_compute(const uint8_t *data, uint32_t len, uint8_t *digest);
static int bootloader_try_launch_app(void);
static void bootloader_jump_to_app(uint32_t app_base);

/* USER CODE END PFP */

/* Private user code ---------------------------------------------------------*/
/* USER CODE BEGIN 0 */

/*
 * Minimal SHA-256 implementation for bootloader digest verification.
 * Public domain, based on FIPS 180-2.
 */
static void sha256_compute(const uint8_t *data, uint32_t total_len, uint8_t *digest)
{
  static const uint32_t K[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2,
  };

  uint32_t H[8] = {
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
    0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
  };

  uint32_t W[64];
  uint32_t a, b, c, d, e, f, g, h, T1, T2;
  uint32_t j;
  uint32_t len = total_len;

  /* Process full 512-bit blocks */
  while (len >= 64) {
    for (j = 0; j < 16; j++) {
      W[j] = ((uint32_t)data[0]<<24) | ((uint32_t)data[1]<<16) |
             ((uint32_t)data[2]<<8) | (uint32_t)data[3];
      data += 4;
    }
    for (j = 16; j < 64; j++) {
      uint32_t s0 = ((W[j-15]>>7)|(W[j-15]<<25)) ^ ((W[j-15]>>18)|(W[j-15]<<14)) ^ (W[j-15]>>3);
      uint32_t s1 = ((W[j-2]>>17)|(W[j-2]<<15)) ^ ((W[j-2]>>19)|(W[j-2]<<13)) ^ (W[j-2]>>10);
      W[j] = W[j-16] + s0 + W[j-7] + s1;
    }
    a = H[0]; b = H[1]; c = H[2]; d = H[3];
    e = H[4]; f = H[5]; g = H[6]; h = H[7];
    for (j = 0; j < 64; j++) {
      uint32_t S1 = ((e>>6)|(e<<26)) ^ ((e>>11)|(e<<21)) ^ ((e>>25)|(e<<7));
      uint32_t ch = (e & f) ^ ((~e) & g);
      T1 = h + S1 + ch + K[j] + W[j];
      uint32_t S0 = ((a>>2)|(a<<30)) ^ ((a>>13)|(a<<19)) ^ ((a>>22)|(a<<10));
      uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      T2 = S0 + maj;
      h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d;
    H[4] += e; H[5] += f; H[6] += g; H[7] += h;
    len -= 64;
  }

  /* Final block with padding */
  uint8_t block[64];
  uint32_t i;
  for (i = 0; i < len; i++) block[i] = data[i];
  block[len++] = 0x80;
  if (len > 56) {
    while (len < 64) block[len++] = 0;
    for (j = 0; j < 16; j++) {
      W[j] = ((uint32_t)block[j*4]<<24) | ((uint32_t)block[j*4+1]<<16) |
             ((uint32_t)block[j*4+2]<<8) | (uint32_t)block[j*4+3];
    }
    for (j = 16; j < 64; j++) {
      uint32_t s0 = ((W[j-15]>>7)|(W[j-15]<<25)) ^ ((W[j-15]>>18)|(W[j-15]<<14)) ^ (W[j-15]>>3);
      uint32_t s1 = ((W[j-2]>>17)|(W[j-2]<<15)) ^ ((W[j-2]>>19)|(W[j-2]<<13)) ^ (W[j-2]>>10);
      W[j] = W[j-16] + s0 + W[j-7] + s1;
    }
    a = H[0]; b = H[1]; c = H[2]; d = H[3];
    e = H[4]; f = H[5]; g = H[6]; h = H[7];
    for (j = 0; j < 64; j++) {
      uint32_t S1 = ((e>>6)|(e<<26)) ^ ((e>>11)|(e<<21)) ^ ((e>>25)|(e<<7));
      uint32_t ch = (e & f) ^ ((~e) & g);
      T1 = h + S1 + ch + K[j] + W[j];
      uint32_t S0 = ((a>>2)|(a<<30)) ^ ((a>>13)|(a<<19)) ^ ((a>>22)|(a<<10));
      uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
      T2 = S0 + maj;
      h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;
    }
    H[0] += a; H[1] += b; H[2] += c; H[3] += d;
    H[4] += e; H[5] += f; H[6] += g; H[7] += h;
    len = 0;
  }
  while (len < 56) block[len++] = 0;
  /* Append length in bits, big-endian */
  {
    uint64_t bitlen = (uint64_t)total_len * 8;
    for (i = 0; i < 8; i++) block[63 - i] = (uint8_t)(bitlen >> (i * 8));
  }
  for (j = 0; j < 16; j++) {
    W[j] = ((uint32_t)block[j*4]<<24) | ((uint32_t)block[j*4+1]<<16) |
           ((uint32_t)block[j*4+2]<<8) | (uint32_t)block[j*4+3];
  }
  for (j = 16; j < 64; j++) {
    uint32_t s0 = ((W[j-15]>>7)|(W[j-15]<<25)) ^ ((W[j-15]>>18)|(W[j-15]<<14)) ^ (W[j-15]>>3);
    uint32_t s1 = ((W[j-2]>>17)|(W[j-2]<<15)) ^ ((W[j-2]>>19)|(W[j-2]<<13)) ^ (W[j-2]>>10);
    W[j] = W[j-16] + s0 + W[j-7] + s1;
  }
  a = H[0]; b = H[1]; c = H[2]; d = H[3];
  e = H[4]; f = H[5]; g = H[6]; h = H[7];
  for (j = 0; j < 64; j++) {
    uint32_t S1 = ((e>>6)|(e<<26)) ^ ((e>>11)|(e<<21)) ^ ((e>>25)|(e<<7));
    uint32_t ch = (e & f) ^ ((~e) & g);
    T1 = h + S1 + ch + K[j] + W[j];
    uint32_t S0 = ((a>>2)|(a<<30)) ^ ((a>>13)|(a<<19)) ^ ((a>>22)|(a<<10));
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    T2 = S0 + maj;
    h = g; g = f; f = e; e = d + T1; d = c; c = b; b = a; a = T1 + T2;
  }
  H[0] += a; H[1] += b; H[2] += c; H[3] += d;
  H[4] += e; H[5] += f; H[6] += g; H[7] += h;

  for (j = 0; j < 8; j++) {
    digest[j*4 + 0] = (uint8_t)(H[j] >> 24);
    digest[j*4 + 1] = (uint8_t)(H[j] >> 16);
    digest[j*4 + 2] = (uint8_t)(H[j] >> 8);
    digest[j*4 + 3] = (uint8_t)(H[j]);
  }
}

/* Search for valid application and launch. Returns 1 if launched (never returns), 0 if not found. */
static int bootloader_try_launch_app(void)
{
  for (uint32_t s = 0; s < NUM_APP_SECTORS; s++) {
    const uint32_t sector_start = SECTOR_INFO[s].start;
    const uint32_t sector_size = SECTOR_INFO[s].size;
    const uint8_t *sector = (const uint8_t *)sector_start;

    /* Search for metadata at 8-byte aligned offsets */
    for (uint32_t offset = 0; offset + sizeof(AppMetadata_t) <= sector_size; offset += 8) {
      const AppMetadata_t *meta = (const AppMetadata_t *)(sector + offset);

      if (memcmp(meta->magic, APP_METADATA_MAGIC, APP_METADATA_FIELD_LEN) != 0) continue;
      if (memcmp(meta->inverted_magic, APP_METADATA_INV_MAGIC, APP_METADATA_FIELD_LEN) != 0) continue;
      if (memcmp(meta->validation, APP_METADATA_VALID, APP_METADATA_FIELD_LEN) != 0) continue;
      if (memcmp(meta->invalidation, APP_METADATA_INVALID, APP_METADATA_FIELD_LEN) != 0) continue;

      /* Metadata found - verify SHA256: sector from start up to (but not including) digest field */
      uint32_t hash_len = offset + (uint32_t)offsetof(AppMetadata_t, sha256);
      uint8_t computed[32];
      sha256_compute(sector, hash_len, computed);

      int match = 1;
      for (int i = 0; i < 32; i++) {
        if (computed[i] != meta->sha256[i]) { match = 0; break; }
      }
      if (!match) continue;

      /* Valid application found - sector starts with Cortex-M4 vector table */
      bootloader_jump_to_app(sector_start);
      /* never returns */
    }
  }
  return 0;
}

static void bootloader_jump_to_app(uint32_t app_base)
{
  const uint32_t *vt = (const uint32_t *)app_base;
  uint32_t msp = vt[0];
  uint32_t reset_handler = vt[1];

  /* Diagnostic: Print vector table values before jump */
#if BOOTLOADER_DEBUG_ENABLE
  {
    char dbg_msg[128];
    int len = sprintf(dbg_msg, "Jump: base=0x%08lX, MSP=0x%08lX, Reset=0x%08lX\r\n", 
                      (unsigned long)app_base, (unsigned long)msp, (unsigned long)reset_handler);
    HAL_UART_Transmit(&huart1, (uint8_t*)dbg_msg, len, 1000);
  }
#endif
  
  /* Validate vector table values */
  if (msp < 0x20000000 || msp > 0x20018000) {
#if BOOTLOADER_DEBUG_ENABLE
    {
      char dbg_msg[128];
      int len = sprintf(dbg_msg, "ERROR: Invalid MSP=0x%08lX\r\n", (unsigned long)msp);
      HAL_UART_Transmit(&huart1, (uint8_t*)dbg_msg, len, 1000);
    }
#endif
    return;
  }
  
  if ((reset_handler & 1) == 0) {
#if BOOTLOADER_DEBUG_ENABLE
    {
      char dbg_msg[128];
      int len = sprintf(dbg_msg, "ERROR: Reset handler missing thumb bit\r\n");
      HAL_UART_Transmit(&huart1, (uint8_t*)dbg_msg, len, 1000);
    }
#endif
    return;
  }
  
  if (reset_handler < 0x08060000 || reset_handler > 0x0807FFFF) {
#if BOOTLOADER_DEBUG_ENABLE
    {
      char dbg_msg[128];
      int len = sprintf(dbg_msg, "WARN: Reset handler outside sector 7: 0x%08lX\r\n", (unsigned long)reset_handler);
      HAL_UART_Transmit(&huart1, (uint8_t*)dbg_msg, len, 1000);
    }
#endif
  }

  /* Deinitialize peripherals before jumping to application */
  HAL_UART_DeInit(&huart1);
  HAL_UART_DeInit(&huart2);
  HAL_GPIO_DeInit(GPIOC, B1_Pin|GPIO_PIN_0|GPIO_PIN_1|GPIO_PIN_2|GPIO_PIN_3|GPIO_PIN_4|GPIO_PIN_5|
                        GPIO_PIN_6|GPIO_PIN_7|GPIO_PIN_8|GPIO_PIN_9|GPIO_PIN_10|GPIO_PIN_11|GPIO_PIN_12);
  HAL_GPIO_DeInit(GPIOA, GPIO_PIN_0|GPIO_PIN_1|GPIO_PIN_4|GPIO_PIN_5|GPIO_PIN_6|GPIO_PIN_7|
                        GPIO_PIN_8|GPIO_PIN_9|GPIO_PIN_10|GPIO_PIN_11|GPIO_PIN_12|GPIO_PIN_15);
  HAL_GPIO_DeInit(GPIOB, GPIO_PIN_0|GPIO_PIN_1|GPIO_PIN_2|GPIO_PIN_4|GPIO_PIN_5|GPIO_PIN_6|
                        GPIO_PIN_7|GPIO_PIN_8|GPIO_PIN_9|GPIO_PIN_10|GPIO_PIN_12|GPIO_PIN_13|
                        GPIO_PIN_14|GPIO_PIN_15);
  HAL_GPIO_DeInit(GPIOD, GPIO_PIN_2);

  /* Reset RCC to default state (HSI) so application can configure clocks cleanly */
  /* This prevents clock configuration conflicts when app tries to reconfigure */
  /* The bootloader has configured HSE+PLL, but well-monitor-2 needs to configure */
  /* its own clocks including LSE. Switching to HSI gives a clean starting state. */
  
#if BOOTLOADER_DEBUG_ENABLE
  {
    char dbg_msg[128];
    int len = sprintf(dbg_msg, "Resetting clocks to HSI...\r\n");
    HAL_UART_Transmit(&huart1, (uint8_t*)dbg_msg, len, 1000);
  }
#endif
  
  /* Ensure HSI is enabled (should be by default, but make sure) */
  __HAL_RCC_HSI_ENABLE();
  while(__HAL_RCC_GET_FLAG(RCC_FLAG_HSIRDY) == RESET) {}
  
  /* Switch system clock to HSI */
  __HAL_RCC_SYSCLK_CONFIG(RCC_SYSCLKSOURCE_HSI);
  while(__HAL_RCC_GET_SYSCLK_SOURCE() != RCC_SYSCLKSOURCE_STATUS_HSI) {}
  
  /* Now safe to disable PLL and HSE - system is running on HSI */
  __HAL_RCC_PLL_DISABLE();
  __HAL_RCC_HSE_CONFIG(RCC_HSE_OFF);
  
  /* Wait for HSE to be disabled */
  uint32_t tickstart = HAL_GetTick();
  while(__HAL_RCC_GET_FLAG(RCC_FLAG_HSERDY) != RESET) {
    if ((HAL_GetTick() - tickstart) > 1000) {  /* 1 second timeout */
      break;
    }
  }
  
  /* Set flash latency for HSI (16MHz) - latency 0 is sufficient */
  FLASH->ACR = (FLASH->ACR & ~FLASH_ACR_LATENCY) | FLASH_LATENCY_0;
  
#if BOOTLOADER_DEBUG_ENABLE
  {
    char dbg_msg[128];
    int len = sprintf(dbg_msg, "Clocks reset, jumping to app...\r\n");
    HAL_UART_Transmit(&huart1, (uint8_t*)dbg_msg, len, 1000);
  }
#endif
  
  /* Reset RCC to default state - this ensures clean clock state for application */
  /* HSI remains enabled as it's the default and app may need it during init */

  __disable_irq();
  __DSB();
  __ISB();

  SCB->VTOR = app_base;
  __set_MSP(msp);

  ((void (*)(void))reset_handler)();
}

/* USER CODE END 0 */

/**
  * @brief  The application entry point.
  * @retval int
  */
int main(void)
{

  /* USER CODE BEGIN 1 */

  /* USER CODE END 1 */

  /* MCU Configuration--------------------------------------------------------*/

  /* Reset of all peripherals, Initializes the Flash interface and the Systick. */
  HAL_Init();

  /* USER CODE BEGIN Init */

  /* USER CODE END Init */

  /* Configure the system clock */
  SystemClock_Config();

  /* USER CODE BEGIN SysInit */

  /* USER CODE END SysInit */

  /* Initialize all configured peripherals */
  MX_GPIO_Init();
  MX_USART2_UART_Init();
  MX_USART1_UART_Init();
  /* USER CODE BEGIN 2 */

  /* Bootloader: search sectors 1-7 for application and launch */
  if (bootloader_try_launch_app()) {
    /* Never returns if app launched */
  }

  /* USER CODE END 2 */

  /* Infinite loop */
  /* USER CODE BEGIN WHILE */
  while (1)
  {
    /* USER CODE END WHILE */

    /* USER CODE BEGIN 3 */
  }
  /* USER CODE END 3 */
}

/**
  * @brief System Clock Configuration
  * @retval None
  */
void SystemClock_Config(void)
{
  RCC_OscInitTypeDef RCC_OscInitStruct = {0};
  RCC_ClkInitTypeDef RCC_ClkInitStruct = {0};

  /** Configure the main internal regulator output voltage
  */
  __HAL_RCC_PWR_CLK_ENABLE();
  __HAL_PWR_VOLTAGESCALING_CONFIG(PWR_REGULATOR_VOLTAGE_SCALE2);

  /** Initializes the RCC Oscillators according to the specified parameters
  * in the RCC_OscInitTypeDef structure.
  */
  RCC_OscInitStruct.OscillatorType = RCC_OSCILLATORTYPE_HSE;
  RCC_OscInitStruct.HSEState = RCC_HSE_ON;
  RCC_OscInitStruct.PLL.PLLState = RCC_PLL_ON;
  RCC_OscInitStruct.PLL.PLLSource = RCC_PLLSOURCE_HSE;
  RCC_OscInitStruct.PLL.PLLM = 12;
  RCC_OscInitStruct.PLL.PLLN = 72;
  RCC_OscInitStruct.PLL.PLLP = RCC_PLLP_DIV2;
  RCC_OscInitStruct.PLL.PLLQ = 7;
  if (HAL_RCC_OscConfig(&RCC_OscInitStruct) != HAL_OK)
  {
    Error_Handler();
  }

  /** Initializes the CPU, AHB and APB buses clocks
  */
  RCC_ClkInitStruct.ClockType = RCC_CLOCKTYPE_HCLK|RCC_CLOCKTYPE_SYSCLK
                              |RCC_CLOCKTYPE_PCLK1|RCC_CLOCKTYPE_PCLK2;
  RCC_ClkInitStruct.SYSCLKSource = RCC_SYSCLKSOURCE_PLLCLK;
  RCC_ClkInitStruct.AHBCLKDivider = RCC_SYSCLK_DIV1;
  RCC_ClkInitStruct.APB1CLKDivider = RCC_HCLK_DIV2;
  RCC_ClkInitStruct.APB2CLKDivider = RCC_HCLK_DIV1;

  if (HAL_RCC_ClockConfig(&RCC_ClkInitStruct, FLASH_LATENCY_2) != HAL_OK)
  {
    Error_Handler();
  }
}

/**
  * @brief USART1 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART1_UART_Init(void)
{

  /* USER CODE BEGIN USART1_Init 0 */

  /* USER CODE END USART1_Init 0 */

  /* USER CODE BEGIN USART1_Init 1 */

  /* USER CODE END USART1_Init 1 */
  huart1.Instance = USART1;
  huart1.Init.BaudRate = 115200;
  huart1.Init.WordLength = UART_WORDLENGTH_8B;
  huart1.Init.StopBits = UART_STOPBITS_1;
  huart1.Init.Parity = UART_PARITY_NONE;
  huart1.Init.Mode = UART_MODE_TX_RX;
  huart1.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart1.Init.OverSampling = UART_OVERSAMPLING_16;
  if (HAL_UART_Init(&huart1) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN USART1_Init 2 */

  /* USER CODE END USART1_Init 2 */

}

/**
  * @brief USART2 Initialization Function
  * @param None
  * @retval None
  */
static void MX_USART2_UART_Init(void)
{

  /* USER CODE BEGIN USART2_Init 0 */

  /* USER CODE END USART2_Init 0 */

  /* USER CODE BEGIN USART2_Init 1 */

  /* USER CODE END USART2_Init 1 */
  huart2.Instance = USART2;
  huart2.Init.BaudRate = 115200;
  huart2.Init.WordLength = UART_WORDLENGTH_8B;
  huart2.Init.StopBits = UART_STOPBITS_1;
  huart2.Init.Parity = UART_PARITY_NONE;
  huart2.Init.Mode = UART_MODE_TX_RX;
  huart2.Init.HwFlowCtl = UART_HWCONTROL_NONE;
  huart2.Init.OverSampling = UART_OVERSAMPLING_16;
  if (HAL_UART_Init(&huart2) != HAL_OK)
  {
    Error_Handler();
  }
  /* USER CODE BEGIN USART2_Init 2 */

  /* USER CODE END USART2_Init 2 */

}

/**
  * @brief GPIO Initialization Function
  * @param None
  * @retval None
  */
static void MX_GPIO_Init(void)
{
  GPIO_InitTypeDef GPIO_InitStruct = {0};
  /* USER CODE BEGIN MX_GPIO_Init_1 */

  /* USER CODE END MX_GPIO_Init_1 */

  /* GPIO Ports Clock Enable */
  __HAL_RCC_GPIOC_CLK_ENABLE();
  __HAL_RCC_GPIOH_CLK_ENABLE();
  __HAL_RCC_GPIOA_CLK_ENABLE();
  __HAL_RCC_GPIOB_CLK_ENABLE();
  __HAL_RCC_GPIOD_CLK_ENABLE();

  /*Configure GPIO pin : B1_Pin */
  GPIO_InitStruct.Pin = B1_Pin;
  GPIO_InitStruct.Mode = GPIO_MODE_IT_FALLING;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(B1_GPIO_Port, &GPIO_InitStruct);

  /*Configure GPIO pins : PC0 PC1 PC2 PC3
                           PC4 PC5 PC6 PC7
                           PC8 PC9 PC10 PC11
                           PC12 */
  GPIO_InitStruct.Pin = GPIO_PIN_0|GPIO_PIN_1|GPIO_PIN_2|GPIO_PIN_3
                          |GPIO_PIN_4|GPIO_PIN_5|GPIO_PIN_6|GPIO_PIN_7
                          |GPIO_PIN_8|GPIO_PIN_9|GPIO_PIN_10|GPIO_PIN_11
                          |GPIO_PIN_12;
  GPIO_InitStruct.Mode = GPIO_MODE_ANALOG;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(GPIOC, &GPIO_InitStruct);

  /*Configure GPIO pins : PA0 PA1 PA4 PA5
                           PA6 PA7 PA8 PA11
                           PA12 PA15 */
  GPIO_InitStruct.Pin = GPIO_PIN_0|GPIO_PIN_1|GPIO_PIN_4|GPIO_PIN_5
                          |GPIO_PIN_6|GPIO_PIN_7|GPIO_PIN_8|GPIO_PIN_11
                          |GPIO_PIN_12|GPIO_PIN_15;
  GPIO_InitStruct.Mode = GPIO_MODE_ANALOG;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(GPIOA, &GPIO_InitStruct);

  /*Configure GPIO pins : PB0 PB1 PB2 PB10
                           PB12 PB13 PB14 PB15
                           PB4 PB5 PB6 PB7
                           PB8 PB9 */
  GPIO_InitStruct.Pin = GPIO_PIN_0|GPIO_PIN_1|GPIO_PIN_2|GPIO_PIN_10
                          |GPIO_PIN_12|GPIO_PIN_13|GPIO_PIN_14|GPIO_PIN_15
                          |GPIO_PIN_4|GPIO_PIN_5|GPIO_PIN_6|GPIO_PIN_7
                          |GPIO_PIN_8|GPIO_PIN_9;
  GPIO_InitStruct.Mode = GPIO_MODE_ANALOG;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(GPIOB, &GPIO_InitStruct);

  /*Configure GPIO pin : PD2 */
  GPIO_InitStruct.Pin = GPIO_PIN_2;
  GPIO_InitStruct.Mode = GPIO_MODE_ANALOG;
  GPIO_InitStruct.Pull = GPIO_NOPULL;
  HAL_GPIO_Init(GPIOD, &GPIO_InitStruct);

  /* USER CODE BEGIN MX_GPIO_Init_2 */

  /* USER CODE END MX_GPIO_Init_2 */
}

/* USER CODE BEGIN 4 */

/* USER CODE END 4 */

/**
  * @brief  This function is executed in case of error occurrence.
  * @retval None
  */
void Error_Handler(void)
{
  /* USER CODE BEGIN Error_Handler_Debug */
  /* User can add his own implementation to report the HAL error return state */
  __disable_irq();
  while (1)
  {
  }
  /* USER CODE END Error_Handler_Debug */
}
#ifdef USE_FULL_ASSERT
/**
  * @brief  Reports the name of the source file and the source line number
  *         where the assert_param error has occurred.
  * @param  file: pointer to the source file name
  * @param  line: assert_param error line source number
  * @retval None
  */
void assert_failed(uint8_t *file, uint32_t line)
{
  /* USER CODE BEGIN 6 */
  /* User can add his own implementation to report the file name and line number,
     ex: printf("Wrong parameters value: file %s on line %d\r\n", file, line) */
  /* USER CODE END 6 */
}
#endif /* USE_FULL_ASSERT */
