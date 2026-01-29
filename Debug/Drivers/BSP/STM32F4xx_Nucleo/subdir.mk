################################################################################
# Automatically-generated file. Do not edit!
# Toolchain: GNU Tools for STM32 (13.3.rel1)
################################################################################

# Add inputs and outputs from these tool invocations to the build variables 
C_SRCS += \
C:/Users/jthom/STM32Cube/Example/BootLoader/Drivers/BSP/STM32F4xx_Nucleo/stm32f4xx_nucleo.c 

OBJS += \
./Drivers/BSP/STM32F4xx_Nucleo/stm32f4xx_nucleo.o 

C_DEPS += \
./Drivers/BSP/STM32F4xx_Nucleo/stm32f4xx_nucleo.d 


# Each subdirectory must supply rules for building sources it contributes
Drivers/BSP/STM32F4xx_Nucleo/stm32f4xx_nucleo.o: C:/Users/jthom/STM32Cube/Example/BootLoader/Drivers/BSP/STM32F4xx_Nucleo/stm32f4xx_nucleo.c Drivers/BSP/STM32F4xx_Nucleo/subdir.mk
	arm-none-eabi-gcc "$<" -mcpu=cortex-m4 -std=gnu11 -g3 -DDEBUG -DUSE_HAL_DRIVER -DSTM32F401xE -c -I../../Inc -I../../Drivers/STM32F4xx_HAL_Driver/Inc -I../../Drivers/STM32F4xx_HAL_Driver/Inc/Legacy -I../../Drivers/CMSIS/Device/ST/STM32F4xx/Include -I../../Drivers/CMSIS/Include -I../../Drivers/BSP/STM32F4xx_Nucleo -O0 -ffunction-sections -fdata-sections -Wall -fstack-usage -fcyclomatic-complexity -MMD -MP -MF"$(@:%.o=%.d)" -MT"$@" --specs=nano.specs -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb -o "$@"

clean: clean-Drivers-2f-BSP-2f-STM32F4xx_Nucleo

clean-Drivers-2f-BSP-2f-STM32F4xx_Nucleo:
	-$(RM) ./Drivers/BSP/STM32F4xx_Nucleo/stm32f4xx_nucleo.cyclo ./Drivers/BSP/STM32F4xx_Nucleo/stm32f4xx_nucleo.d ./Drivers/BSP/STM32F4xx_Nucleo/stm32f4xx_nucleo.o ./Drivers/BSP/STM32F4xx_Nucleo/stm32f4xx_nucleo.su

.PHONY: clean-Drivers-2f-BSP-2f-STM32F4xx_Nucleo

