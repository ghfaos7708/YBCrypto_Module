RM := rm -rf

C_SRCS += \
blockcipher_core.c \
ctr_drbg.c \
ctrdrbg_core.c \
entropy.c \
hash.c \
hash_core.c \
hmac.c \
hmac_core.c \
KAT_test.c \
mode.c \
mode_core.c \
YBCrypto.c \
integrity.c

OBJS += \
./build/blockcipher_core.o \
./build/ctr_drbg.o \
./build/ctrdrbg_core.o \
./build/entropy.o \
./build/hash.o \
./build/hash_core.o \
./build/hmac.o \
./build/hmac_core.o \
./build/KAT_test.o \
./build/mode.o \
./build/mode_core.o \
./build/YBCrypto.o \
./build/integrity.o

C_DEPS += \
./build/blockcipher_core.d \
./build/ctr_drbg.d \
./build/ctrdrbg_core.d \
./build/entropy.d \
./build/hash.d \
./build/hash_core.d \
./build/hmac.d \
./build/hmac_core.d \
./build/KAT_test.d \
./build/mode.d \
./build/mode_core.d \
./build/YBCrypto.d \
./build/integrity.d

build/%.o: %.c
	@echo 'Building file: $<'
	@echo 'Invoking: GCC C Compiler'
	mkdir -p build
	gcc -O3 -Werror -c -fmessage-length=0 -fvisibility=hidden -fPIC -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@)" -o "$@" "$<"
	@echo 'Finished building: $<'
	@echo ' '

USER_OBJS :=

LIBS := -ldl

ifneq ($(MAKECMDGOALS),clean)
ifneq ($(strip $(C_DEPS)),)
-include $(C_DEPS)
endif
endif


#! All Target
all: YBCrypto.so

#! Tool invocations
YBCrypto.so: $(OBJS) $(USER_OBJS)
	@echo 'Building target: $@'
	@echo 'Invoking: GCC C Linker'
	gcc -shared -o "YBCrypto.so" $(OBJS) $(USER_OBJS) $(LIBS)
	@echo 'Finished building target: $@'
	@echo ' '

#! Other Targets
clean:
	-$(RM) $(LIBRARIES)$(OBJS)$(C_DEPS) YBCrypto.so
	-$(RM) ./build
	-@echo ' '

.PHONY: all clean dependents
.SECONDARY: