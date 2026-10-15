obj-m += gxfp51b7_native.o
obj-m += gxfp51b7_sealed.o
KDIR ?= /usr/lib/modules/$(shell uname -r)/build

all:
	$(MAKE) -C $(KDIR) M=$(CURDIR) W=1 modules

check:
	$(CC) -Wall -Wextra -Werror -fsanitize=address,undefined -g test_frame.c -o test_frame
	ASAN_OPTIONS=detect_leaks=0 ./test_frame
	$(CC) -Wall -Wextra -Werror -fsanitize=address,undefined -g test_blob.c -o test_blob
	ASAN_OPTIONS=detect_leaks=0 ./test_blob
	$(CC) -Wall -Wextra -Werror -fsanitize=address,undefined -g test_tls_hello.c -o test_tls_hello
	ASAN_OPTIONS=detect_leaks=0 ./test_tls_hello
	$(CC) -Wall -Wextra -Werror -fsanitize=address,undefined -g test_chicago_config.c -o test_chicago_config
	ASAN_OPTIONS=detect_leaks=0 ./test_chicago_config
	$(CC) -Wall -Wextra -Werror -fsanitize=address,undefined -g test_chicago_factory_bus.c -o test_chicago_factory_bus
	ASAN_OPTIONS=detect_leaks=0 ./test_chicago_factory_bus

clean:
	$(MAKE) -C $(KDIR) M=$(CURDIR) clean
	$(RM) test_frame test_blob test_tls_hello test_chicago_config test_chicago_factory_bus
