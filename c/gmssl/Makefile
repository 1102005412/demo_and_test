OPTION=-I include -lgmcrypto -L lib -g
#all:35114Register_test sm2_test

all: 35114Register_test  sm2_test

35114Register_test:35114Register_test.c
	$(CC) 35114Register_test.c -o 35114Register_test $(OPTION)

sm2_test:sm2_test.c
	$(CC) $< -o $@  $(OPTION)

clean:
	rm 35114Register_test sm2_test  -rvf
