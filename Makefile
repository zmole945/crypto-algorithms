
#CFLAGS = -Wall

all : aes arcfour base64 blowfish des md2 md5 rot-13 sha1 sha256 sm3 sm4

base_obj = cryptoalg_debug.o

aes : ${base_obj}
	$(CC) $(CFLAGS) -o aes_test aes.c aes_test.c ${base_obj}

arcfour : ${base_obj}
	$(CC) $(CFLAGS) -o arcfour_test arcfour.c arcfour_test.c ${base_obj}

base64 : ${base_obj}
	$(CC) $(CFLAGS) -o base64_test base64.c base64_test.c ${base_obj}

blowfish : ${base_obj}
	$(CC) $(CFLAGS) -o blowfish_test blowfish.c blowfish_test.c ${base_obj}

des : ${base_obj}
	$(CC) $(CFLAGS) -o des_test des.c des_test.c ${base_obj}

md2 : ${base_obj}
	$(CC) $(CFLAGS) -o md2_test md2.c md2_test.c ${base_obj}

md5 : ${base_obj}
	$(CC) $(CFLAGS) -o md5_test md5.c md5_test.c ${base_obj}

rot-13 : ${base_obj}
	$(CC) $(CFLAGS) -o rot-13_test rot-13.c rot-13_test.c ${base_obj}

sha1 : ${base_obj}
	$(CC) $(CFLAGS) -o sha1_test sha1.c sha1_test.c ${base_obj}

sha256 : ${base_obj}
	$(CC) $(CFLAGS) -o sha256_test sha256.c sha256_test.c ${base_obj}

sm3 : ${base_obj}
	$(CC) $(CFLAGS) -o sm3_test sm3.c sm3_test.c ${base_obj}

sm4 : ${base_obj}
	$(CC) $(CFLAGS) -o sm4_test sm4.c sm4_test.c ${base_obj}

doxygen :
	doxygen Doxyfile
doxygen_clean :
	rm -rf doc/

clean :
	rm -rf *.o
	rm -rf aes_test
	rm -rf arcfour_test
	rm -rf base64_test
	rm -rf blowfish_test
	rm -rf des_test
	rm -rf md2_test
	rm -rf md5_test
	rm -rf rot-13_test
	rm -rf sha1_test
	rm -rf sha256_test
	rm -rf sm3_test
	rm -rf sm4_test

