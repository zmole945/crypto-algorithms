
all : aes arcfour base64 blowfish des md2 md5 rot-13 sha1 sha256

aes : 
	$(CC) -o aes_test aes.c aes_test.c

arcfour :
	$(CC) -o arcfour_test arcfour.c arcfour_test.c

base64 :
	$(CC) -o base64_test base64.c base64_test.c

blowfish :
	$(CC) -o blowfish_test blowfish.c blowfish_test.c

des :
	$(CC) -o des_test des.c des_test.c

md2 :
	$(CC) -o md2_test md2.c md2_test.c

md5 :
	$(CC) -o md5_test md5.c md5_test.c

rot-13 :
	$(CC) -o rot-13_test rot-13.c rot-13_test.c

sha1 :
	$(CC) -o sha1_test sha1.c sha1_test.c

sha256 :
	$(CC) -o sha256_test sha256.c sha256_test.c

clean :
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

