all: debug

CC=gcc

#-pg for gprof
debug: flatnamed.c
	$(CC)  -DDEBUG -pg  -std=gnu99  flatnamed.c -o flatnamed

release: flatnamed.c
	$(CC) -O3  -std=gnu99  flatnamed.c -o flatnamed
