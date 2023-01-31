all: debug

debug: flatnamed.c
	$(CC) -DDEBUG flatnamed.c -o flatnamed

release: flatnamed.c
	$(CC) flatnamed.c -o flatnamed
