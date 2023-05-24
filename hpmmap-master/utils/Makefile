CC=gcc -DDEBUG -g 

all: mem_ctrl launcher

mem_ctrl: mem_ctrl.c pet_mem.c ../interface.h
	$(CC) mem_ctrl.c pet_mem.c -o mem_ctrl

launcher: launcher.c ../interface.h
	$(CC) launcher.c -o launcher -lnuma

clean:	
	-rm mem_ctrl launcher
