CC=gcc
FLAGS=-std=c11 -Wall -Wextra -pedantic
LDFLAGS=-shared -fPIC -lcap -ldl

all: detach preload preload-detach
	$(CC) $(FLAGS) $(LDFLAGS) sandkox.c -o sandkox.so

detach:
	$(CC) -DSANDKOX_DETACH_CHILD__ \
	$(FLAGS) $(LDFLAGS) sandkox.c -o sandkox-detach.so

preload:
	$(CC) -DSANDKOX_NOSTARTFILES__ \
	$(FLAGS) -nostartfiles $(LDFLAGS) sandkox.c -o sandkox-preload.so

preload-detach:
	$(CC) -DSANDKOX_DETACH_CHILD__ -DSANDKOX_NOSTARTFILES__ \
	$(FLAGS) -nostartfiles $(LDFLAGS) sandkox.c -o sandkox-preload-detach.so
	
clean:
	rm sandkox*so
