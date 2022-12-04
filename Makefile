all: main.c
	gcc -o kgadget_finder main.c
clean:
	rm kgadget_finder
