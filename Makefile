all: kmsg_simple kmsg_simple_static

kmsg_simple:
	g++ -O2 -std=c++17 main.cpp -o kmsg_simple

kmsg_simple_static:
	g++ -O2 -std=c++17 -static main.cpp -o kmsg_simple_static

clean:
	rm -f kmsg_simple kmsg_simple_static
