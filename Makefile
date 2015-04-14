default: tor-blink.c
	gcc -o torblink tor-blink.c -lwiringPi -lpcap

clean: 
	rm -rf torblink

