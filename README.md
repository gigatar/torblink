# torblink
RaspberryPi application to listen for tor traffic and blink an LED when traffic is seen

This program has two required libraries:
  1. wiringPi: http://wiringpi.com/
  2. libpcap: http://www.tcpdump.org/

The program also requires that you build your circuit to use GPIO port 0 and set iface to your capture port.
