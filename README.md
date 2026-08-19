# Packet Sniffer and Analyzer

This project can be used to sniff and analyze packets being tranfer on your machine via different devices. 

You can see its source/destination MAC address, IP address, Protocol, network type and detect anomalies. 

The `libpcap` library is used in C language as it provides interface to communicate with PCAP driver.

## Current Progress

The source/destination MAC address, IP address, Protocol, network type can be viewed on the terminal.

## Future Work

Add the functionality to detect anomalies, analyze packets and see logs.

## How to use

Clone the repository

```cmd
git clone https://github.com/meet-asati/Packet_Sniffer_And_Analyzer.git

cd Packet_Sniffer_And_Analyzer
```

On Linux/MacOS

```run
sudo apt update
sudo apt install libpcap-dev

gcc main.c -o main.exe -lpcap
./main.exe
```
