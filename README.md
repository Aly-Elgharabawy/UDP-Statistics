# UDP-Statistics
## Overview
A small Linux C++ project that sniffs incoming UDP packets using libpcap for a window of time and displays statistics for that stream.

### Statistics displayed:
* Total packet size
* Number of packets
* Average packet size
* Average bitrate
* Average shannon entropy for UDP payload data

The idea of this project is to provide a basis for a UDP stream classifier that will use extracted packet
metadata as features to classify the type of incoming data in UDP streams (e.g. video streaming, VoIP, online gaming).

NOTE: For the moment, streams are ~1 second windows that are not separated by source IP or port.

## Build/Run Instructions
NOTE: This program requires superuser access to run.<br />

To build this program, navigate to the respository in the terminal and run the command below:
```
make
```
To run this program, run the terminal command below in the same directory:
```
make run
```
Alternatively you can run the following terminal commands in the repository's directory:
```
g++ -O3 -o build/UDP-Statistics src/UDP-Statistics.cpp -lpcap
```

```
sudo build/UDP-Statistics
```
## TODO
* Streams by IP/Port instead of time window.
* Better C++ file structure.
* Design and implement UDP stream classifier.
* Use separate threads for sniffing, classification, and extraction.  
