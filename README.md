# 5G-UE-SecurityTesting

## Description

This project, **5G-UE-SecurityTesting**, is currently a work in progress. It focuses on security testing for 5G Standalone User Equipment (UE). The objective of this project is to develop a comprehensive framework for assessing the security aspects of 5G UE devices.

## Table of Contents

- [Description](#description)
- [Installation](#installation)
- [Usage](#usage)
- [License](#license)
- [Reference](#reference)

## Installation

### srsRAN
prerequisite:  sudo apt-get install build-essential cmake libfftw3-dev libmbedtls-dev libboost-program-options-dev libconfig++-dev libsctp-dev
1. cd srsRAN    
2. mkdir build    
3. cd build
4. cmake ../
5. make
6. sudo make install
   
More details on srsRAN installation can be found at: https://docs.srsran.com/projects/4g/en/latest/general/source/1_installation.html
    
### open5GS
prerequisite:  apt install python3-pip python3-setuptools python3-wheel ninja-build build-essential flex bison git cmake libsctp-dev libgnutls28-dev libgcrypt-dev libssl-dev libidn11-dev libmongoc-dev libbson-dev libyaml-dev libnghttp2-dev libmicrohttpd-dev libcurl4-gnutls-dev libnghttp2-dev libtins-dev libtalloc-dev meson libjson0 libjson0-dev
1. cd open5gs
2. meson build --prefix=`pwd`/install
3. ninja -C build
4. cd build
5. ninja install
   
More details on open5gs installation can be found at: https://open5gs.org/open5gs/docs/guide/01-quickstart/

### cJSON
1. git colne https://github.com/DaveGamble/cJSON.git
2. cd cJSON
3. mkdir build
4. cd build
5. cmake ..
6. make
7. sudo make install

### MongoDB
1. sudo apt update
2. sudo apt install -y mongodb-org
3. sudo systemctl start mongod (if '/usr/bin/mongod' is not running)
4. sudo systemctl enable mongod (ensure to automatically start it on system boot)

### NodeJS
1. sudo apt install curl
2. curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
3. sudo apt install nodejs

### Open5GS web UI
curl -fsSL https://open5gs.org/open5gs/assets/webui/install | sudo -E bash -


## Usage

The usage instructions will be provided shortly.

## License

The **5G-UE-SecurityTesting** project is open-source. The specific license details will be provided later.

## Reference

If you are using or referencing this project, please cite the following paper:

[UE Security Reloaded: Developing a 5G Standalone User-Side Security Testing Framework](https://wisec2023.surrey.ac.uk/accepted-papers/#UE_Security_Reloaded__Developing_a_5G_Standalone_User_Side_Security_Testing_Framework)<br>
Evangelos Bitsikas, Syed Khandker, Ahmad Salous, Aanjhan Ranganathan, Roger Piqueras Jover, and Christina Pöpper<br>
16th ACM Conference on Security and Privacy in Wireless and Mobile Networks (WiSec '23), Guildford, Surrey, UK

Please note that the paper will be linked here once it is available.
