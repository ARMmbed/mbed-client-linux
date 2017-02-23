This repository contains the Yotta module with Linux OS specific components required by mbed-client.
The components are:
1) Linux BSD Socket APIs
2) Linux Thread APIs


See https://github.com/ARMmbed/mbed-client-linux-example for reference on how this module is used with mbed-client.

# Running unittests
The unittests require some additional dependencies to be installed. `Cpputest`, `lcov`, `xsltproc` and `gcovr` are needed. On Ubuntu/Debian these can be installed with the following commands:
`sudo apt-get install cpputest lcov xsltproc` and `pip install gcovr`

Unittests can be run using the `make`command like so:
`make test`
