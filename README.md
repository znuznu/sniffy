# sniffy
A simple & raw python network sniffer (TCP/UDP protocols) for Linux based systems.  

## Usage examples
Must be run as __root__.    

All ports and TCP/UDP

    $ python3 sniffy.py

All ports and TCP only  

    $ python3 sniffy.py -t 6

TCP and port 80  

    $ python3 sniffy.py -p 80 -t 6

UDP and ports 443 & 80  

    $ python3 sniffy.py -p 80 443 -t 17
