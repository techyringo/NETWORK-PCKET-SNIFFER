# NETWORK-PACKET-SNIFFER
It Is sniffing the network and  saving the data into csv file..only source and destination.After that i am plotting the bipartite graph between source and destination.and then i am plotting mobile patent suits graph using d3.js

#### How To Run
Before Going To Run You Must have these in your system
- Python(Download Link :- https://www.python.org/downloads/)
- GCC Compiler (Download Link :- https://gcc.gnu.org/)
- pcap library (Download Linl :- https://www.winpcap.org/install/)

 Some basic Git commands are:
```
git status
git add
git commit
```

###### To gathered Information/ Sniffing Over the all Sniffing point 
1.Just Run The Projecttool.c file
1.1 DEMO-
   gcc <filetype.c> -lpcap

To Run The Python file
1.python3 packsniff.py
2.python3 bipartitegraph.py (If You Want the PNG image of Bipartite Graph otherwise don't run it.)

Then With the json data Run The html file
1.Simply click on the html file [it's Fully Automatic graph plotting keep refreshing the page according to your requirement otherwise it will refresh the page after 5sec]

N.B : According To your user data/ Network Traffic  set this to [1-infinte] (set here see this line at the packsniff.py code -> [if len(obj['links']) < 200]: and paste [any postive no at the place of 200]

If You have any doubt and want to modify this just mail me..
Thanks,
Ringo..
