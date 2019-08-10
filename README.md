About:

Enea is a simple cli tool written in python for the purpose of uploading multiple hashes to the public Virustotal API.
It is based on the free VirusTotal API, and will send a new hash to the API every 15 seconds.
I have written it for self use and used this tool extensively as a SOC analyst.

Installation:

First you need to tell Enea your VirusTotal API key:

    a) Create a file named key.txt in the same folder as all the .py files.

    b) Insert your VirusTotal API key inside the key.txt file.

    c) Make sure there are no spaces in the file name and close it.

Notes:

Create a .csv file with all the hashes you have, DO NUT PUT ANYTHING THAT IS NOT A HASH INSIDE THIS FILE.

Flags:

    Must:

        -f [file.csv] - specify the csv in the local folder or a full path to the csv file.

    Optional:

        -r [number of days] - Will rescan results that are older than the number of days you specified.

         0 will make scan all files anew

        -v is verbose, will print the result for every hash.

Examples:

#To simply get results from VirusTotal:

Enea.py -f hashes.csv -v

#To ignore the data of previous scans and rescan anew all the hashes:

Enea.py -f hashes.csv -r 0 -v


#To scan all the hashes but also rescan hashes whole results are older then 7 days:

Enea.py -f hashes.csv -r 7 -v
