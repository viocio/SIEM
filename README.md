This is a minimalist SIEM.
It is used for securing a network.

Its functionality consists of 3 main blocks: an agent script, a manager script and syslog database.

The agent script runs on endpoint devices with Linux based OS-es. It periodically runs 3 functions, one that checks the local file for failed 3 consecutive logins, one that runs a "ss -tp" command 
and watches for possibly remote connections, and one that checks if ussually malware targeted files have been modified. If any of the functions determines that a possible threat is detected, an alert
is sent to the manager script. The function that checks for remote acces, actually also kills that procces.

In the project directory you have to open three servers, the syslog listener, the manager and the blacklist server. The syslog listener server listens for messages sent by the network devices on port
514 UDP. The format of the syslogs has to be RFC3164 for it to be parsed and then be introduced in the database. The manager calls 3 functions from the pkg/detectie package. Each of these functions
queries the database and takes a decision of wheter it exists a possible attack or not.

The three functions check for brute force attacks, possible port scans or exfiltration. If any is met, the manager will display a warning in a console in the form of an alert. These functions also 
parse the messages in the databse for the IPs these attacks originated from and adds them into a blacklist.txt file. A server must pe opened to serve the IPs to the network devices and they can be
configured to block traffic from those IPs.
