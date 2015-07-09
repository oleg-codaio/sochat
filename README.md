sochat
======
soChat - secure instant messaging service.

Implementation
--------------
This is a server-based messaging service. The assumptions are that the
server contains the list of usernames, and the respective salted Lamport's
n-fold hashes.

The login protocol for each client securely establishes a symmetric key for
client-server communication.

Actual messaging between clients is established though a modified
Needham-Schroeder protocol; the server is used as an intermediary to mutually
verify the clients' identities and establish an ephemeral shared key.

Installation and Runnning
-------------------------
First, go into the `_bin/` directory, which contains runnable JAR files.

These instructions are for Windows. Both the client and the server have
configuration files.

To run the server: `java -jar server.jar 9000`

To run the client: `java -jar client.jar`

Registered users:

    Username          Password 
    saba              sabap
    oleg              olegp
    joni              jonip
    amirali           amirp
    guevara           guevp


Usage
-------------------------------------------

To get a list of connected users, type: 

    list 

in the command prompt. This command is called automatically when a 
user connects at first. To send a message to another user, for example, 
to send a message to oleg as saba, type: 

    send oleg WHATEVERMESSAGEYOUWANTTOSEND

into the command prompt. The thing to note here is that it is only possible
to send a message to the user you know is connected, thus, if you have called
the list command and the recipient user has showed up on that list. If the user
you want to send a message to connected after your last list command, you
won't be able to send him a message unless he contacts you first or until you 
call the list command again.
