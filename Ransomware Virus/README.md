# Ransomware Virus
* Encrypt all specified types of file with random generated key
* Encryption key automatically upload to server with user ID
* Decryption program automatically generated with user ID
* Blackmail automatically pop up after all files are encrepted
* Recover all encrepted files using the generated decryption program
* Encryption program is not detectable by antivirus software
---
## 
I was thinking about making a simple blackmail window program embedded in the ransomware main program, where the PC owner can contact the hacker directly via the blackmail window, and the hacker can use the blackmail window program decrypte all the encrepted files in this PC remotely, this can be done using Websocket and the communication will be protected by the Tor routing.

##
But this is for my study and educational purpose only, the blackmail window is not a necessary feature, instead, most ransomware program will leave hacker's email/other contact information and ask you to contact them directly, for example, my blackmail pop up can leave my contact information and my cryptocurrency wallect address

##
The implementation of the blackmail window program is not complicated, I may make one in the future just for fun.

---
# Demo
## Files encrypted and upload key to the server with ID identification for management purpose
https://user-images.githubusercontent.com/70169080/187103672-c142e022-4679-41ba-b318-5680ebc01831.mp4

## Files recovery/decrypt using decryption program on the server

https://user-images.githubusercontent.com/70169080/187103673-9c63e60f-7043-4b34-9ecb-bdf7db69a868.mp4

---
## This project is not for harmful usage, it's for my study only, to prevent illegal usage/people accidentally run the virus program, source code and main program of this project will not be published

If you are interesting in encryption, you can look at my [DES](https://github.com/tlistudents/Computer-Security/tree/main/DES), [RSA](https://github.com/tlistudents/Computer-Security/tree/main/RSA), [AES](https://github.com/tlistudents/Computer-Security/tree/main/AES) encryption implmentation for my school project, it would be better to use more efficiency language like C/C++ instead of Python in practical, since encryption speed and resource usage is critical in computer security(eg, it would be easy to detect the virus if it keeps running on the background and use ton's of computing resource, but if the encryption happens instantly you won't even get the chance to catch the virus)
---
## My other computer security project can be found [here](https://github.com/tlistudents/Computer-Security) 
