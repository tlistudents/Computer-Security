#!/bin/bash  
  
for i in {1..74} 
do   
    procmail .procmailrc < ./ece404/junkMail_$i
done