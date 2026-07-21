"""

A fake shell that simulates a real Linux system.

The goal is to keep the attacker connected for as long as possible (to capture
more commands) without giving them access to the real system.

The responses are intentionally plausible but not perfect—an attentive human
attacker might notice that it is fake, but automated botnets will not check.

"""


import random

# Simulating a hostname and an consistent user for all session

HOSTNAME = "ubuntu-server"
FAKE_USER = "root"
FAKE_IP = "10.0.0.5"

# fake output for the most common commands tried by attackers
COMMAND_RESPONSE = {
    "whoami": "root",
    "id": "uid=0(root) gid=0(root) groups=0(root)",
    "uname -a": "Linux ubuntu-server 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux",
    "uname": "Linux",
    "pwd": "/root",
    "hostname": HOSTNAME,
    "ls": "snap Documents Downloads",
    "ls -la": """total 40
drwx------ 5 root root 4096 Nov 14 08:22 .
drwxr-xr-x 1 root root 4096 Nov 14 08:20 ..
-rw------- 1 root root  220 Nov 14 08:20 .bash_logout
-rw------- 1 root root 3526 Nov 14 08:20 .bashrc
drwx------ 2 root root 4096 Nov 14 08:22 .cache
drwxr-xr-x 3 root root 4096 Nov 14 08:20 snap
-rw------- 1 root root  807 Nov 14 08:20 .profile""",
    "ls -l": """total 8
drwxr-xr-x 3 root root 4096 Nov 14 08:20 snap
drwxr-xr-x 2 root root 4096 Nov 14 08:20 Documents""",
    "cat /etc/passwd": """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
ubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash""",
    "cat /etc/shadow": "cat: /etc/shadow: Permission denied",
    "cat /etc/hosts": f"""127.0.0.1 localhost
127.0.1.1 {HOSTNAME}
::1 localhost ip6-localhost ip6-loopback""",
    "ifconfig": f"""eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
        inet {FAKE_IP}  netmask 255.255.255.0  broadcast 10.0.0.255
        ether 02:42:ac:11:00:02  txqueuelen 0  (Ethernet)""",
    "ip a": f"""1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536
    link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    link/ether 02:42:ac:11:00:02 brd ff:ff:ff:ff:ff:ff
    inet {FAKE_IP}/24 brd 10.0.0.255 scope global eth0""",
    
    "ps aux": """USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND
root         1  0.0  0.1  18376  2148 ?        Ss   08:20   0:00 /sbin/init
root       423  0.0  0.2  15432  3012 ?        Ss   08:20   0:00 sshd
root       891  0.0  0.1   4628  1832 pts/0    Ss   08:22   0:00 bash""",
    "w": f"""08:22:42 up 2 min,  1 user,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
root     pts/0    {FAKE_IP}        08:22    0.00s  0.01s  0.00s w""",
    "uptime": " 08:22:42 up 2 min,  1 user,  load average: 0.00, 0.00, 0.00",
    "df -h": """Filesystem      Size  Used Avail Use% Mounted on
/dev/sda1        25G  3.2G   21G  14% /
tmpfs           994M     0  994M   0% /dev/shm""",
    "free -h": """              total        used        free
Mem:           1.9G        312M        1.6G
Swap:          2.0G          0B        2.0G""",
    "env": """SHELL=/bin/bash
PWD=/root
HOME=/root
USER=root
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin""",
    "history": """    1  ls
    2  cd /tmp
    3  ls -la""",
    "crontab -l": "no crontab for root",
    "netstat -an": """Active Internet connections (servers and established)
Proto Recv-Q Send-Q Local Address           Foreign Address         State
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN""",
    "exit": "__EXIT__",
    "logout": "__EXIT__"
}

def get_prompt() -> str:
    return f"{FAKE_USER}@{HOSTNAME}:~# "

def handle_command(commnad: str) -> str:

    # Receives a command from the attacker adn returns a fake response
    # Returns '__EXIT__' if the attacker wants to exit the shell
    command = command.strip()

    if not command:
        return ""

    if command in COMMAND_RESPONSES:
        return COMMAND_RESPONSES[command]
    
    #commands that start with common prefix
    if command.startswith("cd "):
        return "" #cd doesn't prints anything

    if command.startswith("echo "):
        return command[5:]

    if command.startswith("cat "):
        path = command[4:].strip()
        
        if "passwd" in path:
            return COMMAND_RESPONSE["cat /etc/passwd"]
        if "shadow" in path:
            return COMMAND_RESPONSE["cat /etc/shadow"]
        return f"cat: {path}: No such file or directory"
    
    if command.startswith("wget ") or command.startswith("curl "):
        # The attackers try to download malwarem, simulated with a timeout
        return "curl: (6) Could not resolve host: connection timed out"
    
    if command.startswith("chmod ") or command.startswith("chown "):
        return "" #looks like it worked but didn't do anything
    
    if command.startswith("python") or command.startswith("perl") or command.startswith("php"): 
        return ""

    if command in ("clear","reset"):
        return ""

    first_word = command.split()[0]
    return f"-bash: {first_word}: command not found"
