import { MALICIOUS_IPS } from "./threat-intel";

const USERS = ["root", "admin", "ubuntu", "deploy", "oracle", "postgres", "test", "git", "svc_backup"];
const HOSTS = ["bastion-01", "app-node-03", "db-primary", "web-frontend-01", "fw-edge"];
const FUZZ_PATHS = ["/.env", "/wp-login.php", "/admin/config.php", "/.git/HEAD", "/phpmyadmin/", "/actuator/env", "/backup.zip", "/.aws/credentials", "/cgi-bin/test.cgi"];
const TRAVERSAL = ["/../../../../etc/passwd", "/images/..%2F..%2F..%2Fetc%2Fshadow", "/static/../../../proc/self/environ", "/download?file=../../../../boot.ini"];
const SQLI = ["/products?id=1' UNION SELECT username,password FROM users--", "/login?user=admin' OR 1=1--", "/api/items?id=1;DROP TABLE sessions", "/search?q=1' AND SLEEP(5)--"];
const UAS = ["sqlmap/1.8.2#stable (https://sqlmap.org)", "Mozilla/5.0 (Nikto/2.5.0)", "gobuster/3.6", "Fuzz Faster U Fool v2.1.0", "python-requests/2.32.3", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/128.0 Safari/537.36"];
const PORTS = [22, 23, 80, 443, 445, 3389, 3306, 5432, 6379, 8080, 8443, 27017];

const pick = <T>(arr: readonly T[]): T => arr[Math.floor(Math.random() * arr.length)] as T;
const rndIp = () => `${Math.floor(Math.random() * 223) + 1}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 255)}.${Math.floor(Math.random() * 254) + 1}`;
const attackerIp = () => (Math.random() < 0.7 ? pick(MALICIOUS_IPS) : rndIp());

function syslogTs(d = new Date()) {
  const mon = d.toLocaleString("en-US", { month: "short" });
  return `${mon} ${String(d.getDate()).padStart(2, " ")} ${d.toTimeString().slice(0, 8)}`;
}
function apacheTs(d = new Date()) {
  const mon = d.toLocaleString("en-US", { month: "short" });
  const off = -d.getTimezoneOffset();
  const sign = off >= 0 ? "+" : "-";
  const hh = String(Math.floor(Math.abs(off) / 60)).padStart(2, "0");
  const mm = String(Math.abs(off) % 60).padStart(2, "0");
  return `${String(d.getDate()).padStart(2, "0")}/${mon}/${d.getFullYear()}:${d.toTimeString().slice(0, 8)} ${sign}${hh}${mm}`;
}

export type Scenario = "ssh-brute" | "web-fuzz" | "traversal" | "sqli" | "fw-drop" | "port-scan" | "sudo" | "login-after-brute";

export function generateScenario(scenario?: Scenario): string[] {
  const s: Scenario = scenario ?? pick(["ssh-brute", "web-fuzz", "traversal", "sqli", "fw-drop", "port-scan", "sudo", "ssh-brute", "fw-drop"] as const);
  const ip = attackerIp();
  const lines: string[] = [];
  const pid = Math.floor(Math.random() * 60000) + 1000;

  switch (s) {
    case "ssh-brute": {
      const host = pick(HOSTS);
      const user = pick(USERS);
      const n = 3 + Math.floor(Math.random() * 3);
      for (let i = 0; i < n; i++) {
        const invalid = Math.random() < 0.5;
        lines.push(`${syslogTs()} ${host} sshd[${pid + i}]: Failed password for ${invalid ? "invalid user " : ""}${user} from ${ip} port ${40000 + Math.floor(Math.random() * 20000)} ssh2`);
      }
      break;
    }
    case "login-after-brute": {
      const host = pick(HOSTS);
      const user = pick(["root", "admin", "deploy"]);
      for (let i = 0; i < 4; i++) lines.push(`${syslogTs()} ${host} sshd[${pid + i}]: Failed password for ${user} from ${ip} port ${41000 + i} ssh2`);
      lines.push(`${syslogTs()} ${host} sshd[${pid + 9}]: Accepted password for ${user} from ${ip} port 41009 ssh2`);
      break;
    }
    case "web-fuzz": {
      const ua = pick(UAS.slice(0, 5));
      const n = 3 + Math.floor(Math.random() * 3);
      for (let i = 0; i < n; i++) lines.push(`${ip} - - [${apacheTs()}] "GET ${pick(FUZZ_PATHS)} HTTP/1.1" ${pick([404, 403, 401])} ${Math.floor(Math.random() * 600) + 150} "-" "${ua}"`);
      break;
    }
    case "traversal":
      lines.push(`${ip} - - [${apacheTs()}] "GET ${pick(TRAVERSAL)} HTTP/1.1" ${pick([200, 400, 403])} ${Math.floor(Math.random() * 2000) + 300} "-" "${pick(UAS)}"`);
      break;
    case "sqli":
      lines.push(`${ip} - - [${apacheTs()}] "GET ${pick(SQLI)} HTTP/1.1" ${pick([500, 200, 403])} ${Math.floor(Math.random() * 3000) + 300} "-" "${pick(UAS)}"`);
      break;
    case "fw-drop": {
      const dst = `10.0.${Math.floor(Math.random() * 5)}.${Math.floor(Math.random() * 200) + 1}`;
      const n = 1 + Math.floor(Math.random() * 2);
      for (let i = 0; i < n; i++) lines.push(`${syslogTs()} fw-edge kernel: [${(Math.random() * 99999).toFixed(6)}] [UFW BLOCK] IN=eth0 OUT= MAC=00:16:3e:5a:bc:11 SRC=${ip} DST=${dst} LEN=40 TOS=0x00 PREC=0x00 TTL=${Math.floor(Math.random() * 100) + 40} ID=${Math.floor(Math.random() * 65535)} PROTO=TCP SPT=${Math.floor(Math.random() * 60000) + 1024} DPT=${pick(PORTS)} WINDOW=1024 RES=0x00 SYN URGP=0`);
      break;
    }
    case "port-scan": {
      const dst = `10.0.1.${Math.floor(Math.random() * 200) + 1}`;
      const shuffled = [...PORTS].sort(() => Math.random() - 0.5).slice(0, 5);
      for (const p of shuffled) lines.push(`${syslogTs()} fw-edge kernel: [${(Math.random() * 99999).toFixed(6)}] [UFW BLOCK] IN=eth0 OUT= MAC=00:16:3e:5a:bc:11 SRC=${ip} DST=${dst} LEN=44 TOS=0x00 PREC=0x00 TTL=52 ID=${Math.floor(Math.random() * 65535)} PROTO=TCP SPT=${Math.floor(Math.random() * 60000) + 1024} DPT=${p} WINDOW=65535 RES=0x00 SYN URGP=0`);
      break;
    }
    case "sudo": {
      const host = pick(HOSTS);
      const user = pick(["www-data", "deploy", "jenkins"]);
      lines.push(`${syslogTs()} ${host} sudo: ${user} : TTY=pts/2 ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash`);
      break;
    }
  }
  return lines;
}

export const SAMPLE_LOGS = `Sep 19 14:02:11 bastion-01 sshd[2211]: Failed password for invalid user admin from 218.92.0.107 port 51122 ssh2
Sep 19 14:02:13 bastion-01 sshd[2212]: Failed password for invalid user admin from 218.92.0.107 port 51130 ssh2
Sep 19 14:02:15 bastion-01 sshd[2213]: Failed password for root from 218.92.0.107 port 51141 ssh2
Sep 19 14:02:18 bastion-01 sshd[2214]: Failed password for root from 218.92.0.107 port 51150 ssh2
Sep 19 14:03:01 bastion-01 sshd[2230]: Accepted publickey for deploy from 10.0.4.22 port 39012 ssh2
45.155.205.233 - - [19/Sep/2026:14:04:22 +0530] "GET /images/..%2F..%2F..%2Fetc%2Fpasswd HTTP/1.1" 403 318 "-" "Mozilla/5.0 (Nikto/2.5.0)"
196.251.84.19 - - [19/Sep/2026:14:04:40 +0530] "GET /products?id=1' UNION SELECT username,password FROM users-- HTTP/1.1" 500 1204 "-" "sqlmap/1.8.2#stable (https://sqlmap.org)"
23.129.64.130 - - [19/Sep/2026:14:05:02 +0530] "GET /.env HTTP/1.1" 404 196 "-" "gobuster/3.6"
23.129.64.130 - - [19/Sep/2026:14:05:02 +0530] "GET /.git/HEAD HTTP/1.1" 404 196 "-" "gobuster/3.6"
23.129.64.130 - - [19/Sep/2026:14:05:03 +0530] "GET /wp-login.php HTTP/1.1" 404 196 "-" "gobuster/3.6"
Sep 19 14:06:10 fw-edge kernel: [88123.442101] [UFW BLOCK] IN=eth0 OUT= MAC=00:16:3e:5a:bc:11 SRC=91.240.118.172 DST=10.0.1.15 LEN=44 TOS=0x00 PREC=0x00 TTL=52 ID=54321 PROTO=TCP SPT=44011 DPT=22 WINDOW=65535 RES=0x00 SYN URGP=0
Sep 19 14:06:10 fw-edge kernel: [88123.442188] [UFW BLOCK] IN=eth0 OUT= MAC=00:16:3e:5a:bc:11 SRC=91.240.118.172 DST=10.0.1.15 LEN=44 TOS=0x00 PREC=0x00 TTL=52 ID=54322 PROTO=TCP SPT=44012 DPT=3389 WINDOW=65535 RES=0x00 SYN URGP=0
Sep 19 14:06:11 fw-edge kernel: [88123.442255] [UFW BLOCK] IN=eth0 OUT= MAC=00:16:3e:5a:bc:11 SRC=91.240.118.172 DST=10.0.1.15 LEN=44 TOS=0x00 PREC=0x00 TTL=52 ID=54323 PROTO=TCP SPT=44013 DPT=445 WINDOW=65535 RES=0x00 SYN URGP=0
Sep 19 14:06:11 fw-edge kernel: [88123.442301] [UFW BLOCK] IN=eth0 OUT= MAC=00:16:3e:5a:bc:11 SRC=91.240.118.172 DST=10.0.1.15 LEN=44 TOS=0x00 PREC=0x00 TTL=52 ID=54324 PROTO=TCP SPT=44014 DPT=6379 WINDOW=65535 RES=0x00 SYN URGP=0
Sep 19 14:07:45 app-node-03 sudo: www-data : TTY=pts/2 ; PWD=/var/www ; USER=root ; COMMAND=/bin/bash`;
