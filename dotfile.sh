readme() {
echo 'What is this?
This is a bunch of scripts to help automate out some of the external pentest process

What do they do?

START HERE IF YOU WANT TO EXPAND SCOPE
1. apex_expand_scope
  * Input: an apex domain like acme.com
  * Output: a file of fqdns of all subdomains found 
  * Used By: rustscan_scan, fqdns functions
2. apex_quick
  * Input: an apex domain like acme.com
  * Output: a file of fqdns all subdomains found for each apex, top 1000 port scan, with nuclei results ran for all of the web servers
  * Used By: rustscan_scan, fqdns functions

2.5 apex_nuclei (optional/helper)
  * Input: an apex domain like acme.com
  * Output: a file of fqdns all subdomains found for each apex, with nuclei ran on all of them
  * Used By: N/A

START HERE IF YOU ARE NOT EXPANDING SCOPE
3. scope_scan_all
  * Input: a file with hosts (or IPs) separated by newlines
  * Output: a scan of all TCP ports for specific hosts, a file of all hosts running web servers, and a flyover of screenshots of all web servers found
  * Used By: fqdns_crawl/feroxbuster_urls, fqdns_nuclei/url_nuclei
4. fqdns_crawl
  * Input: a file with webhosts (or IPs) and ports separated by newlines (from rustscan_scan or apex_quick)
  * Output: Runs httpx to fingerprint webserver, feroxbuster, and then katana for spidering
  * Used By: N/A
4.5. urls_feroxbuster (optional/helper) - must be called by cat-ing a file
  * Input: a file with webhosts (or IPs) and ports separated by newlines (from rustscan_scan or apex_quick)
  * Output: feroxbuster scan on each host
  * Used By: N/A
5. fqdns_nuclei
  * Input: a file with hosts webhosts (or IPs) and ports separated by newlines
  * Output: nuclei scan of all hosts running web servers
  * Used By: N/A
6. flyover
  * Input: a file with webhosts (or IPs) and ports separated by newlines (from rustscan_scan or apex_quick)
  * Output: a gowitness flyover of all top level site content (Work in progress to get snapshots of content discovered in crawling)
  * Used By: N/A
'
}


get_web_servers() {
    nmap_parser *.gnmap --web
}

install_go() {
    wget "https://go.dev/dl/go1.25.5.linux-amd64.tar.gz" -O /tmp/go.linux-amd64.tar.gz
    sudo rm -rf /usr/local/go
    sudo tar -C /usr/local -xzf /tmp/go.linux-amd64.tar.gz
    echo "export PATH=$HOME/go/bin:/usr/local/share:/usr/local/go/bin:$HOME/.local/bin:/usr/local/sbin:/usr/bin:/sbin:/bin" >> "$HOME/.zshrc"
}

install_go_tools() {
    sudo apt install -y libpcap-dev tmux time parallel git make gcc
    # kalis pre packaged amass is missing some critical features such as 'intel'
    sudo apt remove -y amass
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
    CGO_ENABLED=1 go install -v github.com/projectdiscovery/katana/cmd/katana@latest
    go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
    go install -v github.com/owasp-amass/amass/v4/...@master
    go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
    go install -v github.com/tomnomnom/anew@latest
    go install -v github.com/tomnomnom/unfurl@latest
    go install -v github.com/OJ/gobuster/v3@latest
    go install -v github.com/lc/gau/v2/cmd/gau@latest
    go install -v github.com/sensepost/gowitness@latest
    GO111MODULE=on go install github.com/jaeles-project/gospider@latest
}


install_wordlists() {
    mkdir -p "$HOME/tools"
    sudo apt install seclists
    cat /usr/share/seclists/Discovery/Web-Content/raft-large-files.txt /usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt /usr/share/seclists/Discovery/Web-Content/api/api-seen-in-wild.txt /usr/share/seclists/Discovery/Web-Content/api/api-endpoints.txt | tr [A-Z] [a-z] | sort -u > "$HOME/tools/content-directories.txt"
}

install_nmap_parser() {
    git clone https://github.com/shifty0g/ultimate-nmap-parser.git "$HOME/tools/nmap_parser"
    chmod +x "$HOME/tools/nmap_parser/ultimate-nmap-parser.sh"
    sudo ln -sf "$HOME/tools/nmap_parser/ultimate-nmap-parser.sh" /usr/bin/nmap_parser
}

install_rustscan() {
  wget https://github.com/bee-san/RustScan/releases/download/2.4.1/rustscan.deb.zip
  mkdir -p rustscan_install
  unzip rustscan.deb.zip -d rustscan_install
  for file in ./rustscan_install/*.deb; do sudo dpkg -i $file; done
}

git_clone_tooling() {
    export GIT_TERMINAL_PROMPT=0
    git clone https://github.com/BooOM/fuzz.txt "$HOME/tools/lists/"
    
    git clone https://github.com/Sybil-Scan/getresolvers "$HOME/tools/getresolvers/"
    pushd "$HOME/tools/getresolvers"
    getresolvers
    sudo apt install -y massdns
    
}

mkdir -p "$HOME/tool_logs/"

install_all_tools () {

install_go
install_rustscan
install_go_tools
install_wordlists
git_clone_tooling
install_nmap_parser
}

enable_pwdless_root () {
    sudo apt install -y kali-grant-root && sudo dpkg-reconfigure kali-grant-root && sudo reboot
}

now() {
    date +"%Y%m%d_%H%M%S"
}
resolve_hostname_all() {
  local host="$1"

  # system resolver
  dig +short "$host"

  # public resolvers
  dig @8.8.8.8 +short "$host"
  dig @1.1.1.1 +short "$host"
  dig @9.9.9.9 +short "$host"
}
parse_gnmap_ports () {
  awk '
  /^Host:/ {
    ip="UNKNOWN"
    os="UNKNOWN"

    # IP
    if (match($0, /^Host: ([0-9.]+)/, m)) {
      ip=m[1]
    }

    # OS
    if (match($0, /OS: ([^ ]+.*?)(  Seq Index:|$)/, o)) {
      os=o[1]
    }

    # Ports
    if (match($0, /Ports: (.*)/, p)) {
      n=split(p[1], ports, ",")
      for (i=1; i<=n; i++) {
        split(ports[i], f, "/")

        port=f[1]
        state=f[2]
        proto=toupper(f[3])
        service=f[5]

        if (state == "open") {
          if (service == "" ) service="UNKNOWN"
          printf "%s, %s, %s %s (%s)\n",
                 ip, os, port, proto, toupper(service)
        }
      }
    }
  }'
}

merge_ip_hosts_ports () {
  local ip_host_csv="$1"
  local ports_csv="$2"
  local out_csv="${3:-hostname_ip_ports_merged.csv}"

  # header
  echo "ip,hostname,OS,port" > "$out_csv"

  awk -F', *' '
    NR==FNR {
      # build ip -> hostname(s) map (allow multiple hostnames per IP)
      host[$1] = (host[$1] ? host[$1] RS $2 : $2)
      next
    }
    {
      ip=$1
      os=$2
      port=$3

      if (ip in host) {
        n = split(host[ip], h, RS)
        for (i=1; i<=n; i++) {
          printf "%s,%s,%s,%s\n", ip, h[i], os, port
        }
      } else {
        printf "%s,UNKNOWN,%s,%s\n", ip, os, port
      }
    }
  ' "$ip_host_csv" "$ports_csv" >> "$out_csv"
}

resolve_helper () {
  infile="$1"
  outfile="${2:-mapping.csv}"

  tmp="$(mktemp)"
  trap 'rm -f "$tmp"' EXIT

  expand_cidr() {
    nmap -n -sL "$1" 2>/dev/null | awk '/Nmap scan report for/ {print $NF}'
  }

  while IFS= read -r entry || [[ -n "$entry" ]]; do
    entry="$(echo "$entry" | xargs)"
    [[ -z "$entry" ]] && continue

    # CIDR
    if [[ "$entry" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]]; then
      expand_cidr "$entry" | while IFS= read -r ip; do
        hostname="$(getent hosts "$ip" | awk '{print $2}' | head -n1)"
        [[ -z "$hostname" ]] && hostname="UNKNOWN"
        echo "$ip,$hostname" >> "$tmp"
      done

    # IP
    elif [[ "$entry" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
      hostname="$(getent hosts "$entry" | awk '{print $2}' | head -n1)"
      [[ -z "$hostname" ]] && hostname="UNKNOWN"
      echo "$entry,$hostname" >> "$tmp"

    # Hostname
    else
      ips="$(resolve_hostname_all "$entry" | grep -E '^([0-9]{1,3}\.){3}[0-9]{1,3}$')"
      if [[ -z "$ips" ]]; then
        echo "UNKNOWN,$entry" >> "$tmp"
      else
        while IFS= read -r ip; do
          echo "$ip,$entry" >> "$tmp"
        done <<< "$ips"
      fi
    fi
  done < "$infile"

  # Deduplicate identical rows only
  sort "$tmp" | uniq > "$outfile"
}

scope_scan_all () {
  logtime="$(now)"
  abspath="$(pwd)""/""$1"
  
  mkdir -p rustscan nuclei
  
  echo "Resolving IPs to hostnames for mapping later"

  # map hostnames to IPs
  resolve_helper "$abspath"
  set -x
  echo "beginning rustscan at $logtime with command 'rustscan -a $1 -- -sS -sU -sV -A --privileged -Pn --max-retries 1 --min-rtt-timeout 100ms --max-rtt-timeout 1030ms --initial-rtt-timeout 500ms --defeat-rst-ratelimit --min-rate 450 --max-rate 15000 -oA "$logtime"-rustscan-output'" >> "$HOME/tool_logs/"$logtime"-rustscan-logs"
  
  # flags here match the -pt profile
  cd ./rustscan && sudo rustscan -a "$abspath" -- -sS -sU -sV -A --privileged -Pn --max-retries 1 --min-rtt-timeout 100ms --max-rtt-timeout 1030ms --initial-rtt-timeout 500ms --defeat-rst-ratelimit --min-rate 450 --max-rate 15000 -oA {{ip}}-"$logtime"-output
  
  # parse out our gnmap results for mapping later
  for f in *.gnmap; do                             
  parse_gnmap_ports < "$f"
  done > ips_all_ports.csv
  # merge in rustscan results, map back to hostnames
  merge_ip_hosts_ports ../mapping.csv all_ports.csv

  # use these for feroxbusting later
  get_web_servers
  
  # we run flyover on the scope file because we want to capture screenshots of fqdns and not direct access IPs
  cd ../ && flyover "$abspath"
  

  # nuclei scans
  nuclei -sa -as -l "$abspath" -o nuclei/full-scope-nuclei.txt
  
  # nonstandard web servers 
  nuclei -l rustscan/urls.txt -as -sa -o nuclei/full-scope-nuclei_nonstandard_web.txt

  set +x
  echo "Rustscan, nuclei, and flyovers complete - review the output and determine if the web servers allow direct access or if you need to use FQDNS. 
  Next Steps - Review the following files and directories:
  1. rustscan/hostname_ip_ports_merged.csv - this contains a list of hostnames, their IPs and identified open services
  2. flyovers/ - this diretory contains all output from gowitness for any web servers found
  3. nuclei/- nuclei output 

  Next Tools to run:
  1. Use crawl_fqdns if no direct access to web services via IPs are allowed
  2. Use feroxbuster_urls ./urls.txt if direct access allowed
  
  Finally, review all output and begin manual testing!"

  
}

feroxbuster_urls() {
  logtime="$(now)"
  url=${1?Error: no url file found}
  domain=$(echo "$url" | cut -d \/ -f3)
  set -x
  mkdir -p feroxbuster
  echo "$url" | feroxbuster --depth 3 --stdin --silent --no-state --filter-status 400,404,500,403 -k -A -o feroxbuster/"$logtime"-"$domain"-content-directories.output -w ~/tools/content-directories.txt
  set +x
}

apex_expand_scope (){
  logtime="$(now)"
  set +x 
  domain=$1
  mkdir  subfinder dnsrecon gobuster fqdns amass
  dnsrecon -d "$domain" > dnsrecon/"$logtime"-"$domain"-dnsrecon.txt
  amass enum  -nocolor -d "$domain" -active -o amass/"$logtime"-"$domain"-output -timeout 10
  cat amass/"$logtime"-"$domain"-output | awk '{printf $1; printf "\n"}' | grep "$domain" | uniq > amass/"$logtime"-"$domain"-amass.txt
  echo "$domain" | subfinder -silent > subfinder/"$logtime"-"$domain"-subfinder.txt
  gobuster dns --domain "$domain" --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -q > gobuster/"$logtime"-"$domain"-gobuster-output.txt
  cat dnsrecon/"$logtime"-"$domain"-dnsrecon.txt amass/"$logtime"-"$domain"-amass.txt subfinder/"$logtime"-"$domain"-subfinder.txt gobuster/"$logtime"-"$domain"-gobuster-output.txt | sort -u > fqdns/"$logtime"-"$domain"-fqdnslist.txt
  echo "Expansion and enumeration of $domain done. For one final expansion, consider running `amass intel -whois -active -d $domain` WARNING: There is a possibility this command will return apex and subdomains that are not actually owned by the owners of $domain" 
}

#TODO Fix this
fqdn_content() {
  logtime="$(now)"
  fqdnsfile=${2?Error: no domain file provided}
  filename=$(basename "${pwd}")

  set -x
  mkdir -p naabu httpx feroxbuster
  naabu -p - -l "$fqdnsfile" --silent --rate 2500 -o "naabu/"$logtime"-$filename-all-tcp.output"
  httpx -l "naabu/"$logtime"-$filename-all-tcp.output" --silent -o "httpx/"$logtime"-$filename"
  cat "httpx/"$logtime"-$filename-naabu.output" | feroxbuster --filter-status 400,404,500,403 --stdin --no-state -k -A -o "feroxbuster/"$logtime"-$filename-content-directories.output" -w ~/tools/content-directories.txt
  set +x
}

crawl_fqdns() {
  logtime="$(now)"
  fqdn=${1?Error: no FQDN file provided}
  fbn=$(basename $fqdn)
  set -x
  mkdir -p httpx feroxbuster katana

  cat "$fqdn" | httpx -nc -fhr -title -tech-detect -status-code -cname -server -silent -o httpx/"$logtime"-$fbn.raw
  cat httpx/"$logtime"-$fbn.raw | cut -d " " -f1 > httpx/"$logtime"-$fbn-discovered.output
  cat httpx/"$logtime"-$fbn-discovered.output | feroxbuster  --depth 3 --stdin --silent --no-state --filter-status 400,404,500,403 -k -A -o feroxbuster/"$logtime"-$fbn-content-directories.output
  cat feroxbuster/"$logtime"-$fbn-content-directories.output | katana --silent > katana/"$logtime"-$fbn-feroxbuster-content-directories.output
  set +x
}

fqdns_nuclei() {
  logtime="$(now)"
  fqdn=${1?Error: no FQDN file provided}
  fbn=$(basename $fqdn)
  set -x
  mkdir -p nuclei
  nuclei -sa -as -l $1 -o "nuclei/"$logtime"-fqdn_nuclei.output"
  set +x
}

url_nuclei() {
  logtime="$(now)"
  fbn=$(basename $fqdn)
  set -x
  mkdir -p nuclei
  nuclei -sa -as -l $1 -o "nuclei/"$logtime"-urls_nuclei.output"
  set +x
}

# can be used on a list of URLs or a simple scope file
flyover () {
  mkdir -p flyovers
  scope=$1
  logtime="$(now)"
  gowitness scan file -f "$scope" --screenshot-path ./flyovers
}

apex_nuclei() {
  logtime="$(now)"
  set -x
  mkdir -p nuclei
  subfinder -d "$1" -silent | httpx | nuclei -sa -as -o "nuclei/"$logtime"_apex-nuclei-templates.output"
}

apex_quick() {
  logtime="$(now)"
  domain=$1
  set -x
  mkdir -p quick/"$domain"
  
  subfinder -d "$domain" -silent | anew "quick/"$domain"-subs.txt" | \
  dnsx -resp -silent | anew "quick/"$domain"-alive-subs-ip.txt" | awk '{print $1}' | anew "quick/"$domain"-alive-subs.txt"
  flyover "quick/"$domain"-alive-subs-ip.txt"
  sudo rustscan -a "quick/"$domain"-alive-subs.txt" -r 1-1000 -- -sS -sV -Pn -oA {{ip}}-"$logtime"-quickwins-top-1000
  get_web_servers
  # fix this, this isnt generating links correctly
  #gau --blacklist eot,svg,swf,woff,tff,png,jpg,gif,btf,bmp,pdf,mp3,mp4,mov --subs | anew "quickwins/"$domain"-gau.txt" | \
  #httpx -silent -title -status-code -mc 200,403,400,500 | anew "quickwins/"$domain"-web-alive.txt" | awk '{print $1}' | \
  nuclei -sa -as -l "quick/"$domain"-alive-subs.txt" -o "quick/"$domain"-nuclei.txt"
  # nonstandard web servers 
  nuclei -l ./urls.txt -as -sa -o "quick/"$domain"-nuclei_nonstandard_web.txt"
  set +x
}
