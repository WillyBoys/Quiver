import { useState, useMemo } from "react";
import {
  ExternalLink, Search, Network, Mail, User, ShieldAlert, AlertTriangle,
  Link2, Cpu, Building2, Coins, MapPin, Wrench, FileSearch,
  Activity, Users, Image, Video, Plane, MessageSquare, EyeOff,
  Archive, Phone, Key, FileText, Bug, Crosshair,
  Radio, Satellite, Scale, Rss, Layers, Cloud,
  Twitter, Youtube, Car, BarChart2, Eye,
} from "lucide-react";
import styles from "./OsintPage.module.css";

const GROUPS = [
  { id: "all",       label: "All" },
  { id: "infra",     label: "Infrastructure" },
  { id: "identity",  label: "Identity & People" },
  { id: "threat",    label: "Threat Intel" },
  { id: "social",    label: "Social & Media" },
  { id: "financial", label: "Financial" },
  { id: "geo",       label: "Geo & Location" },
  { id: "tools",     label: "Utilities & Tools" },
];

const CATEGORIES = [
  /* ── INFRASTRUCTURE ────────────────────────────────── */
  {
    id: "domain-dns", group: "infra",
    label: "Domain / Network Intel", icon: Network,
    links: [
      { name: "Shodan",               url: "https://shodan.io",                                           desc: "Internet-connected device and service search" },
      { name: "Censys",               url: "https://censys.io",                                           desc: "Internet-wide scan data and host certificate info" },
      { name: "SecurityTrails",       url: "https://securitytrails.com",                                  desc: "DNS history, subdomains, reverse DNS, IP data" },
      { name: "DNSdumpster",          url: "https://dnsdumpster.com",                                     desc: "DNS recon and visual domain mapping" },
      { name: "crt.sh",               url: "https://crt.sh",                                              desc: "Certificate transparency log search" },
      { name: "ViewDNS.info",         url: "https://viewdns.info",                                        desc: "Swiss army knife of DNS lookup tools" },
      { name: "MXToolbox",            url: "https://mxtoolbox.com",                                       desc: "Email headers, blacklist check, DNS diagnostics" },
      { name: "Netcraft",             url: "https://sitereport.netcraft.com",                             desc: "Site reports, hosting history, tech stack" },
      { name: "Whoxy",                url: "https://whoxy.com",                                           desc: "WHOIS history and reverse WHOIS lookup" },
      { name: "BGP.he.net",           url: "https://bgp.he.net",                                          desc: "ASN, BGP routes, and peering data" },
      { name: "BGP.tools",            url: "https://bgp.tools",                                           desc: "BGP prefix, ASN, and network data explorer" },
      { name: "dnslytics",            url: "https://dnslytics.com",                                       desc: "DNS analytics and reverse IP lookup" },
      { name: "ONYPHE",               url: "https://search.onyphe.io",                                    desc: "Cyber threat intelligence and passive scan data" },
      { name: "Validin",              url: "https://app.validin.com",                                     desc: "Historical DNS and WHOIS correlation search" },
      { name: "Robtex",               url: "https://robtex.com",                                          desc: "IP, domain, and ASN lookup with visual graphs" },
      { name: "CompleteDNS History",  url: "https://completedns.com/dns-history",                         desc: "DNS record history for any domain" },
      { name: "Domain Dossier",       url: "https://centralops.net/co/DomainDossier.aspx",                desc: "Comprehensive domain and IP network report" },
      { name: "ICANN Lookup",         url: "https://lookup.icann.org/en/lookup",                          desc: "Official ICANN WHOIS lookup" },
      { name: "DNSviz",               url: "https://dnsviz.net",                                          desc: "DNS visualization and DNSSEC chain validation" },
      { name: "SubDomainRadar",       url: "https://subdomainradar.io",                                   desc: "Subdomain discovery and enumeration" },
      { name: "HackerTarget",         url: "https://hackertarget.com",                                    desc: "Online scanners: host recon, subnet, DNS, port scan" },
      { name: "IntoDNS",              url: "https://intodns.ai",                                          desc: "DNS health check and configuration audit" },
    ],
  },
  {
    id: "search-dorking", group: "infra",
    label: "Search & Dorking", icon: Search,
    links: [
      { name: "Google Advanced",      url: "https://google.com/advanced_search",                          desc: "Targeted Google search with full parameter controls" },
      { name: "GHDB",                 url: "https://exploit-db.com/google-hacking-database",              desc: "Google Hacking Database — community dork library" },
      { name: "PublicWWW",            url: "https://publicwww.com",                                       desc: "Source code and HTML search across live sites" },
      { name: "NerdyData",            url: "https://nerdydata.com",                                       desc: "Search HTML and JS source code across the web" },
      { name: "Yandex",               url: "https://yandex.com",                                          desc: "Russian search engine — different indexing than Google" },
      { name: "GrayhatWarfare",       url: "https://grayhatwarfare.com",                                  desc: "Public S3, Azure, and GCS bucket search" },
      { name: "DorkGenius",           url: "https://dorkgenius.com",                                      desc: "AI-powered Google dork generator" },
      { name: "DorkGPT",              url: "https://www.dorkgpt.com",                                     desc: "ChatGPT-powered Google dork builder" },
      { name: "Dorksearch",           url: "https://dorksearch.com",                                      desc: "Pre-built dork search engine with categories" },
      { name: "Million Short",        url: "https://millionshort.com",                                    desc: "Remove top N results to uncover obscure content" },
      { name: "Baidu",                url: "https://baidu.com",                                           desc: "Chinese search engine — unique indexing coverage" },
      { name: "SearXNG",              url: "https://searxng.org",                                         desc: "Open-source privacy meta-search engine" },
      { name: "Bing",                 url: "https://bing.com",                                            desc: "Indexes different content than Google — worth checking" },
      { name: "SEQE.me",              url: "https://seqe.me",                                             desc: "Construct advanced queries for 5 search engines at once" },
      { name: "Pentest-Tools Dork",   url: "https://pentest-tools.com/information-gathering/google-hacking", desc: "Online Google hacking tool with dork builder" },
    ],
  },
  {
    id: "source-code-pastes", group: "infra",
    label: "Source Code & Pastes", icon: FileSearch,
    links: [
      { name: "GitHub Search",        url: "https://github.com/search",                                   desc: "Search all public repositories and code" },
      { name: "SourceGraph",          url: "https://sourcegraph.com/search",                              desc: "Universal code search — GitHub, GitLab, Bitbucket" },
      { name: "Grep.app",             url: "https://grep.app",                                            desc: "Regex search across 500K+ public GitHub repos" },
      { name: "SearchCode",           url: "https://searchcode.com",                                      desc: "Code search across multiple hosting platforms" },
      { name: "Sourcebot",            url: "https://www.sourcebot.dev",                                   desc: "Fast code search across GitHub repositories" },
      { name: "GitLeak",              url: "https://gitleak.io",                                          desc: "Search for leaked secrets in public repositories" },
      { name: "psbdmp.ws",            url: "https://psbdmp.ws",                                           desc: "Search 25M+ pastebin entries for sensitive data" },
      { name: "Pastebin CSE",         url: "https://cipher387.github.io/pastebinsearchengines",           desc: "Google CSE searching across 48 pastebin sites" },
      { name: "doxbin",               url: "https://doxbin.net",                                          desc: "Dox and paste search index" },
      { name: "GitHub Gist",          url: "https://gist.github.com",                                     desc: "Search public code snippets and pastes" },
    ],
  },
  {
    id: "url-web", group: "infra",
    label: "URL & Web Analysis", icon: Link2,
    links: [
      { name: "urlscan.io",           url: "https://urlscan.io",                                          desc: "Scan URLs — screenshot, DOM, network requests, relations" },
      { name: "BuiltWith",            url: "https://builtwith.com",                                       desc: "Technology profiler — CMS, CDN, analytics, frameworks" },
      { name: "WhatCMS",              url: "https://whatcms.org",                                         desc: "CMS and framework detection for any site" },
      { name: "Shodan InternetDB",    url: "https://internetdb.shodan.io",                                desc: "Quick Shodan IP data — no account required" },
      { name: "Web-Check",            url: "https://web-check.as93.net",                                  desc: "Comprehensive site analysis: DNS, headers, tech, certs" },
      { name: "urlDNA",               url: "https://urldna.io",                                           desc: "URL analysis and threat intelligence" },
      { name: "Redirect Detective",   url: "https://redirectdetective.com",                               desc: "Trace and visualize URL redirect chains" },
      { name: "Qualys SSL Labs",      url: "https://ssllabs.com/ssltest",                                 desc: "SSL/TLS configuration test and grading" },
      { name: "Google Transparency",  url: "https://transparencyreport.google.com/safe-browsing/search",  desc: "Google Safe Browsing status check" },
      { name: "URLVoid",              url: "https://urlvoid.com",                                         desc: "Website reputation and blacklist checker" },
      { name: "SimilarWeb",           url: "https://similarweb.com",                                      desc: "Traffic analytics and competitor intelligence" },
      { name: "HypeStat",             url: "https://hypestat.com",                                        desc: "Website traffic, revenue, and analytics estimates" },
      { name: "IsLegitSite",          url: "https://islegitsite.com",                                     desc: "Check if a website is legitimate or a scam" },
      { name: "urlQuery",             url: "http://urlquery.net",                                          desc: "URL analysis with full network behavior capture" },
    ],
  },
  {
    id: "iot-infra", group: "infra",
    label: "IoT & Infrastructure", icon: Cpu,
    links: [
      { name: "FOFA",                 url: "https://fofa.info",                                           desc: "Chinese internet scanner — broad global asset discovery" },
      { name: "ZoomEye",              url: "https://zoomeye.org",                                         desc: "Cyberspace search engine with strong Asia-Pacific coverage" },
      { name: "BinaryEdge",           url: "https://binaryedge.io",                                       desc: "Attack surface and internet-wide exposure monitoring" },
      { name: "LeakIX",               url: "https://leakix.net",                                          desc: "Internet scanner focused on leaking and vulnerable services" },
      { name: "Netlas",               url: "https://app.netlas.io",                                       desc: "Internet host search — domain, IP, cert, and header data" },
      { name: "Criminal IP",          url: "https://criminalip.io",                                       desc: "Threat-enriched internet search by IP, CVE, or HTML title" },
      { name: "FullHunt",             url: "https://fullhunt.io",                                         desc: "Attack surface database of the entire internet" },
      { name: "Hunter.how",           url: "https://hunter.how",                                          desc: "Security researcher search by domain, title, ASN, protocol" },
      { name: "Insecam",              url: "https://insecam.org",                                         desc: "Directory of open and unsecured IP cameras worldwide" },
      { name: "Thingful",             url: "https://thingful.net",                                        desc: "IoT device search engine and smart device index" },
      { name: "ODIN",                 url: "https://search.odin.io",                                      desc: "Asset discovery and attack surface management search" },
      { name: "Shadowserver",         url: "https://dashboard.shadowserver.org",                          desc: "Internet-wide vulnerability and misconfiguration reports" },
    ],
  },
  {
    id: "archives", group: "infra",
    label: "Archives & Web History", icon: Archive,
    links: [
      { name: "Wayback Machine",      url: "https://web.archive.org",                                     desc: "Historical web page snapshots dating back to 1996" },
      { name: "Archive.is",           url: "https://archive.is",                                          desc: "Capture and retrieve web page snapshots" },
      { name: "Archive.md",           url: "https://archive.md",                                          desc: "Page archiving and cached content access" },
      { name: "Quick Cache Search",   url: "https://quickcacheandarchivesearch.onrender.com",             desc: "Search site old versions across 21 archive sources" },
      { name: "CommonCrawl",          url: "https://commoncrawl.org",                                     desc: "Petabytes of web crawl data — open dataset" },
      { name: "GAU",                  url: "https://github.com/lc/gau",                                   desc: "Fetch all known URLs from Wayback, AlienVault, URLScan" },
      { name: "WayMore",              url: "https://github.com/xnl-h4ck3r/waymore",                       desc: "Wayback Machine and Common Crawl URL harvesting" },
      { name: "Wayback GA IDs",       url: "https://github.com/bellingcat/wayback-google-analytics",      desc: "Find all Google Analytics IDs in archived pages" },
      { name: "TheTimeMachine",       url: "https://github.com/anmolksachan/TheTimeMachine",              desc: "Archive.org recon: subdomains, endpoints, vuln hunting" },
      { name: "Waybackpack",          url: "https://github.com/jsvine/waybackpack",                       desc: "Download entire Wayback Machine archive for a URL" },
      { name: "Stored.website",       url: "https://stored.website",                                      desc: "Cached and stored versions of web pages" },
      { name: "CachedView",           url: "https://cachedview.nl",                                       desc: "Quick access to cached page versions" },
    ],
  },
  {
    id: "cloud-recon", group: "infra",
    label: "Cloud Recon", icon: Cloud,
    links: [
      { name: "GrayhatWarfare Buckets",url: "https://grayhatwarfare.com",                                 desc: "Search public S3, Azure Blob, and GCS storage buckets" },
      { name: "Azure Tenant Resolver", url: "https://tenantresolution.pingcastle.com",                    desc: "Resolve Microsoft Azure tenant from a domain name" },
      { name: "S3Scanner",            url: "https://github.com/sa7mon/S3Scanner",                         desc: "Scan for open S3 buckets and dump contents" },
      { name: "cloud_enum",           url: "https://github.com/initstring/cloud_enum",                    desc: "Enumerate public cloud resources for any target keyword" },
      { name: "Subdomainizer",        url: "https://github.com/nsonaniya2010/SubDomainizer",              desc: "Find subdomains and cloud assets hidden in JS files" },
      { name: "APIs.guru",            url: "https://apis.guru",                                           desc: "Directory of 2000+ public REST API definitions" },
      { name: "SwaggerHub",           url: "https://app.swaggerhub.com/search",                           desc: "Search public API specifications and OpenAPI docs" },
      { name: "Postman Explore",      url: "https://www.postman.com/explore",                             desc: "Discover public API collections and documentation" },
      { name: "BeVigil",              url: "https://bevigil.com/search",                                  desc: "Search mobile apps for exposed API keys and endpoints" },
    ],
  },

  /* ── IDENTITY & PEOPLE ─────────────────────────────── */
  {
    id: "email-identity", group: "identity",
    label: "Email & Identity", icon: Mail,
    links: [
      { name: "Epieos",               url: "https://epieos.com",                                          desc: "Email OSINT — linked accounts and registered services" },
      { name: "hunter.io",            url: "https://hunter.io",                                           desc: "Email format discovery and domain-level verification" },
      { name: "holehe",               url: "https://github.com/megadose/holehe",                          desc: "Check if email is registered on 120+ sites" },
      { name: "Phonebook.cz",         url: "https://phonebook.cz",                                        desc: "Email, domain, and URL OSINT search engine" },
      { name: "GHunt",                url: "https://github.com/mxrch/GHunt",                              desc: "Google account OSINT — linked services and location data" },
      { name: "h8mail",               url: "https://github.com/khast3x/h8mail",                           desc: "Email OSINT and breach hunting tool" },
      { name: "EmailRep",             url: "https://emailrep.io",                                         desc: "Email reputation and risk scoring API" },
      { name: "EmailHippo",           url: "https://tools.emailhippo.com",                                desc: "Email existence and reliability check" },
      { name: "OSINT Industries",     url: "https://osint.industries",                                    desc: "Find accounts associated with an email or phone number" },
      { name: "Castrickclues",        url: "https://castrickclues.com",                                   desc: "Google and Skype account info by email, phone, or nick" },
      { name: "mailcat",              url: "https://github.com/sharsil/mailcat",                          desc: "Find existing email addresses by nickname across providers" },
      { name: "Snov.io",              url: "https://snov.io/email-finder",                                desc: "Find employee emails by company domain" },
      { name: "Email Permutator",     url: "https://www.polished.app/email-permutator",                   desc: "Generate email variants from first name, last name, domain" },
      { name: "Apollo.io",            url: "https://apollo.io",                                           desc: "B2B contact database — emails, titles, and company data" },
      { name: "ContactOut",           url: "https://contactout.com",                                      desc: "Email and phone lookup from LinkedIn profiles" },
      { name: "VoilaNorbert",         url: "https://www.voilanorbert.com",                                desc: "Find anyone's email address by name and company" },
    ],
  },
  {
    id: "username-search", group: "identity",
    label: "Username Search", icon: User,
    links: [
      { name: "WhatsMyName",          url: "https://whatsmyname.app",                                     desc: "Username search across 600+ platforms" },
      { name: "Sherlock",             url: "https://github.com/sherlock-project/sherlock",                desc: "CLI username hunt across social networks" },
      { name: "Maigret",              url: "https://github.com/soxoj/maigret",                            desc: "Username OSINT with profile data parsing from 1500+ sites" },
      { name: "Blackbird",            url: "https://github.com/p1ngul1n0/blackbird",                      desc: "Username search across 200+ sites incl. archived Twitter" },
      { name: "NexFil",               url: "https://github.com/thewhiteh4t/nexfil",                       desc: "Username search across 350 social media platforms" },
      { name: "Social Analyzer",      url: "https://github.com/qeeqbox/social-analyzer",                  desc: "Profile search on 300+ sites with analysis and scoring" },
      { name: "User Searcher",        url: "https://www.user-searcher.com",                               desc: "Username in 2000+ websites" },
      { name: "SherlockEye",          url: "https://sherlockeye.io",                                      desc: "Username, email, and phone OSINT search" },
      { name: "Snoop",                url: "https://github.com/snooppr/snoop",                            desc: "Username search on 1500+ platforms with detailed output" },
      { name: "IDCrawl",              url: "https://www.idcrawl.com",                                     desc: "Cross-platform username, name, and email search" },
      { name: "Digital Footprint Check", url: "https://www.digitalfootprintcheck.com/free-checker.html",  desc: "Free username, email, phone, and handle OSINT check" },
      { name: "Namechk",              url: "https://namechk.com",                                         desc: "Username and domain availability across platforms" },
    ],
  },
  {
    id: "phone-research", group: "identity",
    label: "Phone Number Research", icon: Phone,
    links: [
      { name: "PhoneInfoga",          url: "https://github.com/sundowndev/PhoneInfoga",                   desc: "Advanced phone OSINT — carrier, region, risk score" },
      { name: "Truecaller",           url: "https://truecaller.com",                                      desc: "Caller ID and reverse phone number lookup" },
      { name: "FreeCarrierLookup",    url: "https://freecarrierlookup.com",                               desc: "Carrier, line type, and porting status lookup" },
      { name: "NumVerify",            url: "https://numverify.com",                                       desc: "Global phone number validation API (free tier)" },
      { name: "SpyDialer",            url: "https://spydialer.com",                                       desc: "Reverse phone, name, address, and email search" },
      { name: "Defastra",             url: "https://defastra.com",                                        desc: "Phone and email reliability with social profile discovery" },
      { name: "Phomber",              url: "https://github.com/s41r4j/phomber",                           desc: "CLI phone OSINT: country, timezone, provider info" },
      { name: "Sync.ME",              url: "https://sync.me",                                             desc: "Reverse phone lookup with social profile matching" },
    ],
  },
  {
    id: "people-search", group: "identity",
    label: "People Search", icon: Users,
    links: [
      { name: "TruePeopleSearch",     url: "https://truepeoplesearch.com",                                desc: "Free US people search — address, phone, relatives" },
      { name: "FastPeopleSearch",     url: "https://fastpeoplesearch.com",                                desc: "Free people finder — address, phone, email" },
      { name: "White Pages",          url: "https://whitepages.com",                                      desc: "US people, address, and business search" },
      { name: "PeekYou",              url: "https://peekyou.com",                                         desc: "People search with linked social profiles" },
      { name: "ZabaSearch",           url: "https://zabasearch.com",                                      desc: "Free US people search with address history" },
      { name: "FamilyTreeNow",        url: "https://familytreenow.com",                                   desc: "Free genealogy search with address and relative data" },
      { name: "Spokeo",               url: "https://spokeo.com",                                          desc: "People search — social profiles, address, phone" },
      { name: "BeenVerified",         url: "https://beenverified.com",                                    desc: "Background check and people search platform" },
      { name: "192.com",              url: "https://192.com",                                             desc: "UK people and business search directory" },
      { name: "Anywho",               url: "https://anywho.com",                                          desc: "US people search by name with free partial results" },
      { name: "ThatsThem",            url: "https://thatsthem.com",                                       desc: "Reverse search by email, IP, phone, VIN, or address" },
      { name: "USPhonebook",          url: "https://usphonebook.com",                                     desc: "US person and phone lookup" },
    ],
  },
  {
    id: "passwords-creds", group: "identity",
    label: "Passwords & Default Creds", icon: Key,
    links: [
      { name: "CrackStation",         url: "https://crackstation.net",                                    desc: "Password hash cracker with large precomputed table" },
      { name: "Default Router Creds", url: "https://cleancss.com/router-default",                         desc: "Default login credentials for network devices by model" },
      { name: "Many Passwords",       url: "https://many-passwords.github.io",                            desc: "Default passwords database for IoT and web apps" },
      { name: "PassHunt",             url: "https://github.com/Viralmaniar/Passhunt",                     desc: "Search default credentials for 523 vendors and 2084 passwords" },
      { name: "BugMeNot",             url: "http://bugmenot.com",                                         desc: "Shared public account logins for various websites" },
      { name: "CIRT.net Passwords",   url: "https://cirt.net/passwords",                                  desc: "Default password database searchable by vendor or device" },
      { name: "OnlineHashCrack",      url: "https://onlinehashcrack.com",                                 desc: "Online hash cracking service: MD5, SHA1, SHA256" },
      { name: "Hashes.com",           url: "https://hashes.com/en/decrypt/hash",                          desc: "Hash lookup and decryption database" },
    ],
  },

  /* ── THREAT INTEL ──────────────────────────────────── */
  {
    id: "threat-intel", group: "threat",
    label: "Threat Intel & Malware", icon: ShieldAlert,
    links: [
      { name: "VirusTotal",           url: "https://virustotal.com",                                      desc: "File, URL, IP, and domain multi-engine analysis" },
      { name: "Any.run",              url: "https://any.run",                                             desc: "Interactive malware sandbox with real-time analysis" },
      { name: "Hybrid-Analysis",      url: "https://hybrid-analysis.com",                                 desc: "Free automated malware analysis service" },
      { name: "MalwareBazaar",        url: "https://bazaar.abuse.ch",                                     desc: "Malware sample database and hash lookup" },
      { name: "URLhaus",              url: "https://urlhaus.abuse.ch",                                    desc: "Malicious URL and payload database" },
      { name: "Cisco Talos",          url: "https://talosintelligence.com",                               desc: "IP and domain reputation, spam intel" },
      { name: "OTX AlienVault",       url: "https://otx.alienvault.com",                                  desc: "Community threat intelligence feeds and IOC sharing" },
      { name: "GreyNoise",            url: "https://greynoise.io",                                        desc: "Differentiates internet noise from targeted scanning" },
      { name: "Pulsedive",            url: "https://pulsedive.com",                                       desc: "Threat intel aggregator and IOC enrichment platform" },
      { name: "Malpedia",             url: "https://malpedia.caad.fkie.fraunhofer.de",                    desc: "Malware family encyclopedia and actor knowledge base" },
      { name: "IBM X-Force",          url: "https://exchange.xforce.ibmcloud.com",                        desc: "Threat intelligence exchange and indicator lookup" },
      { name: "JoeSandbox",           url: "https://joesandbox.com",                                      desc: "Deep automated malware behavior analysis" },
      { name: "AbuseIPDB",            url: "https://abuseipdb.com",                                       desc: "Community IP abuse report database and reputation check" },
      { name: "MetaDefender",         url: "https://metadefender.opswat.com",                             desc: "Multi-engine file and URL scanner (30+ AV engines)" },
      { name: "PhishStats",           url: "https://phishstats.info",                                     desc: "Phishing intelligence database and feed" },
      { name: "URLVoid",              url: "https://urlvoid.com",                                         desc: "Website reputation and blacklist check" },
      { name: "DomainTools",          url: "https://domaintools.com",                                     desc: "DNS, WHOIS history, and threat context for domains" },
      { name: "Abuse.ch Hunting",     url: "https://hunting.abuse.ch",                                    desc: "Hunt malware with YARA rules and network IOCs" },
      { name: "InQuest Labs",         url: "https://inquest.net",                                         desc: "File and network artifact deep inspection" },
      { name: "PolySwarm",            url: "https://polyswarm.io",                                        desc: "Decentralized threat intelligence from security experts" },
      { name: "Emerging Threats",     url: "https://rules.emergingthreats.net",                           desc: "Open Suricata/Snort rulesets for known threats" },
      { name: "Sucuri SiteCheck",     url: "https://sitecheck.sucuri.net",                                desc: "Website malware and blacklist scanner" },
    ],
  },
  {
    id: "breaches", group: "threat",
    label: "Data Breaches", icon: AlertTriangle,
    links: [
      { name: "HaveIBeenPwned",       url: "https://haveibeenpwned.com",                                  desc: "Check email or phone number in known breach databases" },
      { name: "DeHashed",             url: "https://dehashed.com",                                        desc: "Search leaked credentials and personal data" },
      { name: "Intelligence X",       url: "https://intelx.io",                                           desc: "Historical data, pastes, dark web leaks" },
      { name: "Snusbase",             url: "https://snusbase.com",                                        desc: "Database leak search engine" },
      { name: "LeakCheck",            url: "https://leakcheck.io",                                        desc: "Credential and breach lookup" },
      { name: "CheckLeaked",          url: "https://checkleaked.cc",                                      desc: "Multi-source data breach search engine" },
      { name: "LeakRadar",            url: "https://leakradar.io",                                        desc: "Credential leak detection and monitoring" },
      { name: "InfoStealers",         url: "https://infostealers.info",                                   desc: "Stealer log database search engine" },
      { name: "Breachchecker",        url: "https://breachchecker.com",                                   desc: "Email data leak history tracker" },
      { name: "SpyCloud",             url: "https://spycloud.com/check-your-exposure",                    desc: "Breach exposure check for email or domain" },
      { name: "Have I Been Sold",     url: "https://haveibeensold.app",                                   desc: "Check if email is in illegally sold databases" },
      { name: "Cybernews Leak Check", url: "https://cybernews.com/personal-data-leak-check",             desc: "Check personal data against known breach dumps" },
      { name: "Leak-Lookup",          url: "https://leak-lookup.com",                                     desc: "Multi-breach credential lookup database" },
    ],
  },
  {
    id: "threat-maps", group: "threat",
    label: "Live Threat Maps", icon: Activity,
    links: [
      { name: "Kaspersky Cyberthreat",url: "https://cybermap.kaspersky.com",                              desc: "Real-time global malware and attack visualization" },
      { name: "Check Point Threat Map",url: "https://threatmap.checkpoint.com",                           desc: "Live cyber attack map from Check Point sensors" },
      { name: "Bitdefender Threat Map",url: "https://threatmap.bitdefender.com",                          desc: "Global malware activity from Bitdefender telemetry" },
      { name: "IBM X-Force Activity", url: "https://exchange.xforce.ibmcloud.com/activity/map",           desc: "Current malicious activity map from IBM X-Force" },
      { name: "Fortiguard Threat Map",url: "https://fortiguard.fortinet.com/threat-map",                  desc: "FortiGuard labs live threat intelligence map" },
      { name: "Radware Threat Map",   url: "https://livethreatmap.radware.com",                           desc: "Live DDoS attack origin and volume map" },
      { name: "Cloudflare Radar",     url: "https://radar.cloudflare.com",                                desc: "Internet traffic trends, routing, and threat insights" },
      { name: "ThreatsEye",           url: "https://threatseye.io/threats-map",                           desc: "Real-time cyber threat intelligence map" },
    ],
  },
  {
    id: "apt-intel", group: "threat",
    label: "Threat Actor / APT Intel", icon: Crosshair,
    links: [
      { name: "MITRE ATT&CK",         url: "https://attack.mitre.org",                                   desc: "Adversary tactics, techniques, and procedures framework" },
      { name: "Malpedia Actors",       url: "https://malpedia.caad.fkie.fraunhofer.de/actors",            desc: "Threat actor profiles linked to malware families" },
      { name: "MISP Galaxy",           url: "https://www.misp-galaxy.org",                               desc: "Threat actor clusters, tools, and intelligence taxonomy" },
      { name: "APT Groups Sheet",      url: "https://docs.google.com/spreadsheets/d/1H9_xaxQHpWaa4O_Son4Gx0YOIzlcBWMsdvePFX68EKU/pubhtml", desc: "Crowd-sourced APT group and operations tracker" },
      { name: "ETDA APT Groups",       url: "https://apt.etda.or.th/cgi-bin/listgroups.cgi",             desc: "Thailand NCSA APT group tracker and profiles" },
      { name: "FortiGuard Actors",     url: "https://fortiguard.com/threat-actor",                       desc: "FortiGuard labs threat actor profiles and campaigns" },
      { name: "SOCRadar Actors",       url: "https://socradar.io/labs/threat-actor",                     desc: "Threat actor profiles and active campaign tracking" },
      { name: "Dark Web Informer",     url: "https://darkwebinformer.com/threat-actor-database",         desc: "Threat actor database with dark web monitoring" },
      { name: "Bi.Zone GTI",           url: "https://gti.bi.zone",                                        desc: "Threat intelligence portal with actor attribution" },
      { name: "Lazarus Map",           url: "https://lazarus.day/actors",                                 desc: "Lazarus Group and DPRK-linked actor tracker" },
      { name: "OPENHUNTING.IO",        url: "https://openhunting.io/threat-library",                      desc: "Open threat library with hunt packages" },
    ],
  },
  {
    id: "dark-web", group: "threat",
    label: "Dark Web", icon: EyeOff,
    links: [
      { name: "Ahmia",                url: "https://ahmia.fi",                                            desc: "Clearnet search engine for Tor hidden services" },
      { name: "DarkSearch",           url: "https://darksearch.io",                                       desc: "Dark web search engine with API access" },
      { name: "Intelligence X",       url: "https://intelx.io",                                           desc: "Dark web, I2P, Tor archive, and paste search" },
      { name: "Dark Web Informer",    url: "https://darkwebinformer.com",                                  desc: "Threat actor and data leak monitoring from dark web" },
      { name: "Onion Search",         url: "https://github.com/megadose/onionsearch",                     desc: "Multi-engine .onion site search script" },
      { name: "Exonera Tor",          url: "https://exonerator.torproject.org",                            desc: "Check if an IP was a Tor exit node at a given time" },
      { name: "DDoSecrets",           url: "https://ddosecrets.com",                                       desc: "Distributed denial of secrets — leaked dataset archive" },
      { name: "Tor Metrics",          url: "https://metrics.torproject.org",                               desc: "Tor network statistics: relays, users, traffic" },
    ],
  },

  /* ── SOCIAL & MEDIA ────────────────────────────────── */
  {
    id: "social-media", group: "social",
    label: "Social Media Tools", icon: MessageSquare,
    links: [
      { name: "Social Searcher",      url: "https://social-searcher.com",                                 desc: "Real-time social media search across platforms" },
      { name: "Twitter Adv. Search",  url: "https://twitter.com/search-advanced",                         desc: "Advanced Twitter/X search with date and user filters" },
      { name: "Trends24",             url: "https://trends24.in",                                         desc: "Twitter trending topics by country and city" },
      { name: "Who Posted What",      url: "https://whopostedwhat.com",                                   desc: "Facebook keyword search by date range — no login needed" },
      { name: "SocialBlade",          url: "https://socialblade.com",                                     desc: "YouTube, Twitter, Instagram, Twitch growth analytics" },
      { name: "Reddit User Analyser", url: "https://atomiks.github.io/reddit-user-analyser",              desc: "Reddit account karma, activity, and post history analysis" },
      { name: "RedditMetis",          url: "https://redditmetis.com",                                     desc: "Reddit user profile statistics and activity patterns" },
      { name: "Pullpush",             url: "https://pullpush.io",                                         desc: "Reddit comment and post archive search" },
      { name: "TGStat",               url: "https://tgstat.com",                                          desc: "Telegram channel analytics, subscriber stats, search" },
      { name: "TeleSearch",           url: "https://telesearch.me",                                       desc: "Telegram member and group search engine" },
      { name: "Telegago",             url: "https://cse.google.com/cse?q=+&cx=006368593537057042503:efxu7xprihg", desc: "Telegram content search via Google CSE" },
      { name: "Osintgram",            url: "https://github.com/Datalux/Osintgram",                        desc: "Instagram OSINT tool for account analysis and extraction" },
      { name: "LinkedIn X-Ray",       url: "https://google.com/search?q=site:linkedin.com/in/",           desc: "Google X-Ray search for LinkedIn profiles" },
      { name: "GHNames",              url: "https://ghnames.com",                                         desc: "GitHub username search and profile discovery" },
      { name: "Boardreader",          url: "https://boardreader.com",                                     desc: "Forum and discussion board search engine" },
      { name: "4Chan Search",         url: "https://4chansearch.com",                                     desc: "Search across 4chan boards and archived threads" },
      { name: "Kribrum",              url: "https://kribrum.io",                                          desc: "Russian social media monitoring and analytics" },
      { name: "UVRX",                 url: "http://www.uvrx.com/social.html",                             desc: "Social media file and content search aggregator" },
    ],
  },
  {
    id: "image-analysis", group: "social",
    label: "Image Search & Analysis", icon: Image,
    links: [
      { name: "Google Lens",          url: "https://lens.google.com",                                     desc: "AI-powered visual and reverse image search" },
      { name: "TinEye",               url: "https://tineye.com",                                          desc: "Reverse image search — find where an image appears online" },
      { name: "Yandex Images",        url: "https://yandex.com/images",                                   desc: "Strong reverse image search with facial recognition" },
      { name: "PimEyes",              url: "https://pimeyes.com",                                         desc: "Face recognition reverse image search across the web" },
      { name: "FaceCheck.ID",         url: "https://facecheck.id",                                        desc: "Reverse face image search across the web" },
      { name: "Search4Faces",         url: "https://search4faces.com",                                    desc: "Face reverse search across Russian social networks" },
      { name: "Baidu Images",         url: "https://image.baidu.com",                                     desc: "Chinese reverse image search — different index coverage" },
      { name: "ImgOps",               url: "https://imgops.com",                                          desc: "Image analysis hub: EXIF, reverse search, and metadata" },
      { name: "FotoForensics",        url: "https://fotoforensics.com",                                   desc: "Photo manipulation and ELA (error level analysis)" },
      { name: "Forensically",         url: "https://29a.ch/photo-forensics",                              desc: "Advanced image forensics: clone detection, noise analysis" },
      { name: "Jeffrey's Exif",       url: "http://exif.regex.info",                                      desc: "Detailed EXIF and metadata viewer for images" },
      { name: "GeoSpy",               url: "https://geospy.web.app",                                      desc: "AI-powered image geolocation estimation" },
      { name: "Pixsy",                url: "https://pixsy.com",                                           desc: "Find stolen or reused images across the web" },
      { name: "ReverseImageLocation", url: "https://reverseimagelocation.com",                            desc: "Determine photo location via reverse image analysis" },
    ],
  },
  {
    id: "video-media", group: "social",
    label: "Video & Media OSINT", icon: Video,
    links: [
      { name: "YouTube Metadata",     url: "https://mattw.io/youtube-metadata",                           desc: "Extract full metadata from YouTube videos and channels" },
      { name: "YouTube GeoFind",      url: "https://mattw.io/youtube-geofind",                            desc: "Find geotagged YouTube videos by location on a map" },
      { name: "Filmot",               url: "https://filmot.com",                                          desc: "Search inside YouTube subtitles and transcripts" },
      { name: "yt-dlp",               url: "https://github.com/yt-dlp/yt-dlp",                            desc: "Download video from YouTube and 1000+ other sites" },
      { name: "Find YouTube Video",   url: "https://findyoutubevideo.thetechrobo.ca",                     desc: "Find deleted or unlisted YouTube videos" },
      { name: "Internet Archive Video",url: "https://archive.org/details/opensource_movies",              desc: "Archive of open source and public domain videos" },
      { name: "EarthCam",             url: "https://earthcam.com",                                        desc: "Live and archived webcams from around the world" },
      { name: "YouTube Comment Export",url: "https://audiencecue.com/en/tools/youtube-comment-downloader", desc: "Download and export YouTube video comments" },
    ],
  },
  {
    id: "news-intel", group: "social",
    label: "News Intelligence", icon: Rss,
    links: [
      { name: "GDELT Project",        url: "https://gdeltproject.org",                                    desc: "Global event database — 100+ languages, real-time news" },
      { name: "Media Cloud",          url: "https://mediacloud.org",                                      desc: "Open-source media analysis and story tracking" },
      { name: "Google News",          url: "https://news.google.com",                                     desc: "Aggregated news with advanced topic search" },
      { name: "Google Alerts",        url: "https://google.com/alerts",                                   desc: "Set alerts for any keyword — get emailed on new results" },
      { name: "Bellingcat",           url: "https://bellingcat.com",                                      desc: "Open source investigations and verification resources" },
      { name: "OCCRP",                url: "https://occrp.org",                                           desc: "Organized crime and corruption investigative journalism" },
      { name: "ProPublica",           url: "https://propublica.org",                                      desc: "Investigative journalism with public interest data" },
      { name: "AllSides",             url: "https://allsides.com",                                        desc: "Media bias checker — left, center, and right coverage" },
      { name: "Ground News",          url: "https://ground.news",                                         desc: "Compare how different outlets cover the same story" },
      { name: "Hacker News",          url: "https://news.ycombinator.com",                                desc: "Tech and security community news and discussion" },
    ],
  },
  {
    id: "radio-wireless", group: "social",
    label: "Radio & Wireless", icon: Radio,
    links: [
      { name: "Broadcastify",         url: "https://broadcastify.com",                                    desc: "Live and archived police, fire, and EMS scanner audio" },
      { name: "RadioReference",       url: "https://radioreference.com",                                  desc: "Frequency database and scanner reference wiki" },
      { name: "WiGLE",                url: "https://wigle.net",                                           desc: "Wireless network mapping — geolocation and SSID search" },
      { name: "WebSDR",               url: "http://websdr.ewi.utwente.nl:8901",                           desc: "Online shortwave radio receiver for global broadcasts" },
      { name: "FCC License Search",   url: "https://wireless.fcc.gov/uls",                               desc: "FCC ULS — search licensed radio stations and operators" },
      { name: "IPTV-org",             url: "https://iptv-org.github.io",                                  desc: "Directory of 28,000+ public IP television channels" },
      { name: "GlobalTuners",         url: "https://globaltuners.com",                                    desc: "Remote-controlled radio receivers worldwide" },
      { name: "RTL-SDR",              url: "https://rtl-sdr.com",                                         desc: "Resources and tools for software-defined radio" },
    ],
  },

  /* ── FINANCIAL ─────────────────────────────────────── */
  {
    id: "business", group: "financial",
    label: "Business & Corporate", icon: Building2,
    links: [
      { name: "OpenCorporates",       url: "https://opencorporates.com",                                  desc: "World's largest open database of companies (200M+)" },
      { name: "Companies House",      url: "https://find-and-update.company-information.service.gov.uk",  desc: "UK company registry, filings, and officer data" },
      { name: "Corporation Wiki",     url: "https://corporationwiki.com",                                 desc: "US company connections and officer relationship graphs" },
      { name: "Crunchbase",           url: "https://crunchbase.com",                                      desc: "Startup funding, acquisitions, personnel data" },
      { name: "OCCRP Aleph",          url: "https://aleph.occrp.org",                                     desc: "OCCRP's investigative data platform — leaks, filings, entities" },
      { name: "OpenOwnership",        url: "https://openownership.org",                                   desc: "Worldwide beneficial ownership transparency data" },
      { name: "LEI Search",           url: "https://search.gleif.org",                                    desc: "Find who owns and who is owned by a company (global)" },
      { name: "EDGAR",                url: "https://www.sec.gov/cgi-bin/browse-edgar",                    desc: "US SEC filings — public company financial disclosures" },
      { name: "LittleSis",            url: "https://littlesis.org",                                       desc: "Power structure tracker — who knows whom in business/politics" },
      { name: "WIPO Global Brands",   url: "https://www3.wipo.int/branddb/en",                            desc: "Global brand and trademark database (46M+ records)" },
      { name: "Tradeint",             url: "https://tradint.io/tradint-researcher",                       desc: "Quick access to 85+ tools for company and website research" },
      { name: "Glassdoor",            url: "https://glassdoor.com",                                       desc: "Employee reviews, salaries, and org structure insights" },
      { name: "Bloomberg",            url: "https://bloomberg.com",                                       desc: "Financial data, executive profiles, and company news" },
      { name: "Corporative Registry", url: "https://cipher387.github.io/corporative_registry_worldwide_catalog", desc: "Business registry catalog for 63 countries" },
    ],
  },
  {
    id: "crypto", group: "financial",
    label: "Cryptocurrency", icon: Coins,
    links: [
      { name: "Etherscan",            url: "https://etherscan.io",                                        desc: "Ethereum blockchain explorer and analytics" },
      { name: "Blockchair",           url: "https://blockchair.com",                                      desc: "Multi-chain blockchain explorer — Bitcoin, ETH, BNB, more" },
      { name: "Blockchain.com",       url: "https://blockchain.com/explorer",                             desc: "Bitcoin blockchain explorer and wallet lookup" },
      { name: "Bitcoin Abuse",        url: "https://bitcoinabuse.com",                                    desc: "Database of bitcoin addresses used in scams and ransomware" },
      { name: "Breadcrumbs",          url: "https://breadcrumbs.app",                                     desc: "Visual crypto transaction tracing and attribution" },
      { name: "OXT.me",               url: "https://oxt.me",                                              desc: "Bitcoin transaction graph analysis and privacy research" },
      { name: "Mempool Space",        url: "https://mempool.space",                                       desc: "Bitcoin mempool explorer and fee estimator" },
      { name: "WalletExplorer",       url: "https://walletexplorer.com",                                  desc: "Bitcoin wallet clustering and entity identification" },
      { name: "Bitcoin Who's Who",    url: "https://bitcoinwhoswho.com",                                  desc: "Bitcoin address scam and abuse reporting" },
      { name: "Ethplorer",            url: "https://ethplorer.io",                                        desc: "Ethereum token and wallet tracker with charts" },
    ],
  },
  {
    id: "public-records", group: "financial",
    label: "Public Records & Legal", icon: Scale,
    links: [
      { name: "CourtListener",        url: "https://courtlistener.com",                                   desc: "Free US court opinions, PACER docs, and oral arguments" },
      { name: "PACER",                url: "https://pacer.gov",                                           desc: "US federal court electronic records access" },
      { name: "JudyRecords",          url: "https://judyrecords.com",                                     desc: "Free US court records search — 600M+ cases" },
      { name: "RECAP Archive",        url: "https://courtlistener.com/recap",                             desc: "Millions of PACER documents made free" },
      { name: "MuckRock",             url: "https://muckrack.com",                                        desc: "FOIA request tracking and journalist tools" },
      { name: "FOIA.gov",             url: "https://foia.gov",                                            desc: "US government FOIA request portal" },
      { name: "GovSalaries",          url: "https://govsalaries.com",                                     desc: "US government employee salary search" },
      { name: "Federal Inmate Locator",url: "https://www.bop.gov/inmateloc",                              desc: "Federal Bureau of Prisons inmate locator" },
      { name: "VineLink",             url: "https://vinelink.com",                                        desc: "Victim notification — inmate status by state" },
      { name: "UniCourt",             url: "https://unicourt.com",                                        desc: "US litigation analytics and attorney intelligence" },
      { name: "Voter Records",        url: "https://voterrecords.com",                                    desc: "US voter registration lookup by state" },
    ],
  },

  /* ── GEO & LOCATION ────────────────────────────────── */
  {
    id: "geo-maps", group: "geo",
    label: "Geo & Maps", icon: MapPin,
    links: [
      { name: "Google Maps",          url: "https://maps.google.com",                                     desc: "Satellite imagery, street view, and location mapping" },
      { name: "Mapillary",            url: "https://mapillary.com",                                       desc: "Crowdsourced street-level imagery worldwide" },
      { name: "WiGLE",                url: "https://wigle.net",                                           desc: "Wireless network mapping and SSID geolocation" },
      { name: "Shodan Maps",          url: "https://maps.shodan.io",                                      desc: "Geographic view of internet-exposed devices" },
      { name: "Liveuamap",            url: "https://liveuamap.com",                                       desc: "Live conflict and geopolitical event mapping" },
      { name: "Zoom Earth",           url: "https://zoom.earth",                                          desc: "Real-time satellite imagery and weather" },
      { name: "KartaView",            url: "https://kartaview.org/map",                                   desc: "Open street-level photo mapping" },
      { name: "SunCalc",              url: "https://suncalc.org",                                         desc: "Sun position calculator for image geolocation verification" },
      { name: "Google Earth",         url: "https://google.com/earth",                                    desc: "3D globe with historical imagery time slider" },
      { name: "OpenStreetMap",        url: "https://openstreetmap.org",                                   desc: "Collaborative open-source world map" },
      { name: "Instant Street View",  url: "https://instantstreetview.com",                               desc: "Jump to Google Street View by coordinates or address" },
      { name: "EarthCam",             url: "https://earthcam.com",                                        desc: "Live and archived webcams mapped globally" },
      { name: "HERE Maps",            url: "https://here.com",                                            desc: "Alternative map with traffic and route intelligence" },
    ],
  },
  {
    id: "flight-maritime", group: "geo",
    label: "Flight & Maritime", icon: Plane,
    links: [
      { name: "FlightAware",          url: "https://flightaware.com",                                     desc: "Real-time and historical commercial flight tracking" },
      { name: "Flightradar24",        url: "https://flightradar24.com",                                   desc: "Global ADS-B flight tracking with aircraft details" },
      { name: "ADS-B Exchange",       url: "https://adsbexchange.com",                                    desc: "Unfiltered global flight data — military and private included" },
      { name: "RadarBox",             url: "https://radarbox.com",                                        desc: "Flight tracking with historical playback" },
      { name: "OpenSky Network",      url: "https://opensky-network.org",                                  desc: "Non-profit ADS-B flight data network with free API" },
      { name: "PlaneFinder",          url: "https://planefinder.net",                                     desc: "Live flight tracking with route and history data" },
      { name: "MarineTraffic",        url: "https://marinetraffic.com",                                   desc: "Real-time AIS vessel tracking worldwide" },
      { name: "VesselFinder",         url: "https://vesselfinder.com",                                    desc: "Ship tracking with port arrival predictions" },
      { name: "FleetMon",             url: "https://fleetmon.com",                                        desc: "Vessel intelligence and maritime fleet tracking" },
      { name: "AIS Hub",              url: "https://aishub.net",                                          desc: "Real-time AIS vessel data aggregator" },
    ],
  },
  {
    id: "geospatial", group: "geo",
    label: "Geospatial Intelligence", icon: Satellite,
    links: [
      { name: "Sentinel Hub",         url: "https://apps.sentinel-hub.com/sentinel-playground",           desc: "Free ESA Copernicus satellite imagery browser" },
      { name: "NASA Worldview",       url: "https://worldview.earthdata.nasa.gov",                        desc: "NASA Earth observation imagery — near real-time" },
      { name: "USGS Earth Explorer",  url: "https://earthexplorer.usgs.gov",                              desc: "US Geological Survey satellite and aerial imagery archive" },
      { name: "Copernicus Open Access",url: "https://dataspace.copernicus.eu",                            desc: "Free ESA Copernicus satellite data access" },
      { name: "OpenAerialMap",        url: "https://openaerialmap.org",                                   desc: "Open collection of aerial and satellite imagery" },
      { name: "SkyFi",                url: "https://skyfi.com",                                           desc: "Task commercial satellites and order imagery" },
      { name: "GeoHack",              url: "https://geohack.toolforge.org",                               desc: "Coordinate lookup linking to 20+ map services" },
      { name: "Google Earth Engine",  url: "https://earthengine.google.com",                              desc: "Petabyte-scale geospatial analysis platform" },
    ],
  },

  /* ── UTILITIES & TOOLS ─────────────────────────────── */
  {
    id: "utilities", group: "tools",
    label: "Utilities", icon: Wrench,
    links: [
      { name: "CyberChef",            url: "https://gchq.github.io/CyberChef",                           desc: "100+ data encoding, decoding, and transformation tools" },
      { name: "Regex101",             url: "https://regex101.com",                                        desc: "Regex builder, debugger, and explainer" },
      { name: "CentralOps",           url: "https://centralops.net",                                      desc: "Network tools: DNS, traceroute, WHOIS, ping" },
      { name: "Transform Tools",      url: "https://transform.tools",                                     desc: "Convert between JSON, SQL, TypeScript, Markdown, HTML" },
      { name: "JSONCrack",            url: "https://jsoncrack.com",                                       desc: "Visualize and search JSON data interactively" },
      { name: "pyWhat",               url: "https://github.com/bee-san/pyWhat",                           desc: "Identify API keys, wallet addresses, emails in any text" },
      { name: "LemmeKnow",            url: "https://github.com/swanandx/lemmeknow",                       desc: "Identify data types: credit cards, crypto wallets, API keys" },
      { name: "Chepy",                url: "https://github.com/securisec/chepy",                          desc: "Python CLI version of CyberChef with extras" },
      { name: "Online Hash Tools",    url: "https://emn178.github.io/online-tools",                       desc: "55 tools for hash calculation, encoding, and decoding" },
      { name: "Epoch Converter",      url: "https://epochconverter.com",                                  desc: "Unix timestamp to human-readable date converter" },
      { name: "Base64 Decode",        url: "https://base64decode.org",                                    desc: "Base64 encode and decode" },
      { name: "URL Decoder",          url: "https://urldecoder.org",                                      desc: "URL encoding and decoding" },
      { name: "OSINT Framework",      url: "https://osintframework.com",                                  desc: "Categorized OSINT tool directory — meta-resource" },
      { name: "Cipher387 OSINT Map",  url: "https://cipher387.github.io/osintmap",                       desc: "Worldwide map of country-specific OSINT tools" },
      { name: "Lookyloo",             url: "https://lookyloo.circl.lu",                                   desc: "Scrape a site and visualize all domain calls and redirects" },
      { name: "ToS;DR",               url: "https://tosdr.org",                                           desc: "Summary of privacy/ToS clauses for popular sites" },
      { name: "MMHDAN",               url: "https://mmhdan.herokuapp.com",                                desc: "Generate favicon/cert/HTML fingerprints for IOT search" },
      { name: "HexEd.it",             url: "https://hexed.it",                                           desc: "Browser-based hex editor for binary and file analysis" },
    ],
  },
  {
    id: "file-doc-search", group: "tools",
    label: "File & Document Search", icon: FileText,
    links: [
      { name: "de Digger",            url: "https://dedigger.com",                                        desc: "Search public files in Google Drive" },
      { name: "Heystack",             url: "https://heystacks.com",                                       desc: "Search public Google Docs, Sheets, and Slides" },
      { name: "NAPALM FTP Indexer",   url: "https://searchftps.net",                                      desc: "FTP server file search engine" },
      { name: "ODCrawler",            url: "https://odcrawler.xyz",                                       desc: "Open directory file search engine" },
      { name: "Open Directory Finder",url: "https://ewasion.github.io/opendirectory-finder",             desc: "Google CSE-based open directory search" },
      { name: "DocumentCloud",        url: "https://documentcloud.org",                                   desc: "5M+ public government and corporate documents" },
      { name: "FBI Vault",            url: "https://vault.fbi.gov",                                       desc: "FBI FOIA document library — 6,700+ scanned documents" },
      { name: "Anna's Archive",       url: "https://annas-archive.org",                                   desc: "Shadow library search for books, papers, magazines" },
      { name: "Industry Docs (UCSF)", url: "https://industrydocuments.ucsf.edu",                          desc: "Tobacco, pharma, chemical, fossil fuel industry archives" },
      { name: "Filesec.io",           url: "https://filesec.io",                                          desc: "File extension lookup — what each type is used for" },
      { name: "Library Genesis",      url: "https://libgen.fun",                                           desc: "Free search engine for books and academic articles" },
      { name: "Snowfl",               url: "https://snowfl.com",                                           desc: "Real-time torrent aggregator across public indexes" },
      { name: "Filesearching.com",    url: "https://filesearching.com",                                    desc: "FTP server search engine with filetype and TLD filters" },
      { name: "Mamont FTP",           url: "https://www.mmnt.net",                                         desc: "FTP indexer — search public FTP servers for files" },
      { name: "Cloud File Search",    url: "http://filesearch.link",                                       desc: "Search across 59 file-sharing sites at once" },
      { name: "Torrends.to",          url: "https://torrends.to",                                          desc: "Torrent aggregator with real-time tracker listings" },
      { name: "DDL Search",           url: "http://ddlsearch.free.fr",                                     desc: "Search Rapidshare, Megaupload, and similar hosters" },
      { name: "Internet Archive Software", url: "https://archive.org/details/software",                   desc: "Archive of vintage and abandonware software" },
    ],
  },
  {
    id: "bugbounty-vuln", group: "tools",
    label: "Bug Bounty & Vuln Search", icon: Bug,
    links: [
      { name: "Firebounty",           url: "https://firebounty.com",                                      desc: "Bug bounty program search engine" },
      { name: "BugBountyHunting",     url: "https://bugbountyhunting.com",                                desc: "Search bug bounty writeups: XSS, SSRF, RCE, IDOR" },
      { name: "ExploitAlert",         url: "https://exploitalert.com",                                    desc: "Searchable exploit database (2005–2022)" },
      { name: "Hacking the Cloud",    url: "https://hackingthe.cloud",                                    desc: "Encyclopedia of AWS, Azure, and GCP attack techniques" },
      { name: "Control Validation",   url: "https://controlcompass.github.io",                            desc: "9000+ detection rules mapped to offensive techniques" },
      { name: "NERD",                 url: "https://nerd.cesnet.cz",                                      desc: "Network entity reputation — search by IP, domain, country" },
      { name: "CVE Details",          url: "https://cvedetails.com",                                      desc: "CVE vulnerability database with scoring and filters" },
      { name: "NVD",                  url: "https://nvd.nist.gov",                                        desc: "NIST National Vulnerability Database" },
      { name: "RFC.fyi",              url: "https://rfc.fyi",                                             desc: "Browsable and searchable RFC index" },
    ],
  },
  {
    id: "osint-frameworks", group: "tools",
    label: "OSINT Frameworks", icon: Layers,
    links: [
      { name: "Maltego",              url: "https://maltego.com",                                         desc: "Visual link analysis and graph-based OSINT platform" },
      { name: "SpiderFoot",           url: "https://spiderfoot.net",                                      desc: "Automated OSINT collection across 200+ data sources" },
      { name: "Recon-ng",             url: "https://github.com/lanmaster53/recon-ng",                     desc: "Web reconnaissance framework with module ecosystem" },
      { name: "BBOT",                 url: "https://github.com/blacklanternsecurity/bbot",                desc: "Modular OSINT framework — 50+ scanning modules" },
      { name: "theHarvester",         url: "https://github.com/laramies/theHarvester",                    desc: "Email, hostname, and subdomain harvesting tool" },
      { name: "Amass",                url: "https://github.com/owasp-amass/amass",                        desc: "OWASP attack surface mapping and asset discovery" },
      { name: "Scrummage",            url: "https://github.com/matamorphosis/Scrummage",                  desc: "Ultimate OSINT and threat hunting framework" },
      { name: "OSINT Toolkit",        url: "https://github.com/dev-lu/osint_toolkit",                     desc: "Self-hosted web app for IPs, domains, emails, hashes, CVEs" },
      { name: "IntelTechniques Tools",url: "https://inteltechniques.com/tools",                           desc: "Michael Bazzell's curated OSINT tools collection" },
      { name: "Mr.Holmes",            url: "https://github.com/Lucksi/Mr.Holmes",                         desc: "OSINT toolkit for domains, phone numbers, and social media" },
    ],
  },

  /* ── NEW: PLATFORM-SPECIFIC SOCIAL ─────────────────── */
  {
    id: "twitter-osint", group: "social",
    label: "Twitter / X Tools", icon: Twitter,
    links: [
      { name: "Whotwi",               url: "https://en.whotwi.com",                                       desc: "Twitter account analysis — mutual follows, daily activity" },
      { name: "BirdHunt",             url: "https://birdhunt.co",                                         desc: "Find recent tweets by geolocation and radius" },
      { name: "Followerwonk",         url: "https://followerwonk.com",                                    desc: "Bio search, follower analytics, and account comparison" },
      { name: "Treeverse",            url: "https://treeverse.app",                                       desc: "Visualize Twitter thread conversations as a graph" },
      { name: "Hashtagify",           url: "https://hashtagify.me",                                       desc: "Hashtag popularity and related hashtag comparison" },
      { name: "Tweet Binder",         url: "https://www.tweetbinder.com",                                 desc: "Detailed Twitter account analytics and report" },
      { name: "Botometer",            url: "https://botometer.osome.iu.edu",                              desc: "Bot probability score for any Twitter account" },
      { name: "Foller.me",            url: "https://foller.me",                                           desc: "Account statistics, hashtags, topics, and mentions" },
      { name: "GetDayTrends",         url: "https://getdaytrends.com",                                    desc: "Historical Twitter trending topics by country and day" },
      { name: "Sleeping Time",        url: "http://sleepingtime.org",                                     desc: "Estimate an account's timezone from tweet activity" },
      { name: "ShadowBan Checker",    url: "https://shadowban.yuzurisa.com",                              desc: "Check if a Twitter account has been shadowbanned" },
      { name: "DoesFollow",           url: "https://doesfollow.com",                                      desc: "Check if one Twitter account follows another" },
      { name: "One Million Tweet Map",url: "https://onemilliontweetmap.com",                              desc: "Geolocated tweet heatmap — visualize location-tagged tweets" },
      { name: "Tweeplers",            url: "https://www.tweeplers.com",                                   desc: "Find Twitter users by location and trending topics" },
      { name: "FollowerAudit",        url: "https://www.followeraudit.com",                               desc: "Audit followers for fake and inactive accounts" },
      { name: "Scoutzen",             url: "https://www.scoutzen.com/twitter-lists/search",               desc: "Search Twitter lists by keywords" },
      { name: "Eight Dollars",        url: "https://github.com/wseagar/eight-dollars",                    desc: "Find Twitter Blue verified accounts by any field" },
      { name: "Wayback Tweets",       url: "https://waybacktweets.streamlit.app",                         desc: "Retrieve archived and deleted tweets from Wayback Machine" },
      { name: "TweetFeed",            url: "https://tweetfeed.live",                                      desc: "IOCs (IPs, domains, hashes) shared by security researchers" },
      { name: "Twitter Archive Parser",url: "https://github.com/timhutton/twitter-archive-parser",       desc: "Parse and export your Twitter data archive" },
    ],
  },
  {
    id: "youtube-tools", group: "social",
    label: "YouTube Tools", icon: Youtube,
    links: [
      { name: "YouTube Metadata",     url: "https://mattw.io/youtube-metadata",                           desc: "Full metadata extraction for videos and channels" },
      { name: "YouTube GeoFind",      url: "https://mattw.io/youtube-geofind",                            desc: "Find geotagged videos on a map by location" },
      { name: "Filmot",               url: "https://filmot.com",                                          desc: "Search inside YouTube subtitles and closed captions" },
      { name: "YouTube Unlisted",     url: "https://unlistedvideos.com",                                  desc: "Find unlisted YouTube videos via brute-force ID search" },
      { name: "Amnesty DataViewer",   url: "https://citizenevidence.amnestyusa.org",                      desc: "Verify video upload date and metadata for evidence use" },
      { name: "YTComment Finder",     url: "https://ytcomment.kmcat.uk",                                  desc: "Search all comments on any YouTube video" },
      { name: "YT Comment Downloader",url: "https://github.com/egbertbouman/youtube-comment-downloader", desc: "Download full comment thread from any YouTube video" },
      { name: "Anilyzer",             url: "https://anilyzer.com",                                        desc: "Watch YouTube videos frame-by-frame for verification" },
      { name: "WatchFrameByFrame",    url: "http://www.watchframebyframe.com",                            desc: "Step through video frames in browser — no download needed" },
      { name: "Hadzy",                url: "https://hadzy.com",                                            desc: "YouTube comment search engine" },
      { name: "YouTube Transcript API",url: "https://github.com/jdepoix/youtube-transcript-api",         desc: "Programmatically fetch subtitles from any YouTube video" },
      { name: "Channel Crawler",      url: "https://channelcrawler.com",                                  desc: "Discover YouTube channels by keyword, subscriber count" },
      { name: "YouTube Scraper",      url: "https://apify.com/bernardo/youtube-scraper",                  desc: "Scrape channel metadata and video data at scale" },
      { name: "YouGlish",             url: "https://youglish.com",                                        desc: "Search YouTube for specific word or phrase usage" },
      { name: "YouTube Lookup",       url: "https://youtube-lookup.vercel.app",                           desc: "Channel and video metadata lookup by ID or URL" },
      { name: "Noxinfluencer",        url: "https://noxinfluencer.com/youtube/channel-compare",           desc: "Compare YouTube channel growth and analytics" },
      { name: "Channel Search",       url: "https://tools.digitalmethods.net/netvizz/youtube/mod_channels_search.php", desc: "Search and export YouTube channels by keyword" },
      { name: "yt-dlp",               url: "https://github.com/yt-dlp/yt-dlp",                            desc: "Download video from YouTube and 1000+ other sites" },
    ],
  },

  /* ── NEW: FINANCIAL ADDITIONS ───────────────────────── */
  {
    id: "data-statistics", group: "financial",
    label: "Data & Statistics", icon: BarChart2,
    links: [
      { name: "CIA World Factbook",   url: "https://www.cia.gov/the-world-factbook",                      desc: "Country profiles: geography, economy, government, military" },
      { name: "World Bank Open Data", url: "https://data.worldbank.org",                                  desc: "Global development indicators and economic data" },
      { name: "UN Data",              url: "http://data.un.org",                                           desc: "UN statistical database across all member states" },
      { name: "OECD Data",            url: "https://data.oecd.org",                                       desc: "Economic, environmental, and social statistics" },
      { name: "Eurostat",             url: "https://ec.europa.eu/eurostat",                               desc: "European Union statistical office — economy and society" },
      { name: "Statista",             url: "https://www.statista.com",                                    desc: "Market and industry statistics — 1M+ datasets" },
      { name: "Google Public Data",   url: "https://www.google.com/publicdata/directory",                 desc: "Browse and visualize public datasets from multiple sources" },
      { name: "Gapminder",            url: "https://www.gapminder.org/data",                              desc: "Global development data — health, wealth, population" },
      { name: "Our World in Data",    url: "https://ourworldindata.org",                                  desc: "Visualized global statistics on all major issues" },
      { name: "IndexMundi",           url: "https://www.indexmundi.com",                                  desc: "Country facts, statistics, and charts from world agencies" },
      { name: "Trading Economics",    url: "https://www.tradingeconomics.com",                            desc: "200+ countries — GDP, inflation, unemployment, trade" },
      { name: "WHO Data",             url: "https://www.who.int/gho/en",                                  desc: "Global health observatory — mortality, disease, health systems" },
      { name: "Pew Research Datasets",url: "https://www.pewresearch.org/internet/datasets",               desc: "Social and demographic survey data, free download" },
      { name: "Data.gov",             url: "https://data.gov",                                            desc: "US government open data — 300,000+ datasets" },
      { name: "Data.gov.uk",          url: "https://data.gov.uk",                                         desc: "UK government open data portal" },
      { name: "EU Open Data",         url: "https://data.europa.eu",                                      desc: "European Union official open data portal" },
      { name: "Transparency.org CPI", url: "https://www.transparency.org/en/cpi",                        desc: "Corruption Perceptions Index by country" },
      { name: "GDELT Events DB",      url: "https://gdeltproject.org",                                    desc: "Global event database — 250+ languages, real-time news" },
      { name: "Nation Master",        url: "https://www.nationmaster.com/statistics",                     desc: "Cross-country comparison charts for 1000+ indicators" },
      { name: "Google Finance",       url: "https://www.google.com/finance",                              desc: "Stock prices, financial news, and market data" },
    ],
  },

  /* ── NEW: IDENTITY ADDITIONS ────────────────────────── */
  {
    id: "vehicle-research", group: "identity",
    label: "Vehicle Research", icon: Car,
    links: [
      { name: "VIN Search Toolbox",   url: "https://cipher387.github.io/venicle_number_search_toolbox",  desc: "License plate/VIN lookup for 14 countries from one page" },
      { name: "WorldLicensePlates",   url: "http://www.worldlicenseplates.com",                           desc: "Visual index of license plate designs by country" },
      { name: "FaxVIN",               url: "https://www.faxvin.com",                                      desc: "VIN lookup — history, specs, and title records" },
      { name: "EpicVIN",              url: "https://epicvin.com",                                         desc: "Vehicle history report by VIN number" },
      { name: "Carfax",               url: "https://www.carfax.com",                                      desc: "US vehicle history, accidents, and ownership records" },
      { name: "NHTSA VIN Decoder",    url: "https://vpic.nhtsa.dot.gov/api",                              desc: "US federal VIN decoder and recall lookup API" },
      { name: "VinCheck",             url: "https://www.vincheck.info",                                   desc: "Free VIN decoder — make, model, year, specs" },
      { name: "AutoCheck",            url: "https://www.autocheck.com",                                   desc: "Vehicle history report and title search" },
      { name: "DMV.org",              url: "https://www.dmv.org",                                         desc: "State DMV links and US vehicle record resources" },
      { name: "PlateRecognizer",      url: "https://platerecognizer.com",                                 desc: "License plate recognition API for image analysis" },
      { name: "Open Motor Data",      url: "https://developer.nrel.gov/docs/vehicles",                    desc: "US government vehicle fuel economy and specs data" },
      { name: "CheckThatVIN",         url: "https://checkthatvin.com",                                    desc: "Free VIN check — market value and theft records" },
    ],
  },

  /* ── NEW: TOOLS ADDITIONS ───────────────────────────── */
  {
    id: "web-monitoring", group: "tools",
    label: "Web Monitoring", icon: Eye,
    links: [
      { name: "ChangeDetection.io",   url: "https://changedetection.io",                                  desc: "Monitor any web page for changes — self-hostable" },
      { name: "Visualping",           url: "https://visualping.io",                                       desc: "Visual web page change detection with screenshot diffs" },
      { name: "Distill.io",           url: "https://distill.io",                                          desc: "Monitor web pages, spreadsheets, and APIs for changes" },
      { name: "Feedly",               url: "https://feedly.com",                                          desc: "RSS feed aggregator for tracking multiple sources" },
      { name: "Mention",              url: "https://mention.com",                                          desc: "Brand and keyword monitoring across web and social" },
      { name: "Talkwalker",           url: "https://www.talkwalker.com",                                  desc: "Social listening and news monitoring platform" },
      { name: "Silobreaker",          url: "https://www.silobreaker.com",                                 desc: "Threat and news intelligence monitoring platform" },
      { name: "FollowThatPage",       url: "https://www.followthatpage.com",                              desc: "Email notification when any web page changes" },
      { name: "Versionista",          url: "https://versionista.com",                                     desc: "Track and compare web content changes over time" },
      { name: "OnWebChange",          url: "http://onwebchange.com",                                      desc: "Monitor web pages for any content change" },
      { name: "Website-Diff",         url: "https://github.com/GeiserX/Website-Diff",                    desc: "Self-hosted website diff and alerting tool" },
      { name: "Netvibes",             url: "https://www.netvibes.com",                                    desc: "Dashboard aggregating RSS feeds and social streams" },
    ],
  },
];

export default function OsintPage() {
  const [search, setSearch]           = useState("");
  const [activeGroup, setActiveGroup] = useState("all");

  const totalLinks  = CATEGORIES.reduce((n, c) => n + c.links.length, 0);
  const totalCats   = CATEGORIES.length;

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase();
    return CATEGORIES
      .filter((cat) => activeGroup === "all" || cat.group === activeGroup)
      .map((cat) => ({
        ...cat,
        links: q
          ? cat.links.filter(
              (l) =>
                l.name.toLowerCase().includes(q) ||
                l.desc.toLowerCase().includes(q) ||
                cat.label.toLowerCase().includes(q)
            )
          : cat.links,
      }))
      .filter((cat) => cat.links.length > 0);
  }, [search, activeGroup]);

  const groupCounts = useMemo(() => {
    const counts = {};
    CATEGORIES.forEach((cat) => {
      counts[cat.group] = (counts[cat.group] || 0) + cat.links.length;
    });
    counts["all"] = totalLinks;
    return counts;
  }, [totalLinks]);

  return (
    <div className={styles.page}>
      <div className={styles.header}>
        <div>
          <h1 className={styles.title}>OSINT Reference</h1>
          <p className={styles.subtitle}>
            {totalLinks} curated tools across {totalCats} categories
          </p>
        </div>
        <div className={styles.searchWrap}>
          <Search size={14} className={styles.searchIcon} />
          <input
            className={styles.searchInput}
            placeholder="Filter tools…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      <div className={styles.groupFilters}>
        {GROUPS.map((g) => (
          <button
            key={g.id}
            className={`${styles.chip} ${activeGroup === g.id ? styles.chipActive : ""}`}
            onClick={() => setActiveGroup(g.id)}
          >
            {g.label}
            <span className={styles.chipCount}>{groupCounts[g.id] || 0}</span>
          </button>
        ))}
      </div>

      {filtered.length === 0 ? (
        <p className={styles.noResults}>No tools match &ldquo;{search}&rdquo;</p>
      ) : (
        <div className={styles.grid}>
          {filtered.map((cat) => {
            const Icon = cat.icon;
            return (
              <div key={cat.id} className={styles.card}>
                <div className={styles.cardHeader}>
                  <Icon size={13} className={styles.cardIcon} />
                  <span className={styles.cardTitle}>{cat.label}</span>
                  <span className={styles.cardCount}>{cat.links.length}</span>
                </div>
                <ul className={styles.linkList}>
                  {cat.links.map((link) => (
                    <li key={link.url}>
                      <a
                        href={link.url}
                        target="_blank"
                        rel="noreferrer noopener"
                        className={styles.link}
                      >
                        <span className={styles.linkName}>{link.name}</span>
                        <span className={styles.linkDesc}>{link.desc}</span>
                        <ExternalLink size={10} className={styles.linkArrow} />
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
