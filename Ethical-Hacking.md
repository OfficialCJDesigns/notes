
				#	Ethical Hacking Notes

	•	Ethical Hacking and Basic Concepts of Networking 
	•	Ethical hacking is the act of locating the weaknesses and vulnerabilities of computer and information systems by replicating the intent and actions of malicious hackers.
	•	It is also known as penetration testing or red teaming. 
	•	Some terminologies used in hacking include cracking, spoofing and port scanning. Spoofing involves faking the originating IP address in a datagram. 
	•	Penetration testing methodologies include Tiger box, White box, Grey box and Black box models.
	•	Local Area Network (LAN) and Wide Area Network(WAN) are among the types of computer networks.
	•	Packet switching is a modern form of long-distance data communication. It is based on the store and forward concept.
	•	In the datagram approach, every immediate node has to take routing decisions dynamically. 
	•	The seven layers in the OSI model are: Application, Presentation, Session, Transport, Network, Datalink and Physical layers.
	•	TCP/IP is the most fundamental protocol used in the internet.
	•	Packet sniffers can be used to view IP packets. Examples of packet sniffers are Wireshark, Tshark, Windump etc. 

	•		                 # IP Addressing and Routing 
	•	Transparent and non-transparent fragmentation are the two major types of IP fragmentation
	•	Fragmentation is usually done by routers
	•	In transparent fragmentation, subsequent networks do not realize that fragmentation has taken place. So when each fragment comes, it is treated as an independent IP packet and routed separately.
	•	A major drawback of transparent fragmentation is the fact that all packets must be routed via the same exit router
	•	In non-transparent fragmentation, packet fragments are reassembled at the final destination host
	•	For non-transparent fragmentation, multiple exit routers may be used
	•	Ethernet has a maximum frame size of 1500 bytes
	•	Every host connected to the internet is identified by a unique 32-bit IP address, consisting of a network number and a host number
	•	Class A, Class B, Class C, Class D and Class E are the five defined IP address classes
	•	In TCP/IP, the transport layer consists of two protocols - TCP and UDP
	•	IP subnets introduce a network portion, a subnet portion and a host portion
	•	
	•			               # Routing Protocols 
	•	UDP is a classical connectionless protocol, which is used at the TCP level. It does not guarantee reliability in packet transfer.
	•	TCP/IP is the most dominant protocol that drives the Internet and IP is the most widely used protocol at the network layer level which is responsible for packet routing
	•	Direct delivery, indirect delivery are two categories of packet delivery options
	•	There are different routing methods which include: next-hop routing, network-specific routing, host-specific routing and default routing
	•	There are two types of routing tables - static and dynamic
	•	Two broad classes of routing protocols used on the internet are interior and exterior routing protocols
	•	Routing Information Protocol (RIP) and Open Shortest Path First (OSPF) are types of interior routing protocol while Broader Gateway Protocol (BGP) is a type of exterior routing protocol
	•	BGP is the most widely used exterior router protocol
	•	Limited address space and the need for more complex addressing and routing capabilities are some major drawbacks of IP version 4

	 #	Nessus  
	•	In ethical hacking different kinds of operating systems like Windows XP, Windows 7, Windows 8, Windows 10 and Linux are used
	•	Kali Linux is the preferred machine to be used as the hackers' machine
	•	There are different tools like VMware workstation, VMware player and VirtualBox for setting up a virtual hacking platform
	•	VirtualBox for different operating systems can be downloaded from the official website of virtualbox.org
	•	Reconnaissance or information gathering is categorized into active and passive reconnaissance
	•	In passive reconnaissance, information is not gathered directly from communicating with a victim.
	•	In active reconnaisanece, information is gathered by directly communicating with a victim
	•	Active reconnaissance include DNS Enumeration, Mail Server Enumeration, DNS Zone Transfer and Scanning
	•	The Nessus vulnerability scanning tool can be downloaded from the official website of Nessus

	#	Using Metasploit for Penetration testing 
	•	In ethical hacking different kinds of operating systems like Windows XP, Windows 7, Windows 8, Windows 10 and Linux are used
	•	Kali Linux is the preferred machine to be used as the hackers' machine
	•	There are different tools like VMware workstation, VMware player and VirtualBox for setting up a virtual hacking platform
	•	VirtualBox for different operating systems can be downloaded from the official website of virtualbox.org
	•	Reconnaissance or information gathering is categorized into active and passive reconnaissance
	•	In passive reconnaissance, information is not gathered directly from communicating with a victim.
	•	In active reconnaisanece, information is gathered by directly communicating with a victim
	•	Active reconnaissance include DNS Enumeration, Mail Server Enumeration, DNS Zone Transfer and Scanning
	•	The Nessus vulnerability scanning tool can be downloaded from the official website of Nessus

  #	Cryptography  
	•	A security attack is any action that compromises the security of information. 
	•	There are four types of security attacks - Interruption, Interception, Modification and Fabrication
	•	Interruption is an attack on availability, while interception is an attack on confidentiality
	•	Modification is an attack on integrity while fabrication is an attack on authenticity
	•	Passive and Active attacks are other classifications of security attacks
	•	There are four categories of active attacks: masquerade, replay, modification and denial of service
	•	There are two forms of encryption: private(symmetric) and public-key(asymmetric)
	•	Classical private-key encryption techniques fall under two categories - substitution ciphers and transposition ciphers
	•	The most widely used symmetric key or private key algorithm today is called Advanced Encryption Standard or AES
	•	The RSA algorithm in conjunction with some private key algorithm like AES can be used for secure data transfer over an insecure channel

	# Cryptographic Hash Functions 
	•	Hash functions are computational functions that determine a hash digest H from a given message M. They are also referred to as one-way functions
	•	There are two types of hash functions we can use; one that uses a key which is called keyed hash function and another one which does not require a key which is the un-keyed hash function.
	•	An unkeyed hash function is also called Modification Detection Code (MDE) while a keyed hash function is also known as Message Authentication Code (MAC)
	•	Authentication is a process through which the identity of the sender of a message can be confirmed
	•	SHA-512 and HMAC are types of one-way hash functions
	•	Digital signature is the digital equivalent of handwritten signatures, where the signer uses his private key to sign. There are four types of digital signatures
	•	Digital certificates require a Certification Authority (CA) whom every entity over a network can trust
	•	Secure Socket Layer (SSL) was first used by Netscape to ensure data security sent through HTTP, LDAP or POP3.
	•	One of the main objectives fo SSL is to ensure data integrity and privacy
	•	Transport Layer Security (TLS) is an extension of SSL which aims to provide security and data integrity at the transport layer between two web applications. 

	# Information Security 
	•	Stenography literally means "covered writing" in Greek. It may or may not be used in conjunction with cryptography.
	•	Digital watermarking embeds copyright ownership licence and similar information in a medium
	•	The size of an image is determined by pixels. A pixel is an instance of colour 
	•	A Graphics Interchange Format(GIF) is an 8-bit image file which supports at most 256 colours per image
	•	Joint Photography Experts Group (JPEG) is a 24-bit image file that uses lossy compression based on DCT
	•	GIF and JPEG formats use adaptations of the Lempel-Ziv (LZ) compression algorithm
	•	Biometrics are automated methods for recognizing individuals based on measurable biological and behavioural characteristics.
	•	Types of biometrics include fingerprint, signature, hand geometry, iris scan, etc 
	•	Denial-of-Service (DoS) attack is an explicit attempt by attackers to prevent legitimate users of a service from using a particular service
	•	In a DDoS attack, multiple compromised systems are used to attack a single target
	•	Domain Name System (DNS) maintains the correspondence between hostname and IP address

	# Information Security Attacks 
	•	In the early days of computer and mainframes, passwords were stored in a database as plain text
	•	Password Hashing, Plain Text Passwords and Password Hash Salting are types of passwords.
	•	Some password-cracking techniques used by hackers include dictionary attack, brute force attack, rainbow attack, Phishing, Offline cracking, social engineering, and malware.
	•	Whenever a victim accesses a phishing website and enters sensitive and confidential information such as username, password, credit card, debit card number, network credentials and more, then it automatically goes to the attacker's site.
	•	There are four types of phishing: Spear phishing attacks, Whaling attacks, Pharming and Voice phishing
	•	Spear Phishing attacks are directed at specific individuals or companies, usually using information specific to the victim to successfully represent the message as being authentic.
	• Whaling attacks are a type of Spear phishing attack that specifically target senior executives within an organization
	•	Malware or malicious software is an umbrella term which describes any malicious program or code that is harmful to systems
	•	Some types of malware include viruses worms, trojan horse, spyware, logic bombs, etc
	•	Use of antivirus, avoiding malicious websites, use of firewalls and difficult passwords are some measures that can be taken to secure the systems from attack

 	# Hardware Security 
	•	Physical attacks on hardware are carried out on the actual device using hardware tools. Other forms of attack are planned attacks ad stealing secret data
	•	Blackbox Testing, Physical Probing, Reverse Engineering and Side Chanel Analysis are some types of attacks that can be mounted on a hardware device
	•	Black Box Testing is an invasive type of attack where the attacker sends an input to the circuit and receives an output
	•	Physical Probing is an invasive attack which requires sophisticated instrumentation
	•	Hardware Trojan is a malicious logic inserted into a circuit with the knowledge of the designer or user
	•	The payload of a hardware trojan is the entire activity that the trojan executes when triggered
	•	Power analysis attack analyses the power consumed by a device while processing some cryptographic operations.
	•	Differential Power Analysis is a complex power analysis that partitions the data and related curves into two sets, according to select bits
	•	Physical Unclonable Function (PUF) should be unique, easy to evaluate, unclonable and one-way. These are some of its desirable properties

	# Vulnerability Scanning 
	•	SQL injection is a type of injection attack that makes it possible to execute malicious SQL statements.
	•	SQL injection attack can be performed using an automated tool called SQLMAP from Kali Linux
	•	Crosssite scripting (XSS) is a web security vulnerability that allows an attacker to compromise the interactions that users have with the vulnerable application. It enables an attacker to masquerade as a victim to carry out any action the user is able to perform
	•	There are mainly three types of cross-site scripting vulnerabilities: reflected, stored and DOM cross-site scripting
	•	Many websites require file upload functionality for their users. For instance, job portals allow prospective employees to upload their resumes, social media apps allow users to upload profile pictures etc
	•	This file upload functionality poses a big risk to the application and server if proper security measures are not put in place
	•	File upload vulnerability can be demonstrated using Kali Linux as the attacker's machine and Mestsploitable 2 OS which acts as the server

	# Network Analysis Tools 
	•	Network Mapper (Nmap) is an open-source tool for vulnerability scanning and network discovery. It was developed by Gordon Lyon in 1997.
	•	The main features of Nmap include host discovery, port scanning, service, version and OS detection.
	•	Host discovery can be done using ICMP Sweep, Broadcast ICMP, Non-Echo ICMP, TCP Sweep, and UDP Sweep.
	•	The major port scanning techniques in Nmap are TCP Connect scan, TCNP SYN scan, TCP Stealth scan and FTP Bounce scan
	•	TCP Connect scan uses basic TCP connection establishment mechanism.
	•	There are thousands of scripts available with Nmap to perform various operations.
	•	Network analysis is a process of analysing network activity by capturing network traffic.
	•	Some features of network analysers include graphical user interface and statistical report generation.
	•	Wireshark is an open-source tool for profiling network traffic and analysing packets.
