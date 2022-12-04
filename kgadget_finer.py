import os
import sys
import shutil
import time
from threading import Thread
from pwn import*
import re
from termcolor import colored

def gdb_connect_qemu():
	global p
	p = process('gdb')
	p.sendline(b'target remote :1234')
	time.sleep(5)
	p.recvuntil(b'pwndbg>')

def gdb_continue():
	global p
	p.recvuntil(b'pwndbg> ')
	p.sendline(b'c')
	time.sleep(1)

def gdb_interrupt():
	global p
	os.kill(p.pid, 2) #intterupt
	time.sleep(1)

def gdb_quit():
	global p
	p.recvuntil(b'pwndbg> ')
	p.sendline(b'q')
	p.close()
	time.sleep(1)

def gdb_command(cmd):
	p.recvuntil(b'pwndbg> ')
	p.sendline(cmd.encode())

def gdb_get_memory_val(address, count):
	original_count = count
	if count % 2 == 1:
		count += 1
	global p
	p.recvuntil(b'pwndbg> ')
	p.sendline('x/{0}gx {1}'.format(count,hex(address)).encode())
	time.sleep(2)
	count = int(count/2)
	total = b''
	for i in range(count):
		result = p.recvline().decode().split('\t')
		total += p64(int(result[1][2:],16)) + p64(int(result[2][2:-1],16))
	return total[0:original_count*8]

def run_qemu():
	global args
	parent_path = os.path.dirname(args[3])
	os.system("cd {0}; {1}".format(parent_path,args[3]))

def flush_qemu_output():
	out = open("/tmp/kgadget_finder.out","r")
	os.set_blocking(out.fileno(), False)
	out.read()
	out.close()

def run_command_qemu(cmd, wait):
	os.system("echo '{0}' >> /tmp/kgadget_finder.in".format(cmd))
	time.sleep(wait)
	out = open("/tmp/kgadget_finder.out","r")
	os.set_blocking(out.fileno(), False)
	tmp = out.read()
	if type(tmp) != 'NoneType':
		return str(tmp).split('\n')[1:len(str(tmp).split('\n'))-1]
	
	return 'Error'

def search_qemu_memry(value):
	#max value len 0x1000
	pid = get_qemu_pid()
	search_targets = []
	maps = open('/proc/{0}/maps'.format(pid),'r')
	while True:
		line = maps.readline()
		if not line:
			break
		if '/' not in line:
			start = int(line.split('-')[0],16)
			end = int(line.split('-')[1].split(' ')[0],16)
			search_targets.append((start,end))

		if '[stack]' in line:
			break
	maps.close()
	mem = open('/proc/{0}/mem'.format(pid),'rb+')
	for region in search_targets:
		start, end = region
		count = int((end - start)/0x4)
		search_region = start
		print(colored(hex(start)+' ~ '+hex(end),"yellow"))
		for i in range(count):
			#print(hex(search_region))
			mem.seek(search_region, 0)
			try:
				mem_val = mem.read(len(value))
				if mem_val == value:
					mem.close()
					return search_region
				search_region += 0x4

			except:
				pass
	mem.close()
	return -1

def read_qemu_memory(address, count):
	pid = get_qemu_pid()
	mem = open('/proc/{0}/mem'.format(pid),'rb+')
	mem.seek(address)
	result = mem.read(count)
	mem.close()
	return result 

def write_qemu_memory(address, value):
	pid = get_qemu_pid()
	mem = open('/proc/{0}/mem'.format(pid),'wb')
	mem.seek(address)
	mem.write(value)
	mem.close()


def get_qemu_pid():
	os.system("pgrep qemu >> pgrep_result")
	try:
		pid = int(open("pgrep_result", "r").read())
	except:
		print("[!] Can't find qemu")
		cleanup()
	os.remove("pgrep_result")
	return pid

def cleanup():
	print("[+] Cleanup!")
	shutil.move(args[3]+"_origin", args[3])
	os.system("rm inject_code_copy.c")
	os.system('rm inject_code_copy.o')
	os.system('chmod 777 {0}'.format(args[3]))
	print(colored("[+] All proccess done successfully!","green"))
	os.kill(get_qemu_pid(),15)
	os.kill(os.getpid(), 9)

if __name__ == "__main__":
	global args
	start_time = time.time()
	args = sys.argv
	if len(sys.argv) != 4:
		print("Kgadget finder : Make easy to find executable gagdet")
		print("Usage : python3 kgadget_finder.py <gadgets information file> <target kernel object file> <boot script path>")
		print("Gadget information is output of the ROPgadget or rp++")
		exit(0)

	#pre-process path
	for i in range(1,4):
		if args[i][len(args[i])-1] == '/':
			args[i] = args[i][:-1]


	print("[+] Check permission")
	if os.getuid() != 0:
		print('[!] Please run as root')
		exit(-1)

	print("[+] Check file exist")
	if not os.path.isfile(args[1]):
		print(colored("[!] Can't open gadget information file","yellow"))
		exit(-1)
	elif not os.path.isfile(args[2]):
		print(colored("[!] Can't open target kernel object file","yellow"))
		exit(-1)
	elif not os.path.isfile(args[3]):
		print(colored("[!] Can't open boot script file","yellow"))
		exit(-1)
	shutil.copyfile(args[3], args[3]+"_origin")

	print('[+] Create named pipe (/tmp/kgadget_finder.in/out)')
	os.system('rm /tmp/kgadget_finder.in')
	os.mkfifo('/tmp/kgadget_finder.in', 666)
	os.system('rm /tmp/kgadget_finder.out')
	os.mkfifo('/tmp/kgadget_finder.out', 666)

	print('[+] Edit boot script ({0})'.format(args[3]))
	boot_script = open(args[3], 'r+')
	boot_script_content = boot_script.read()
	if boot_script_content[len(boot_script_content)-1] == '\t' or boot_script_content[len(boot_script_content)-1] == '\n':
		boot_script.write('-serial pipe:/tmp/kgadget_finder >> /dev/null')
	elif boot_script_content[len(boot_script_content)-1] == ' ':
		boot_script.write('-serial pipe:/tmp/kgadget_finder >> /dev/null')
	else:
		boot_script.write(' -serial pipe:/tmp/kgadget_finder >> /dev/null')
	boot_script.close()
	
	Thread(target = run_qemu).start()
	time.sleep(1)
	print('[*] Start qemu (pid: {0})'.format(get_qemu_pid()))
	print('[/] Wait...')
	time.sleep(6)
	flush_qemu_output()

	print('[*] Check guest permission')
	result = run_command_qemu('id', 0.5)
	if 'uid=0' in result[0]:
		print(colored(result,'green'))
	else:
		print(colored(result,'red'))
	if 'uid=0' not in result[0]:
		print('[!] Please run guest as root')
		cleanup()

	print('[*] Extract kernel symbol')
	result = (run_command_qemu("cat /proc/kallsyms | grep -e modprobe_path -e page_offset_base", 4))

	for i in result:
		if 'modprobe_path' in str(i):
			modprobe_path_addr = int(i.split(' ')[0],16)
			print(colored(i,"yellow"))
			break
		
	for i in result:
		if 'page_offset_base' in str(i):
			page_base_offset =  int(i.split(' ')[0],16)
			print(colored(i,"yellow"))
			break


	print('[*] Get module base')
	result = (run_command_qemu("lsmod", 1))
	module_base = int(result[0].split(' ')[5],16)
	print(colored(result,'yellow'))

	print('[*] Get module byte code')
	gdb_connect_qemu()
	module_byte = gdb_get_memory_val(module_base,10)
	print('[*] Search kernel object on qemu memory')
	result = search_qemu_memry(module_byte)
	print('\033[32m'+hex(result)+'\033[0m => ' + str(module_byte[0:10]))
	module_qemu_address = result
	
	print('[+] Page base offset')
	page_base_offset_val = gdb_get_memory_val(page_base_offset, 1)
	print(colored(hex(u64(page_base_offset_val)),'yellow'))

	modprobe_path_addr &= 0xfffffffffffff000
	inject_code = open('inject_code.c', "r+")
	code_content = inject_code.read()
	code_content = code_content.replace('0x1111111111111111', str(hex(u64(page_base_offset_val))))
	code_content = code_content.replace('0x2222222222222222', str(hex(modprobe_path_addr + 4))) #result buffer
	code_content = code_content.replace('0x3333333333333333', str(hex(modprobe_path_addr))) #done flag
	code_content = code_content.replace('0x4444444444444444', str(hex(modprobe_path_addr + 0x210))) #gadget buffer
	inject_code.close()

	inject_code = open('inject_code_copy.c', "w")
	inject_code.write(code_content)
	inject_code.close()
	print('[*] Compile code')
	os.system("gcc -c inject_code_copy.c -fno-stack-protector -masm=intel")
	os.system("objcopy -O binary -j .text inject_code_copy.o inject_code_copy.o")
	inject_object = open('inject_code_copy.o', "rb")
	inject_object_code = inject_object.read()
	inject_object.close()

	print('[*] Inject code to qemu memory')
	write_qemu_memory(module_qemu_address, inject_object_code)
	gdb_command('set $rip = {0}'.format(module_base))
	gdb_continue()

	print('[*] Search kernel memory')
	magic = p64(0xdeadbeef) + p64(0xbabacafe) + p64(0xaaaabbbb)
	flag_mem = search_qemu_memry(magic)
	result_mem = flag_mem + 4
	print('\033[32m'+hex(flag_mem)+'\033[0m => ' + str(magic[0:10]))
	print('[+] Extract gadget information')
	result_file = open('result.txt', 'w')
	gadget_info = open(args[1], 'r')
	gadget_list = []
	gadget_origin_list = []
	#gdb_interrupt()
	count = 0
	flag = True;
	#gdb_quit()
	while flag:
		line = gadget_info.readline()
		if not line:
			flag = False
		elif '0x' in line:
			gadget_origin_list.append(line)
			gadget_list.append(int(line.split(' ')[0],16))

		if len(gadget_list) == 400 or (flag == False and len(gadget_list) != 0):
			gadget_mem = flag_mem + 0x210
			gadgets = b''
			for gadget in gadget_list:
				gadgets += p64(gadget)
			write_qemu_memory(gadget_mem, gadgets)
			
			write_qemu_memory(flag_mem, p32(0))

			#write_qemu_memory(flag_mem, p32(0))
			#input()
			while True:
				time.sleep(0.1)
				flag = read_qemu_memory(flag_mem, 4)
				if u32(flag) == 1:
					gadget_result = (read_qemu_memory(gadget_mem, 400 * 8))
					for i in range(400):
						converted = u64(gadget_result[i*8:(i+1)*8])
						if converted != 0:
							for j in gadget_origin_list:
								if hex(converted) in j:
									result_file.write(j[:-1] +'\n')
									count += 1
									break
							#result = read_qemu_memory(result_mem, 32)
							#print(hex(u64(result[0:8])), hex(u64(result[8:16])), hex(u64(result[16:24])), hex(u64(result[24:32])))
					gadget_origin_list = []
					gadget_list = []
					print('\r[+] Find {0} gadgets'.format(count), end = '')
					break
	print('\n[-] End')
	#exit
	result_file.close()
	end_time = time.time()
	gdb_interrupt()
	gdb_quit()
	print('Elapsed time(s) :', round(end_time-start_time,2))
	
	cleanup()

