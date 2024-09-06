from tkinter import *
import tkinter as tk
from tkinter import messagebox
from tkinter import ttk
from tkinter.ttk import *
import socket
import threading
import time
# import mysql.connector as SQL
from tkinter import filedialog


# -----------------------Get ip -------------------------------
def wlan_ip():
    import subprocess
    result = subprocess.run('ipconfig', stdout=subprocess.PIPE, text=True).stdout.lower()
    scan = 0
    for i in result.split('\n'):
        if 'wireless' in i: scan = 1
        if scan:
            if 'ipv4' in i: return i.split(':')[1].strip()


# ----------------------------------------------------------------

Central_server_IP = "172.20.10.13"
MY_IP_ADDRESS = wlan_ip()
# MY_IP_ADDRESS = "172.20.10.13"
print("My IP is: ", MY_IP_ADDRESS)
MY_PORT = 65000
BUFFER = 1024
FILE_SEND_CODE = "0xYzVe_123Sending_@@"
curConnectionList = []
friendList = []
lock = threading.Lock()
lock2 = threading.Lock()


def recvListOfTupple(conn):
    myList = []
    try:
        lenghtList = int(conn.recv(BUFFER).decode())
        conn.sendall("OK".encode())
        lengthTup = int(conn.recv(BUFFER).decode())
        conn.sendall("OK".encode())
        for i in range(lenghtList):
            tup = ()
            for j in range(lengthTup):
                element = conn.recv(BUFFER).decode()
                conn.sendall("OKLA".encode())
                tup += (element,)
            myList.append(tup)
            conn.sendall("OK".encode())
    except:
        print("Error Receiving tupple")
    conn.close()
    return myList


class App(tk.Tk):
    def __init__(self):
        tk.Tk.__init__(self)
        self.title("Chat app")
        self.geometry("500x200")
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        self.resizable(width=False, height=False)
        self.pickFriend = 'tuan'
        self.myUsername = ""
        self.receive_pipe = ""
        self.sendSock = ""
        global friendList
        friendList = []

        container = tk.Frame()

        container.pack(side="top", fill="both", expand=True)
        container.grid_rowconfigure(0, weight=1)
        container.grid_columnconfigure(0, weight=1)
        # Create frames dictionary to store all frames
        self.frames = {}
        for F in {Login, HomePage}:
            frame = F(container, self)
            frame.grid(row=0, column=0, sticky="nsew")
            self.frames[F] = frame
        thread = threading.Thread(target=self.serverRole, args=())
        thread.daemon = True
        thread.start()
        thread1 = threading.Thread(target=self.listenEventFromServer, args=())
        thread1.daemon = True
        thread1.start()
        self.frames[Login].tkraise()

    def listenEventFromServer(self):

        while True:
            try:
                conn, addr = recvMessageFromServerSocket.accept()
                global friendList
                lock2.acquire()
                friendList = []
                lock2.release()
                data = recvListOfTupple(conn)
                conn.close()
                lock2.acquire()
                for i in data:
                    friendList.append(User(i[0], i[1], i[2]))
                self.frames[HomePage].data.delete(0, len(friendList))
                for i in range(len(friendList)):
                    self.frames[HomePage].data.insert(i, friendList[i].name)
                lock2.release()
            except:
                print("Error when running server")

    def signUP(self, curFrame):
        global friendList
        lock2.acquire()
        friendList = []
        lock2.release()
        newSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            newSocket.connect((Central_server_IP, 12000))
            newSocket.sendall("SignUp".encode())
            newSocket.recv(BUFFER)
            # send username
            username = curFrame.entry_user.get()
            self.myUsername = username
            newSocket.sendall(username.encode())
            newSocket.recv(BUFFER)
            newSocket.sendall(curFrame.entry_pswd.get().encode())

            newSocket.recv(BUFFER)
            newSocket.sendall(MY_IP_ADDRESS.encode())

            notice = newSocket.recv(BUFFER).decode()
            if notice == "Error":
                # Raise error
                curFrame.label_notice["text"] = "Username already exists"
                # Close connection
                newSocket.close()
            else:
                data = recvListOfTupple(newSocket)
                lock2.acquire()
                for i in data:
                    friendList.append(User(i[0], i[1], i[2]))
                newSocket.close()
                self.myUsername = username
                curFrame.label_notice["text"] = ""
                self.frames[HomePage].data.delete(0, len(friendList))
                for i in range(len(friendList)):
                    self.frames[HomePage].data.insert(i, friendList[i].name)
                lock2.release()
                self.frames[HomePage].tkraise()
        except:
            newSocket.close()
            print("Error when query DB")

    def logout(self):
        global friendList
        lock2.acquire()
        friendList = []
        lock2.release()
        newSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            newSocket.connect((Central_server_IP, 12000))
            newSocket.sendall("Logout".encode())
            newSocket.recv(BUFFER)
            # send username
            username = self.myUsername
            self.myUsername = ""
            newSocket.sendall(username.encode())
        except:
            print("Logout error")
        self.frames[Login].tkraise()

    def login(self, curFrame):
        global friendList
        lock2.acquire()
        friendList = []
        lock2.release()
        newSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            newSocket.connect((Central_server_IP, 12000))
            newSocket.sendall("Login".encode())
            newSocket.recv(BUFFER)
            # send username
            username = curFrame.entry_user.get()
            self.myUsername = username
            if username == "":
                curFrame.label_notice["text"] = "Username cannot be empty"
                return
            if curFrame.entry_pswd.get() == "":
                curFrame.label_notice["text"] = "Password cannot be empty"
                return

            newSocket.sendall(username.encode())
            newSocket.recv(BUFFER)
            newSocket.sendall(curFrame.entry_pswd.get().encode())

            notice = newSocket.recv(BUFFER).decode()
            if notice == "Error":
                # Raise error
                # TODO
                curFrame.label_notice["text"] = "Invalid username or password"
                # Close connection
                newSocket.close()
            elif notice == "Active":
                curFrame.label_notice["text"] = "Active username"
                # Close connection
                newSocket.close()
            else:
                data = recvListOfTupple(newSocket)
                lock2.acquire()
                for i in data:
                    friendList.append(User(i[0], i[1], i[2]))
                newSocket.close()
                self.myUsername = username
                curFrame.label_notice["text"] = ""
                self.frames[HomePage].data.delete(0, len(friendList))
                for i in range(len(friendList)):
                    self.frames[HomePage].data.insert(i, friendList[i].name)
                lock2.release()
                self.frames[HomePage].tkraise()
        except:
            newSocket.close()
            print("Error when query DB")

    def showPage(self, frameClass):
        self.frames[frameClass].tkraise()

    def connectClient(self, curFrame, data):
        global friendList
        try:
            self.pickFriend = data
            lock2.acquire()
            for i in friendList:
                if self.pickFriend == i.name:
                    IP = i.IP_address
                    Port = i.port
            lock2.release()
            # if IP == "" or Port == "":
            #     curFrame.label_notice["text"] = "Empty Field"
            #     return
            print(IP, Port)
            self.clientRole(IP, Port)
        except:
            # curFrame.label_notice["text"] = "Error when create connection"
            print("Error when create connection")

    def clientRole(self, IP, port):
        lock.acquire()
        for i in curConnectionList:
            if i.name == self.pickFriend:
                if i.status == 1:
                    print("Stop create new connect with this user: ", i.name)
                    return
        lock.release()

        try:
            # Try to connect to server through TCP
            try:
                thread = threading.Thread(target=self.manageConnection, args=(IP, port, None))
                thread.daemon = True
                thread.start()
            except:
                print("Error")
        except:
            print("Error")

    def manageConnection(self, IP, port, conn):
        print(IP, port)
        self.sendSock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        if conn:
            try:
                # create receive-mess pipe
                self.receive_pipe = conn
                string_port = self.receive_pipe.recv(BUFFER).decode()
                self.receive_pipe.sendall("OK".encode())
                # open new socket to send message
                # Waiting to receive new (IP, Port) of your target
                self.sendSock.connect((conn.getpeername()[0], int(string_port)))
                print(conn.getsockname()[0])
                chat_room_windown = ChatRoom(self, self.receive_pipe, self.sendSock, self.pickFriend)

                lock.acquire()
                curConnectionList.append(curUser(self.pickFriend, 1))
                lock.release()
                chat_room_windown.mainloop()

            except:
                print("Error in server role")
        else:
            try:
                self.sendSock.connect((IP, int(port)))  # change this Port to test

                self.sendSock.sendall(self.myUsername.encode())  # need o add
                self.sendSock.recv(BUFFER)

                # Send new (Port) of your device to create receive-mess pipe
                self.sendSock.sendall(str(MY_PORT + 1).encode())  # need o add
                self.sendSock.recv(BUFFER)

                # Waiting to receive new (IP, Port) of your target
                # accept connect to create receive-mess pipe
                self.receive_pipe, addr = recvSocket.accept()
                print("Hi")
                windownName = "Your Friend: "
                chat_room_windown = ChatRoom(self, self.receive_pipe, self.sendSock, self.pickFriend)
                lock.acquire()
                curConnectionList.append(curUser(self.pickFriend, 1))
                lock.release()
                chat_room_windown.mainloop()
            except:
                print("Error in client role")
        # chat_room_windown.protocol("WM_DELETE_WINDOW", chat_room_windown.on_closing())

    def serverRole(self):
        while True:
            try:
                breakSigal = 0
                conn, addr = onlineSocket.accept()
                # Take pickFriend from Client connection request
                self.pickFriend = conn.recv(BUFFER).decode()
                conn.sendall("OK".encode())
                # check if this friend was connected or not
                lock.acquire()
                for i in curConnectionList:
                    if i.name == self.pickFriend:
                        if i.status == 1:
                            breakSigal = 1
                            conn.close()
                            break
                lock.release()
                if breakSigal == 1:
                    continue
                thread = threading.Thread(target=self.manageConnection, args=(None, None, conn))
                thread.daemon = True
                thread.start()
            except:
                print("Error when running server")

    def on_close(self):
        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.logout()
            self.destroy()


class User:
    def __init__(self, name, IP, port):
        self.name = name
        self.IP_address = IP
        self.port = port
        self.connect = 0

    def setConnect(self):
        self.connect = 1

    def isConnect(self):
        return self.connect

    def getName(self):
        return self.name

    def getIP(self):
        return self.IP_address

    def getPort(self):
        return self.port


class Login(tk.Frame):
    def __init__(self, parent, controller):
        tk.Frame.__init__(self, parent)
        self.configure(bg="bisque2")

        label_title = tk.Label(self, text="\nLOG IN OR SIGN UP\n", fg='#20639b', bg="bisque2").grid(row=0, column=1)

        label_user = tk.Label(self, text="\tUSERNAME ", fg='#20639b', bg="bisque2", font='verdana 10 bold').grid(row=1,
                                                                                                                 column=0)
        label_pswd = tk.Label(self, text="\tPASSWORD ", fg='#20639b', bg="bisque2", font='verdana 10 bold').grid(row=2,
                                                                                                                 column=0)

        self.label_notice = tk.Label(self, text="", bg="bisque2", fg='red')
        self.entry_user = tk.Entry(self, width=30, bg='light yellow')
        self.entry_pswd = tk.Entry(self, width=30, bg='light yellow', show="*")

        button_log = tk.Button(self, text="LOG IN", bg="#20639b", fg='floral white',
                               command=lambda: controller.login(self))
        button_sign = tk.Button(self, text="SIGN UP", bg="#20639b", fg='floral white',
                                command=lambda: controller.signUP(self))

        button_log.grid(row=4, column=1)
        button_log.configure(width=10)
        button_sign.grid(row=5, column=1)
        button_sign.configure(width=10)
        self.label_notice.grid(row=3, column=1)
        self.entry_pswd.grid(row=2, column=1)
        self.entry_user.grid(row=1, column=1)


class StartPage(tk.Frame):
    def __init__(self, parent, appController):
        tk.Frame.__init__(self, parent)

        label_IP = tk.Label(self, text="IP Address")
        label_Port = tk.Label(self, text="Port Number")

        self.label_notice = tk.Label(self, text="", bg="bisque2")
        self.entry_IP = tk.Entry(self, width=20, bg="light yellow")
        self.entry_Port = tk.Entry(self, width=20, bg="light yellow")

        btn_confirm = tk.Button(self, text="Confirm", command=lambda: appController.connectClient(self))
        btn_confirm.configure(width=10)

        label_IP.pack()
        self.entry_IP.pack()
        label_Port.pack()
        self.entry_Port.pack()
        self.label_notice.pack()
        btn_confirm.pack()


class ChatRoom(tk.Tk):
    def __init__(self, controller, receive_pipe, sendSock, username):

        self.username = username
        self.receive_pipe = receive_pipe
        self.sendSock = sendSock
        # -----------------------------Change----------------------------------------------
        tk.Tk.__init__(self)
        # self.checkEndFile = 0

        BG_GRAY = "#ABB2B9"
        BG_COLOR = "#17202A"
        TEXT_COLOR = "#EAECEE"

        FONT = "TimesNewRoman"
        FONT_BOLD = "TimesNewRoman"

        lable1 = tk.Label(self, bg=BG_COLOR, fg=TEXT_COLOR, text=self.username, font=FONT_BOLD, pady=10, width=20,
                          height=1).grid(row=0, columnspan=3)

        self.txt = tk.Text(self, bg="Gray91", fg="Black", font=FONT, width=60)
        self.txt.grid(row=1, column=0, columnspan=3)

        self.e = tk.Entry(self, bg="GhostWhite", fg="Black", font=FONT, width=55)
        self.e.grid(row=2, column=0)

        self.protocol("WM_DELETE_WINDOW", self.on_closing)

        send = tk.Button(self, text="Send", font=FONT_BOLD, bg=BG_GRAY, command=self.inChatRoom)
        send.grid(row=2, column=1)
        choose = tk.Button(self, text="Choose", font=FONT_BOLD, bg=BG_GRAY, command=lambda: self.sendFile())
        choose.grid(row=2, column=2)

        receiver = threading.Thread(target=self.receiverWork, args=())
        receiver.daemon = False
        receiver.start()

    def on_closing(self):

        lock.acquire()
        for i in curConnectionList:
            if i.name == self.username:
                curConnectionList.remove(i)
        lock.release()

        if messagebox.askokcancel("Quit", "Do you want to quit?"):
            self.destroy()

        self.receive_pipe.close()
        self.sendSock.close()

    # --------------------------------------------------------------------------------

    def inChatRoom(self):
        sender = threading.Thread(target=self.senderWork, args=())
        sender.daemon = False
        sender.start()

    def sendFile(self):
        try:
            root = tk.Tk()
            root.withdraw()
            path = filedialog.askopenfilename()
            fileName = self.takeFileName(path)
            file = open(path, "rb")
            # Send FILE_CODE to let target know send file section start
            self.sendSock.sendall(FILE_SEND_CODE.encode())
            # Receive response before countinue
            response = self.sendSock.recv(BUFFER).decode()
            if response == "ok":
                # Send file name to let Target create file
                self.sendSock.send(fileName.encode())
                response = self.sendSock.recv(BUFFER).decode()
                if response == "ok":
                    # Send file data
                    for i in file:
                        self.sendSock.sendall(i)
                        self.sendSock.recv(BUFFER)
            file.close()
            # self.checkEndFile = 1
            self.sendSock.sendall("E@N@D".encode())
            self.txt.insert(END, "\n" + "You send file: " + path)
            # print("You send file: ", path)
        except:
            print("File transmission Error")

    def receiveFile(self):
        try:
            # Response to target
            self.receive_pipe.sendall("ok".encode())
            # take file_name to create new file
            file_name = self.receive_pipe.recv(BUFFER).decode()
            print(file_name)
            self.receive_pipe.sendall("ok".encode())
            if (file_name == "E@N@D"):
                file_name = self.receive_pipe.recv(BUFFER).decode()
            self.receive_pipe.sendall("ok".encode())
            f = open(file_name, "wb")
            condition = True
            while condition:
                data = self.receive_pipe.recv(BUFFER)
                self.receive_pipe.sendall("123".encode())
                if str(data) == "b'E@N@D'":
                    condition = False
                    break
                f.write(data)
            f.close()
            self.txt.insert(END, "\n" + "Receive: " + file_name)
            # print("Receive: ", file_name)
        except:
            print("Failed")

    #   When click button Send create new thread then send message
    def senderWork(self):
        try:
            messSending = self.e.get()
            send = "You: " + messSending
            self.txt.insert(END, "\n" + send)
            self.e.delete(0, END)

            self.sendSock.sendall(messSending.encode())
            self.sendSock.recv(BUFFER)
        except:
            self.sendSock.close()
            print("Error from sender")

    # Thread always listen to client message
    def receiverWork(self):
        try:
            while True:
                messReceiving = self.receive_pipe.recv(BUFFER).decode()
                self.receive_pipe.sendall("ok".encode())
                if (messReceiving == FILE_SEND_CODE):
                    self.receiveFile()
                else:
                    self.txt.insert(END, "\n" + "Your friend : " + messReceiving)
        except:
            self.receive_pipe.close()
            print("Error frome receiver")

    def takeFileName(self, string):
        length = len(string) - 1
        a = ""
        while (string[length] != '/'):
            a = string[length] + a
            length -= 1
        return a


class curUser:
    def __init__(self, name, status):
        self.name = name
        self.status = status

    def resetStatus(self):
        self.status = 0


class HomePage(tk.Frame):
    def __init__(self, parent, controller):
        global friendList
        tk.Frame.__init__(self, parent)
        self.configure(bg="CadetBlue1")
        label_title = tk.Label(self, text="\n ACTIVE ACCOUNT ON CHAT APP\n", fg='#20639b', bg="CadetBlue1").pack()
        self.conent = tk.Frame(self)
        self.data = tk.Listbox(self.conent, height=10,
                               width=40,
                               bg='floral white',
                               activestyle='dotbox',
                               font="Helvetica",
                               fg='#20639b')
        lock2.acquire()
        for i in range(len(friendList)):
            self.data.insert(i, friendList[i].name)
        lock2.release()
        # button_log = tk.Button(self,text="REFRESH",bg="#20639b",fg='floral white',command=lambda: self.Update_Friend(controller))
        button_back = tk.Button(self, text="LOG OUT", bg="#20639b", fg='floral white',
                                command=lambda: controller.logout())
        button_chat = tk.Button(self, text="START CHAT", bg="#20639b", fg='floral white',
                                command=lambda: controller.connectClient(self,
                                                                         self.data.get(self.data.curselection()[0])))
        button_back.pack(side=BOTTOM)
        button_back.configure(width=10)
        # button_log.pack(side= BOTTOM)
        # button_log.configure(width=10)
        button_chat.pack(side=BOTTOM)
        button_chat.configure(width=10)

        self.conent.pack_configure()
        self.scroll = tk.Scrollbar(self.conent)
        self.scroll.pack(side=RIGHT, fill=BOTH)
        self.data.config(yscrollcommand=self.scroll.set)

        self.scroll.config(command=self.data.yview)
        self.data.pack()

    def selected_item(self):
        for i in self.data.curselection():
            print(self.data.get(i))

    def Update_Friend(self, controller):
        global friendList
        lock2.acquire()
        self.data.delete(0, len(friendList))
        lock2.release()
        newSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            newSocket.connect((Central_server_IP, 12000))
            newSocket.sendall("Refresh".encode())
            newSocket.recv(BUFFER)
            newSocket.sendall(controller.myUsername.encode())

            dataBack = recvListOfTupple(newSocket)
            lock2.acquire()
            friendList = []
            for i in dataBack:
                friendList.append(User(i[0], i[1], i[2]))

            for i in range(len(friendList)):
                self.data.insert(i, friendList[i].name)
            lock2.release()
        except:
            print("Error to refresh")
        newSocket.close()


# --------------------------------main---------------------------
# ---------------Online--------------------
onlineSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
onlineSocket.bind((MY_IP_ADDRESS, MY_PORT))
onlineSocket.listen()

recvSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
recvSocket.bind((MY_IP_ADDRESS, MY_PORT + 1))
recvSocket.listen()

recvMessageFromServerSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
recvMessageFromServerSocket.bind((MY_IP_ADDRESS, MY_PORT + 2))
recvMessageFromServerSocket.listen()

app = App()
app.mainloop()
time.sleep(1)

# -----------------------------------------
