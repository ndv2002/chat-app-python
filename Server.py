import socket
import mysql.connector as SQL
import threading


# Change this IP to your IP if need
# -----------------------Get ip if use Window -------------------------------
def wlan_ip():
    import subprocess
    result = subprocess.run('ipconfig', stdout=subprocess.PIPE, text=True).stdout.lower()
    scan = 0
    for i in result.split('\n'):
        if 'wireless' in i: scan = 1
        if scan:
            if 'ipv4' in i: return i.split(':')[1].strip()


# ----------------------------------------------------------------

# MY_IP_ADDRESS = wlan_ip()
MY_IP_ADDRESS = "172.20.10.13"
# Dont change PORT
MY_PORT = 12000
BUFFER = 1024

onlineSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
onlineSocket.bind(("", MY_PORT))
onlineList = ()
onlineSocket.listen()
lock = threading.Lock()
print("serving....")

mydb = SQL.connect(
    host="localhost",
    user="root",
    password="",
    database="db_client")
mycursor = mydb.cursor()


def sendListOfTuple(lst, conn):
    try:
        lenghtList = len(lst)
        lengthTup = len(lst[0])
        conn.sendall(str(lenghtList).encode())
        response = conn.recv(BUFFER).decode()
        if response == "OK":
            conn.sendall(str(lengthTup).encode())
            response = conn.recv(BUFFER).decode()
            if response == "OK":
                for i in range(lenghtList):
                    for j in range(lengthTup):
                        conn.sendall(str(lst[i][j]).encode())
                        conn.recv(BUFFER)
                    response = conn.recv(BUFFER).decode()
                    if response != "OK":
                        break
    except:
        print("Error sending tupple")
    conn.close()


def connectSession(conn: socket, mycursor):
    global onlineList
    try:
        Request = conn.recv(BUFFER).decode()
        conn.sendall("OK".encode())

        if Request == "Login":
            # Receive information from client
            user = conn.recv(BUFFER).decode()
            conn.sendall("OK".encode())  # Dont care
            pswd = conn.recv(BUFFER).decode()
            ip = conn.getpeername()[0]
            # ----------------------Check----------------------------
            # TODO
            sql = "SELECT password FROM info_clients where username= %s"
            mycursor.execute(sql, (user,))
            myresult = mycursor.fetchall()

            result = 0
            if len(myresult) == 0:
                print("Ten tai khoan chua ton tai")
                # missing UI1
            else:
                if pswd != myresult[0][0]:
                    print("Mat khau khong dung")
                # missing UI2
                else:
                    sql = "SELECT status FROM info_clients where username = %s"
                    mycursor.execute(sql, (user,))
                    st = mycursor.fetchall()
                    if st[0][0] == 'online':
                        conn.sendall("Active".encode())
                        return
                    else:
                        sql = "update info_clients set status='online', ip=%s where username = %s"
                        mycursor.execute(sql, (ip, user))
                        mydb.commit()
                        print(mydb)
                        result = 1

                        mycursor = mydb.cursor()
                        sql = "SELECT username, ip, port FROM info_clients where status= 'online' and not username = %s"
                        mycursor.execute(sql, (user,))
                        myresult = mycursor.fetchall()

            # --------------------------------------------------------
            if result == 0:
                conn.sendall("Error".encode())
            else:
                conn.sendall("Success".encode())

                # Put your result in data = [ ("Duy", "IP", "Post"), ...]
                # TODO
                data = myresult
                # Send data to client
                sendListOfTuple(data, conn)

                lock.acquire()
                onlineList = ()
                print("login sth1")
                sql = "SELECT username, ip, port FROM info_clients where status= 'online'"
                mycursor.execute(sql)
                print("login sth2")
                onlineList = mycursor.fetchall()
                print(onlineList)

                for i in onlineList:
                    if i[0] != user:

                        try:
                            newSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                            onlineFriend = onlineList
                            print(i[1])
                            newSocket.connect((i[1], 65002))
                            for t in range(len(onlineFriend)):
                                if onlineFriend[t][1] == newSocket.getpeername()[0]:
                                    onlineFriend = onlineFriend[:t] + onlineFriend[t + 1:]
                                    print("ssssss", newSocket.getpeername()[0])

                            print(onlineFriend)
                            sendListOfTuple(onlineFriend, newSocket)
                            print("succcess")
                            newSocket.close()
                        except:
                            print("Error when update FriendList for client")
                            newSocket.close()
                lock.release()

        elif Request == "SignUp":
            # Receive information from client
            user = conn.recv(BUFFER).decode()
            conn.sendall("OK".encode())  # Dont care
            pswd = conn.recv(BUFFER).decode()
            conn.sendall("OK".encode())  # Dont care
            clientIP = conn.recv(BUFFER).decode()
            # ----------------------Check----------------------------
            # TODO
            hostname = socket.gethostname()
            portNum = 65000

            result = 0
            # check valid of username, password
            if (not (user.isalnum() and pswd.isalnum())):
                print("Ten tai khoan hoac mat khau khong duoc chua ki tu dac biet hoac dau cach !")
                # missing UI
            else:
                sql = "SELECT password FROM info_clients where username= %s"
                mycursor.execute(sql, (user,))
                myresult = mycursor.fetchall()
                if len(myresult) == 0:
                    # Insert account into database
                    status = 'online'
                    sql = "insert into info_clients (username,password,ip,port,status) values(%s,%s,%s,%s,%s)"
                    mycursor.execute(sql, (user, pswd, clientIP, portNum, status))

                    # Update status account
                    sql = "update info_clients set status='online' where username= %s"
                    mycursor.execute(sql, (user,))

                    # click button dang ky
                    mydb.commit()
                    result = 1

                    # list friend online
                    sql = "SELECT username, ip, port FROM info_clients where status= 'online' and not username = %s"
                    mycursor.execute(sql, (user,))
                    myresult = mycursor.fetchall()
                    # print("Dang ky thanh cong")
                    # go into chat page
                else:
                    print("Tai khoan da duoc dang ky")
                    # missing UI

            # --------------------------------------------------------
            if result == 0:
                conn.sendall("Error".encode())
            else:
                conn.sendall("Success".encode())

                # Put your result in data = [ ("Duy", "IP", "Post"), ...]
                # TODO
                data = myresult
                # Send data to client

                sendListOfTuple(data, conn)
                lock.acquire()
                onlineList = ()
                print("sth1")
                sql = "SELECT username, ip, port FROM info_clients where status= 'online'"
                mycursor.execute(sql)
                print("sth2")
                onlineList = mycursor.fetchall()
                print(onlineList)

                for i in onlineList:
                    try:
                        newSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                        onlineFriend = onlineList
                        print(i[1])
                        newSocket.connect((i[1], 65002))
                        for t in range(len(onlineList)):
                            if onlineList[t][1] == newSocket.getpeername()[0]:
                                onlineFriend = onlineList[:t] + onlineList[t + 1:]

                        sendListOfTuple(onlineFriend, newSocket)
                        newSocket.close()
                    except:
                        print("Error when update FriendList for client")
                lock.release()

        elif Request == "Logout":
            # Receive information from client
            user = conn.recv(BUFFER).decode()

            conn.sendall("OK".encode())  # Dont care
            # Change user status in DataBase
            # TODO
            sql = "update info_clients set status='offline' where username= %s"
            mycursor.execute(sql, (user,))
            mydb.commit()
            # TODO: query IP of online user from database
            lock.acquire()
            onlineList = ()
            print("sth1")
            sql = "SELECT username, ip, port FROM info_clients where status= 'online' and not username = %s"
            mycursor.execute(sql, (user,))
            print("sth2")
            onlineList = mycursor.fetchall()
            print(onlineList)

            for i in onlineList:
                try:
                    newSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    onlineFriend = onlineList
                    print(i[1])
                    newSocket.connect((i[1], 65002))
                    for t in range(len(onlineFriend)):
                        if onlineFriend[t][1] == newSocket.getpeername()[0]:
                            onlineFriend = onlineFriend[:t] + onlineFriend[t + 1:]

                    sendListOfTuple(onlineFriend, newSocket)
                    newSocket.close()
                except:
                    print("Error when update FriendList for client")
            lock.release()

        elif Request == "Refresh":
            # Put your result in data = [ ("Duy", "IP", "Port"), ...]
            # TODO
            user = conn.recv(BUFFER).decode()
            sql = "SELECT username, ip, port FROM info_clients where status= 'online' and not username=%s"
            mycursor.execute(sql, (user,))
            myresult = mycursor.fetchall()
            data = myresult
            sendListOfTuple(data, conn)

    except:
        print("Session Error")


while True:
    conn, addr = onlineSocket.accept()
    thread = threading.Thread(target=connectSession, args=(conn, mycursor,))
    thread.daemon = True
    thread.start()


