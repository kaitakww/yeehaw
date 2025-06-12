import msvcrt
import os
import sys
import time
import datetime
import threading
import socket
import cryptography.hazmat
import cryptography.hazmat.primitives
import cryptography.hazmat.primitives.ciphers
import keyboard
import curses
import signal
import cryptography
from cryptography.hazmat.primitives import padding
# source_firstname = ""
# source_lastname = ""
# username = ""
# address = ""


class EmptyFileError(Exception):
    pass


# def getinfo():
#     print(
#         f"First name: {firstname}\nLast name: {lastname}\nUsername: {username}\nAddress: {address}")
def signal_handler(signum, frame):
    clear_screen()
    print("Force exit received. Terminating the program...")
    os._exit()
    sys.exit(),


signal.signal(signal.SIGINT, signal_handler)


class user:
    def __init__(self, firstname, lastname, username, address):
        self.firstname = firstname
        self.lastname = lastname
        self.username = username
        self.address = address

    def __str__(self):
        return f"First name: {self.firstname}\nLast name: {self.lastname}\nUsername: {self.username}\nAddress: {self.address}"


class message(user):
    def __init__(self, timestamp, sentfrom, sentto, content):
        self.sentfrom = sentfrom
        self.timestamp = timestamp
        self.sentto = sentto
        self.content = content

    def __str__(self):
        return f"{self.timestamp} - {self.sentfrom} to {self.sentto}: {self.content}"

    def message_display_format(self):
        return f"{self.sentfrom}: {self.content}\n"


def clear_screen():
    os.system('cls')


def first_time_login():
    clear_screen()
    try:
        a = open("Final Project/credentials.txt", "r")
        if len(a.readlines()) == 0:
            raise EmptyFileError("No credentials found.")
    except:
        print("This is your first time logging in.")
        while True:
            temp = input(
                f"Do you like to create a new account? (y = create new account, n = exit): ")
            clear_screen()
            if temp == "y":
                firstname = input("Enter your first name: ")
                lastname = input("Enter your last name: ")
                username = input("Enter your username: ")
                address = input("Enter your address as 'ip:port': ")
                clear_screen()
                print("Account created successfully.")
                time.sleep(1)
                break
            elif temp == "n":
                clear_screen()
                print("Exiting...")
                sys.exit()
            else:
                print("Invalid input. Please enter 'y' or 'n'.")
        try:
            os.mkdir("Final Project")
        except:
            pass
        finally:
            try:
                a = open("Final Project/credentials.txt", "x")
            except:
                a = open("Final Project/credentials.txt", "w")
            a.write(f" {firstname}~{lastname}~{username}~{address}")
            a.close()
            print("Credentials updated successfully.")
            time.sleep(1)


def login():
    clear_screen()
    a = open("Final Project/credentials.txt", "r")
    creds = a.readlines()
    for i in range(len(creds)):
        creds[i] = creds[i].split("~")
    print("Accounts available:")
    for i in creds:
        print(
            f"{creds.index(i) + 1}.\nFirst name: {i[0]}\nLast name: {i[1]}\nUsername: {i[2]}\nAddress: {i[3]}")
    while True:
        try:
            b = int(input(
                "Enter the number of the account you want to log in to (or '0' to return to the login menu): "))
        except ValueError:
            clear_screen()
            print("Invalid input. Please enter a number corresponding to an account.")
            msvcrt.getch()
            print("Accounts available:")
            for i in creds:
                print(
                    f"{creds.index(i) + 1}.\nFirst name: {i[0]}\nLast name: {i[1]}\nUsername: {i[2]}\nAddress: {i[3]}")
            continue
        if b in range(1, len(creds) + 1):
            print(f"Logging in account number {b}...")
            a.close()
            return user(creds[b - 1][0], creds[b - 1][1], creds[b - 1][2], creds[b - 1][3])
        elif b == 0:
            clear_screen()
            return
        else:
            print("Invalid input. Please enter a number corresponding to an account.")


def edit_credentials():
    clear_screen()
    try:
        a = open("Final Project/credentials.txt", "r")
    except:
        print("Error: No credentials file found.")
        return
    creds = a.readlines()
    for i in range(len(creds)):
        creds[i] = creds[i].split("~")
    print("Accounts available:")
    for i in creds:
        print(
            f"{creds.index(i) + 1}.\nFirst name: {i[0]}\nLast name: {i[1]}\nUsername: {i[2]}\nAddress: {i[3]}")
    while True:
        try:
            b = int(input("Enter the number of the account you want to edit: "))
        except:
            print("Invalid input. Please enter a number corresponding to an account.")
            msvcrt.getch()
            print("Accounts available:")
            for i in creds:
                print(
                    f"{creds.index(i) + 1}.\nFirst name: {i[0]}\nLast name: {i[1]}\nUsername: {i[2]}\nAddress: {i[3]}")
            continue
        if b in range(1, len(creds) + 1):
            c = int(input(
                f"What do you like to change in account number {b}?\n1. First name\n2. Last name\n3. Username\n4. Address"))
            match c:
                case 1:
                    creds[b - 1][0] = input("Enter the new first name: ")
                    clear_screen()

                    print("First name changed successfully.")
                    break
                case 2:
                    creds[b - 1][1] = input("Enter the new last name: ")
                    clear_screen()
                    print("Last name changed successfully.")
                    break
                case 3:
                    creds[b - 1][2] = input("Enter the new username: ")
                    clear_screen()
                    print("Username changed successfully.")
                    break
                case 4:
                    creds[b - 1][3] = input("Enter the new address: ")
                    clear_screen()
                    print("Address changed successfully.")
                    break
                case _:
                    clear_screen()
                    print(
                        "Invalid input. Please enter a number corresponding to an option.")
        else:
            print("Invalid input. Please enter a number corresponding to an account.")
    a = open("Final Project/credentials.txt", "w")
    for i in creds:
        a.write(f"{i[0]}~{i[1]}~{i[2]}~{i[3]}")
    a.close()
    print("Credentials updated successfully.\nPress any key to get back to the login menu.")
    msvcrt.getch()


def add_account():
    while True:
        a = open("Final Project/credentials.txt", "a")
        clear_screen()
        firstname = input("Enter your first name: ")
        if not firstname:
            print("First name cannot be empty.")
            msvcrt.getch()
            continue
        lastname = input("Enter your last name: ")
        if not lastname:
            print("Last name cannot be empty.")
            msvcrt.getch()
            continue
        username = input("Enter your username: ")
        if not username:
            print("Username cannot be empty.")
            msvcrt.getch()
            continue
        address = input("Enter your address as 'ip:port': ")
        if not address:
            print("Address cannot be empty.")
            msvcrt.getch()
            continue
        a.write(f"{firstname}~{lastname}~{username}~{address}")
        a.close()
        print("Account added successfully.")
        print("Credentials updated successfully.\nPress any key to get back to the login menu.")
        msvcrt.getch()


def remove_account():
    a = open("Final Project/credentials.txt", "r")
    creds = a.readlines()
    a.close()
    for i in range(len(creds)):
        creds[i] = creds[i].split("~")
    clear_screen()
    print("Accounts available:")
    for i in creds:
        print(
            f"{creds.index(i) + 1}.\nFirst name: {i[0]}\nLast name: {i[1]}\nUsername: {i[2]}\nAddress: {i[3]}")
    while True:
        b = int(input("Enter the number of the account you want to remove: "))
        if b in range(1, len(creds) + 1):
            creds.pop(b - 1)
            print("Account removed successfully.")
            break
        else:
            clear_screen()
            print("Invalid input. Please enter a number corresponding to an account.")
            print("Accounts available:")
            for i in creds:
                print(
                    f"{creds.index(i) + 1}.\nFirst name: {i[0]}\nLast name: {i[1]}\nUsername: {i[2]}\nAddress: {i[3]}")
    a = open("Final Project/credentials.txt", "w")
    for i in creds:
        a.write(f"{i[0]}~{i[1]}~{i[2]}~{i[3]}")
    a.close()
    clear_screen()
    print("Credentials updated successfully.\nPress any key to get back to the login menu.")
    msvcrt.getch()


def view_accounts():
    clear_screen()
    a = open("Final Project/credentials.txt", "r")
    creds = a.readlines()
    a.close()
    for i in range(len(creds)):
        creds[i] = creds[i].split("~")
    print("Accounts available:")
    for i in creds:
        print(
            f"{creds.index(i) + 1}.\nFirst name: {i[0]}\nLast name: {i[1]}\nUsername: {i[2]}\nAddress: {i[3]}")
    print("Press any key to get back to the login menu.")
    msvcrt.getch()


def loading(prompt, afterprompt, toggle):
    sys.stdout.write('\033[?25l')
    sys.stdout.flush()
    while not toggle.is_set():
        for i in range(3):
            if toggle.is_set():
                break
            sys.stdout.write(f"\r{prompt} {'.' * (i+1)}{' ' * (3 - i)}")
            sys.stdout.flush()
            time.sleep(0.5)
    sys.stdout.write('\r' + ' ' * (len(prompt) + 4) + '\r')
    sys.stdout.flush()
    sys.stdout.write(f"\r{afterprompt}")
    sys.stdout.flush()
    sys.stdout.write('\033[?25h')
    sys.stdout.flush()


def enable_keepalive(sock):
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    if hasattr(socket, 'TCP_KEEPIDLE'):
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 30)
    if hasattr(socket, 'TCP_KEEPINTVL'):
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
    if hasattr(socket, 'TCP_KEEPCNT'):
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)


def socket_session(current_user, login_success):
    mysocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    enable_keepalive(mysocket)
    mysocket.bind((f'{current_user.address.split(":")[0]}', int(
        current_user.address.split(":")[1])))
    time.sleep(1)
    login_success.set()
    return mysocket


def awaiting_connection(current_user, mysocket, newsocket, addr, connection_success):
    mysocket.listen()
    newsocket, addr = mysocket.accept()
    connection_success.set()
    return newsocket, addr

# def receive_messages(mysocket, newsocket, addr, current_user, recipient, message_list):
#     while True:
#         try:
#             newsocket, addr = mysocket.accept()
#             msg = newsocket.recv(1024).decode()
#         except ConnectionResetError:
#             print(f"Connection closed with user {recipient.username}.")
#             login_success.clear()
#             reconnect_loading = threading.Thread(target=loading, args=(
#                 f"Waiting for the user {recipient.username} to reconnect", "", login_success))
#             reconnect_loading.start()
#             try:
#                 mysocket.settimeout(120)
#                 newsocket, addr = mysocket.accept()
#                 mysocket.settimeout(None)
#                 login_success.set()
#                 print(
#                     f"Reconnected to {recipient.username} at {addr[0]}:{addr[1]}")
#             except socket.timeout:
#                 login_success.set()
#                 print(
#                     f"Could not reconnect to {recipient.username} within 120 seconds. Terminating session.")
#                 sys.exit()
#             msvcrt.getch()
#             sys.exit()
#         messages_list.append(
#             message(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), recipient.username, current_user.username, msg))
#         new_message.set()


# def send_messages(mysocket, current_user, recipient):
#     while True:
#         sys.stdout.write(f"{current_user.username}:\n    ")
#         sys.stdout.flush()
#         msg = sys.stdin.readline().strip()
#         if msg == 'exit':
#             filename = f"{datetime.now().strftime("%Y-%m-%d-%H-%M")}.txt"
#             try:
#                 messages_file = open(filename, "x")
#             except:
#                 messages_file = open(filename, "w")
#             messages_file.write(
#                 f"Messaging history of {current_user.username} and {recipient.username}:\n\n")
#             for i in messages_list:
#                 messages_file.write(f"{str(i)}\n\n")
#             messages_file.close()
#             print(f"Messages saved to '{filename}'.")
#             print("Press any key to close the connection and exit the program.")
#             msvcrt.getch()
#             sys.exit()
#         elif msg == 'save':
#             filename = f"{datetime.datetime.now().strftime('%Y-%m-%d-%H-%M')}.txt"
#             try:
#                 messages_file = open(filename, "x")
#             except:
#                 messages_file = open(filename, "w")
#             for i in messages_list:
#                 messages_file.write(f"{str(i)}\n\n")
#             messages_file.close()
#             print(f"Messages saved to '{filename}'.")
#         elif msg == 'getinfo':
#             print(
#                 f"Name: {recipient.firstname} {recipient.lastname}\nUsername: {recipient.username}\nAddress: {recipient.address.split(':')[0]}\nPort: {recipient.address.split(':')[1]}")
#         else:
#             mysocket.sendall(msg.encode())
#             messages_list.append(
#                 message(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), current_user, recipient, msg))
#             new_message.set()


# def show_messages(messages_list, recipient, addr):
#     clear_screen()
#     sys.stdout.write(
#         f"Connected to {recipient.username} at {addr[0]}:{addr[1]}\n\n")
#     sys.stdout.flush()
#     for i in messages_list:
#         sys.stdout.write(f"i.message_display_format()\n\n")
#     sys.stdout.write(f"{current_user.username}: {text}\n")
#     sys.stdout.flush()


# def main_messenger(current_user):
#     while True:
#         clear_screen()

#         if new_message.is_set():
#             show_messages()
#             new_message.clear()
#         # else:
#         #     sys.stdout.write(f"\r{current_user.username}:\n    ")
#         #     sys.stdout.flush()


messages_list = [message("2023-10-01 12:00:00", "bomba",
                         "itsgrooving", "Hello, this is a test message.")]
newsocket = None
addr = None
current_user_key = None
recipient_key = None
new_message = threading.Event()
new_message.clear()
disconnected = threading.Event()
disconnected.clear()
interrupt = threading.Event()
interrupt.clear()

first_time_login()
while True:
    clear_screen()
    temp = input(
        f"Select an option:\n1. Login\n2. View accounts\n3. Edit an account's credentials\n4. Add a new account\n5. Remove an account\n6. Exit\n")
    try:
        int(temp)
    except:
        clear_screen()
        print("Invalid input. Please enter a number from 1 to 6.\nPress any key to get back to the login menu.")
        msvcrt.getch()
        continue
    if (temp == ''):
        continue
    # elif (temp == False):
    #     print("Invalid input. Please enter a number from 1 to 6.\nPress any key to get back to the login menu.")
    #     msvcrt.getch()
    #     continue
    else:
        match int(temp):
            case 1:
                current_user = login()
                if current_user is None:
                    continue
                else:
                    break
            case 2:
                view_accounts()
            case 3:
                edit_credentials()
            case 4:
                add_account()
            case 5:
                remove_account()
            case 6:
                print("Exiting...")
                sys.exit()
            case _:
                clear_screen()
                print(
                    "Invalid input. Please enter a number from 1 to 6.\nPress any key to get back to the login menu.")
                msvcrt.getch()
# print(user)
clear_screen()
login_success = threading.Event()
login_loading = threading.Thread(target=loading, args=(
    f"Logging in as {current_user.username}", f"Logged in as {current_user.username}", login_success))
connect = threading.Thread(
    target=socket_session, args=(current_user, login_success))
login_loading.start()
connect.start()
connect.join()
login_loading.join()
login_success.clear()
mysocket = socket_session(current_user, login_success)
while True:
    temp = int(input(
        f"\nSelect an option:\n1. Connect to another user\n2. Listen for connections\n3. Exit\n"))
    match temp:
        case 1:
            ip = input(
                "Enter the IP address of the user you want to connect to: ")
            port = int(
                input("Enter the port of the user you want to connect to: "))
            login_success.clear()
            connection_loading = threading.Thread(target=loading, args=(
                f"Connecting to {ip}:{port}", f"Connected to {ip}:{port}", login_success))
            connection_loading.start()
            try:
                mysocket.connect((ip, port))
            except (ConnectionRefusedError, OSError):
                print(
                    f"Could not connect to {ip}:{port}. Please check the address and port.")
                msvcrt.getch()
                clear_screen()
                continue
            login_success.set()
            connection_loading.join()
            active_socket = mysocket
            current_user_key = os.urandom(32)
            active_socket.sendall(
                f"{current_user.firstname}~{current_user.lastname}~{current_user.username}~{current_user.address}~{current_user_key.hex()}".encode())
            recipient_temp = active_socket.recv(1024).decode().split("~")
            recipient = user(
                recipient_temp[0], recipient_temp[1], recipient_temp[2], recipient_temp[3])
            recipient_key = bytes.fromhex(recipient_temp[4])
            break
        case 2:
            login_success.clear()
            # newsocket, addr = None, None
            listening_loading = threading.Thread(target=loading, args=(
                f"Listening on {current_user.address}", f"New connection detected.", login_success))
            listening_loading.start()
            newsocket, addr = awaiting_connection(current_user, mysocket,
                                                  newsocket, addr, login_success)
            listening_loading.join()
            active_socket = newsocket
            current_user_key = os.urandom(32)
            recipient_temp = active_socket.recv(1024).decode().split("~")
            recipient = user(
                recipient_temp[0], recipient_temp[1], recipient_temp[2], recipient_temp[3])
            recipient_key = bytes.fromhex(recipient_temp[4])
            print(recipient.address.split(":"))

            # mysocket.connect((str(recipient.address.split(
            #     ":")[0]), int(recipient.address.split(":")[1])))
            active_socket.sendall(
                f"{current_user.firstname}~{current_user.lastname}~{current_user.username}~{current_user.address}~{current_user_key.hex()}".encode())

            login_success.set()
            break
        case 3:
            print("Exiting...")
            sys.exit()
        case _:
            clear_screen()
            print(
                "Invalid input. Please enter a number from 1 to 3.\nPress any key to return to connection menu.")
            msvcrt.getch()
            continue

clear_screen()


def encrypt_message(msg, key):
    try:
        iv = os.urandom(16)
        padder = padding.PKCS7(128).padder()
        padded = padder.update(msg.encode()) + padder.finalize()
        cipher = cryptography.hazmat.primitives.ciphers.Cipher(
            cryptography.hazmat.primitives.ciphers.algorithms.AES(key),
            cryptography.hazmat.primitives.ciphers.modes.CBC(iv)
        )
        encryptor = cipher.encryptor()
        ciphermsg = encryptor.update(padded) + encryptor.finalize()
        return iv + ciphermsg
    except Exception as e:
        curses.endwin()
        clear_screen()
        print(
            f"An error occurred while encrypting the message: {e}\nFor security concerns, the session will be terminated.\nPress any key to exit.")
        msvcrt.getch()
        os._exit()
        return None


def decrypt_message(ciphertext, key):
    try:
        iv = ciphertext[:16]
        ciphermsg = ciphertext[16:]
        cipher = cryptography.hazmat.primitives.ciphers.Cipher(cryptography.hazmat.primitives.ciphers.algorithms.AES(key),
                                                               cryptography.hazmat.primitives.ciphers.modes.CBC(iv))
        decryptor = cipher.decryptor()
        padded = decryptor.update(ciphermsg) + decryptor.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        msg = unpadder.update(padded) + unpadder.finalize()
        return msg.decode()
    except Exception as e:
        curses.endwin()
        clear_screen()
        print(
            f"An error occurred while decrypting the message: {e}\nFor security concerns, the session will be terminated.\nPress any key to exit.")
        msvcrt.getch()
        os._exit()
        return None


def send_message(active_socket, current_user, recipient, msg):
    try:
        text = f"{current_user.username}~{recipient.username}~{msg}"
        ciphertext = encrypt_message(text, current_user_key)
        active_socket.sendall(ciphertext)
    except (ConnectionResetError, OSError):
        disconnected.set()
        try:
            active_socket.close()
        except:
            pass


def get_message(active_socket, current_user, recipient, messages_list, new_message):
    while True:
        try:
            msg = active_socket.recv(1024)
            if not msg:
                disconnected.set()
                try:
                    active_socket.close()
                except:
                    pass
                break
            msg = decrypt_message(msg, recipient_key)
            msg_parts = msg.split("~")
            # if msg_parts[0] == recipient.username and msg_parts[1] == current_user.username:
            messages_list.append(message(datetime.datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"), msg_parts[0], msg_parts[1], msg_parts[2]))
            new_message.set()
        except (ConnectionResetError, OSError):
            disconnected.set()
            try:
                active_socket.close()
            except:
                pass
            break
        except Exception as e:
            print(f"An error occurred while receiving messages: {e}")
            continue


def reconnect(current_user, recipient, messages_list, new_message):
    global active_socket
    curses.endwin()
    reconnected_event = threading.Event()
    reconnected_event.clear()
    print(f"Connection closed with {recipient.username}.")
    reconnect_loading = threading.Thread(target=loading, args=(
        f"Waiting for the user {recipient.username} to reconnect", f"User {recipient.username} has successfully reconnected.", reconnected_event))
    reconnect_loading.start()
    timer = time.time()
    newsocket = None
    while time.time() - timer < 120:
        try:
            try:
                active_socket.close()
            except:
                pass
            newsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            enable_keepalive(newsocket)
            newsocket.settimeout(5)
            newsocket.connect((recipient.address.split(
                ":")[0], int(recipient.address.split(":")[1])))
            newsocket.sendall(
                f"{current_user.firstname}~{current_user.lastname}~{current_user.username}~{current_user.address}".encode())
            recipient_temp = newsocket.recv(1024).decode().split("~")
            recipient = user(
                recipient_temp[0], recipient_temp[1], recipient_temp[2], recipient_temp[3])
            reconnected_event.set()
            break
        except Exception as e:
            try:
                newsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                enable_keepalive(newsocket)
                newsocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                newsocket.bind((current_user.address.split(
                    ":")[0], int(current_user.address.split(":")[1])))
                newsocket.listen()
                newsocket.settimeout(5)
                conn, addr = newsocket.accept()
                recipient_temp = conn.recv(1024).decode().split("~")
                recipient = user(
                    recipient_temp[0], recipient_temp[1], recipient_temp[2], recipient_temp[3])
                conn.sendall(
                    f"{current_user.firstname}~{current_user.lastname}~{current_user.username}~{current_user.address}".encode())
                newsocket = conn
                reconnected_event.set()
                break
            except Exception:
                time.sleep(1)
    reconnect_loading.join()
    if reconnected_event.is_set():
        active_socket = newsocket
        disconnected.clear()
        curses.wrapper(main)
    else:
        print("Could not reconnect to the user within 120 seconds. Session terminated.\nPress any key to exit the program.")
        msvcrt.getch()
        reconnected_event.set()
        sys.exit()


def main(myscreen):

    global active_socket, current_user, recipient, messages_list, new_message
    receive_messages_thread = threading.Thread(
        target=get_message,
        args=(active_socket, current_user,
              recipient, messages_list, new_message),
        daemon=True
    )
    receive_messages_thread.start()
    myscreen.clear()
    myscreen.refresh()
    curses.echo()
    curses.start_color()
    curses.init_pair(1, curses.COLOR_WHITE, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_WHITE, curses.COLOR_BLACK)
    h, w = myscreen.getmaxyx()
    display_h = h - 3
    display_w = w
    display_y = 0
    display_x = 0
    input_h = 3
    input_w = w
    input_y = h - input_h
    input_x = 0
    display_window = curses.newwin(
        display_h, display_w, display_y, display_x)
    input_window = curses.newwin(input_h, input_w, input_y, input_x)
    input_window.box()
    display_window.scrollok(True)
    input_window.addstr(
        0, 2, f"{current_user.username}: ", curses.color_pair(1))

    def show_messages():
        display_window.clear()
        line = 0
        for i in range(len(messages_list)):
            # line += 1
            if i+1 >= display_h - 1:
                display_window.scroll()
                display_window.addstr(display_h - 2, 1,
                                      messages_list[i].message_display_format(), curses.color_pair(1))
            else:
                display_window.addstr(i+1, 1,
                                      messages_list[i].message_display_format(), curses.color_pair(1))
        display_window.refresh()
    show_messages()

    def draw_new_message():
        while True:
            if new_message.is_set():
                show_messages()
                new_message.clear()

    draw_thread = threading.Thread(target=draw_new_message)
    draw_thread.start()
    while True:
        if disconnected.is_set():
            curses.endwin()
            return
        input_window.clear()
        input_window.box()
        input_window.addstr(
            1, 1, f"{current_user.username}: ", curses.color_pair(1))
        input_text_x = 1 + len(f"{current_user.username}: ")
        input_text_y = 1
        input_window.addstr(input_text_y, input_text_x,
                            "Enter your message", curses.color_pair(2) | curses.A_DIM)
        input_window.refresh()
        input_window.move(input_text_y, input_text_x)
        max_input = input_w - input_text_x - 1
        user_input_temp = input_window.getstr(max_input)
        user_input = user_input_temp.decode('utf-8').strip()
        if user_input:
            messages_list.append(
                message(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), current_user.username, recipient.username, user_input))
            if user_input.lower() == 'exit':
                filename = f"{datetime.datetime.now().strftime('%Y-%m-%d-%H-%M')}.txt"
                try:
                    messages_file = open(filename, "x")
                except:
                    messages_file = open(filename, "w")
                messages_file.write(
                    f"Messaging history of {current_user.username} and {recipient.username}:\n\n")
                for i in messages_list:
                    messages_file.write(f"{str(i)}\n\n")
                messages_file.close()
                display_window.clear()
                input_window.clear()
                display_window.refresh()
                input_window.refresh()
                curses.endwin()
                clear_screen()
                print(f"Connection closed with {recipient.username}.")
                print(f"Messages saved to '{filename}'.")
                print("Press any key to exit the program.")
                msvcrt.getch()
                sys.exit()
            elif user_input.lower() == 'save':
                filename = f"{datetime.datetime.now().strftime('%Y-%m-%d-%H-%M')}.txt"
                try:
                    messages_file = open(filename, "x")
                except:
                    messages_file = open(filename, "w")
                for i in messages_list:
                    messages_file.write(f"{str(i)}\n\n")
                messages_file.close()
                clear_screen()
                print(f"Messages saved to '{filename}'.")
                messages_list.append(
                    message(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), current_user.username, recipient.username, f"{current_user.username} created a message log at {filename}"))
                send_message(active_socket, current_user,
                             recipient, f"{current_user.username} created a message log at {filename}")
                show_messages()
            elif user_input.lower() == 'getinfo':
                messages_list.append(
                    message(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), current_user.username, recipient.username, f"{current_user.username} Requested recipient's info."))
                send_message(active_socket, current_user,
                             recipient, f"{current_user.username} Requested recipient's info.")
                #  Name: {recipient.firstname} {recipient.lastname}\n Username: {recipient.username}\n Address: {recipient.address.split(':')[0]}\n Port: {recipient.address.split(':')[1]}" + '\033[4B')
                messages_list.append(message(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), current_user.username, recipient.username,
                                             f"Name: {recipient.firstname} {recipient.lastname}"))
                send_message(active_socket, current_user,
                             recipient, f"Name: {recipient.firstname} {recipient.lastname}")
                messages_list.append(message(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), current_user.username, recipient.username,
                                             f"Username: {recipient.username}"))
                send_message(active_socket, current_user,
                             recipient, f"Username: {recipient.username}")
                messages_list.append(message(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), current_user.username, recipient.username,
                                             f"Address: {recipient.address.split(':')[0]}"))
                send_message(active_socket, current_user,
                             recipient, f"Address: {recipient.address.split(':')[0]}")
                messages_list.append(message(datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"), current_user.username, recipient.username,
                                             f"Port: {recipient.address.split(':')[1]}"))
                send_message(active_socket, current_user,
                             recipient, f"Port: {recipient.address.split(':')[1]}")
                show_messages()
            else:
                send_message(active_socket, current_user,
                             recipient, user_input)
                show_messages()
                continue


curses.wrapper(main)
while True:
    if disconnected.is_set():
        reconnect(current_user, recipient, messages_list, new_message)
        disconnected.clear()
# clear_screen()
# main_messenger_thread = threading.Thread(
#     target=main_messenger, args=(current_user,))
# receive_messages_thread = threading.Thread(
#     target=receive_messages, args=(mysocket, newsocket, addr, current_user, recipient, new_message))
# send_messages_thread = threading.Thread(target=send_messages, args=(
#     mysocket, current_user, recipient))
# show_messages_thread = threading.Thread(
#     target=show_messages, args=(messages_list, recipient, addr))
# main_messenger_thread.start()
# receive_messages_thread.start()
# send_messages_thread.start()
# show_messages_thread.start()
