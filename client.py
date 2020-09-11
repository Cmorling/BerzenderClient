import asciiArt
import time
import datetime
import termcolor
import os
import json
import socket
import re
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import argparse


def handleArgs():
    parser = argparse.ArgumentParser(
        description='Berzender Client to connect to a server')
    parser.add_argument('-i', metavar='IP', type=str,
                        help='Ip of Berzender server')
    parser.add_argument('-p', metavar='Port', type=int,
                        help='Port of Berzender server')

    args = parser.parse_args()
    if not args.i or not args.p:
        parser.print_help()
        exit()
    return {
        'ip': args.i,
        'port': args.p
    }


def printAscciArt():
    os.system('clear')
    print(asciiArt.berzanLogo + termcolor.colored(asciiArt.appTitle, 'green'))
    time.sleep(1)


def readConfig():
    username = ''
    password = ''
    try:
        f = open('config.txt').readlines()
        username = re.split(r'username:', f[0][:-1])
        password = re.split(r'password:', f[1][:-1])
        if len(username) != 1:
            username = username[-1]
        else:
            username = ''
        if len(password) != 1:
            password = password[-1]
        else:
            password = ''
        f.close()

    except:
        pass
    return {
        'username': username.strip(),
        'password': password.strip()
    }


class ClientSocket():
    def __init__(self, ip, port):
        self._ip = ip
        self._port = port

    def _start(self):
        try:
            self._client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._client.connect((self._ip, self._port))
        except Exception as e:
            print(e)

    def _close(self):
        try:
            self._client.shutdown(socket.SHUT_RDWR)
        except:
            pass
        self._client.close()

    def send(self, p):
        try:
            self._start()
            data = json.dumps(p)
            response = None
            self._client.send(data.encode())
            response = self._client.recv(20480)
            response = json.loads(response.decode())
        except Exception as e:
            print(e)
        self._close()
        return response

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        print('exiting')
        self._client.shutdown(socket.SHUT_RDWR)
        self._client.close()
        if exc_info[0]:
            import traceback
            traceback.print_exception(*exc_info)

class ClientScope():
    def __init__(self, sock, username, password):
        self.currentFrame = None
        self._PreviousFrame = None
        self._socket = sock
        self._username = username
        self._password = password
        self._failedLogin = False

    def _optionInput(self, mess, start, end):
        choice = -1

        while choice < start or choice > end:
            choice = input('\n[{}-{}] '.format(start, end) +
                           termcolor.colored(mess, 'green'))
            try:
                choice = int(choice)
            except:
                break
        return choice

    def _page(self, title):
        os.system('clear')
        print(asciiArt.smallBerzanLogo + asciiArt.smallAppTitle)
        print(termcolor.colored('-'*10 + title + '-'*10, 'blue'))
        print('\n'*1)

    def loginMethod(self):
        self._page('LOGIN METHOD')
        print('[0] Login with existing account')
        print('[1] Create new account')

        choice = self._optionInput('Choose Option ', 0, 1)
        self.currentFrame = self.login if choice == 0 else self.createAccount
        self.currentFrame()
        return False

    def login(self):
        self._page('LOGIN')
        password = ''
        username = ''
        if self._username != '' and self._password != '' and not self._failedLogin:
            print(termcolor.colored(
                '[TRYING USERNAME AND PASSWORD IN CONFIG FILE]', 'green'))
            username = self._username
            password = self._password
            time.sleep(1)
        else:

            username = input('[Username] ')
            self._username = username.strip()
            if username or username == '':
                password = input('[Password] ')
        password = SHA256.new(data=password.strip().encode())
        p = {
            'head': 'login',
            'body': {
                'username': self._username,
                'password': password.hexdigest(),
            },
            'session': ''
        }
        response = self._socket.send(p)
        if response['code'] == '200':
            self._session = response['session']
            self.currentFrame = self.menu
        else:
            self._failedLogin = True
            print(termcolor.colored('[WRONG PASSWORD OR USERNAME]', 'red'))
            time.sleep(1)

    def createAccount(self):
        self._page('CREATE ACCOUNT')

        password = ''

        username = input('\r[Username] ')
        self._username = username.strip()
        if username or username == '':
            password = input('[Password] ')

        key = RSA.generate(2048)

        f = open('{}.pem'.format(self._username), 'wb')
        f.write(key.export_key('PEM'))
        f.close()
        pk = key.publickey().export_key()

        password = SHA256.new(data=password.strip().encode())

        p = {
            'head': 'createUser',
            'body': {
                'username': self._username,
                'password': password.hexdigest(),
                'publicKey': pk.decode(),
            },
            'session': ''
        }
        response = self._socket.send(p)
        print(response)
        if response['code'] == '200':
            self._session = response['session']
            self.currentFrame = self.menu

    def menu(self):
        self._page('MENU')
        print('[0] Send a Message')
        print('[1] Inbox')
        print('[2] Settings')
        choice = self._optionInput('Choose Option ', 0, 2)

        if choice == 0:
            self.currentFrame = self.sendMessage
        elif choice == 1:
            self.currentFrame = self.inbox
        elif choice == 2:
            self.currentFrame = self.settings

    def settings(self):
        self._page('SETTINGS')
        print('[0] Change Password')
        print('[1] Delete Account')
        choice = self._optionInput('Choose Option ', 0, 1)

        if choice == 0:
            self.currentFrame = self.changePassword
        elif choice == 1:
            self.currentFrame = self.deleteUser

    def changePassword(self):
        verified = False
        password = ''
        while not verified:
            self._page('CHANGE PASSWORD')
            newPass = input('[New Password] ')
            verifyPass = input('[Retype Password] ')
            if newPass == verifyPass:
                verified = True
                password = newPass
        password = SHA256.new(data=password.strip().encode())
        p = {
            'head': 'newPassword',
            'body': {
                'username': self._username,
                'newPassword': password.hexdigest(),
            },
            'session': self._session
        }
        response = self._socket.send(p)
        if response['code'] == '200':
            print(termcolor.colored('\n[SUCCESS]', 'green'))
            time.sleep(1)
            self.currentFrame = menu
        else:
            print(termcolor.colored('\n[SOMETHING WENT WORNG]', 'red'))
            time.sleep(1)

    def deleteUser(self):
        while True:
            self._page('DELETE ACCOUNT')
            check = input(
                '[y/n] Are you sure you want to delete your account? ')
            if check == 'y':
                p = {
                    'head': 'deleteUser',
                    'body': {
                            'username': self._username,
                    },
                    'session': self._session
                }
                response = self._socket.send(p)
                if response['code'] == '200':
                    print(termcolor.colored('\n[SUCCESS]', 'green'))
                    time.sleep(1)
                    self.currentFrame = login
                    self._username = ''
                    self._password = ''
                    self._session = ''
                    break
                else:
                    print(termcolor.colored('\n[SOMETHING WENT WORNG]', 'red'))
                    time.sleep(1)
                    self.currentFrame = self.menu
                    break
            if check == 'n':
                self.currentFrame = self.menu
                break

    def sendMessage(self):
        self._page('SEARCH FOR A USER')
        search = input('[SEARCH USER] ')
        p = {
            'head': 'searchUser',
            'body': {
                'searchTerm': search.strip(),
            },
        }
        response = self._socket.send(p)
        print(response)
        if response['code'] == '200':
            if not len(response['response']) or (len(response['response']) == 1 and response['response'][0][0] == self._username):
                print(self._username)
                print(len(response['response']) ==
                      1 and response['response'][0][0] == self._username)
                foo = input('\n[ENTER] No Users Found')
                return
            users = [[]]
            currentUserPage = 0
            for index, user in enumerate(response['response']):
                if user[0] == self._username:
                    continue
                if len(users[currentUserPage]) == 9:
                    currentUserPage += 1
                    users.append([])
                users[currentUserPage].append({
                    'username': user[0],
                    'id': user[1],
                })
            chosen = False
            currentUserPage = 0
            canForward = False
            canBackward = False
            while not chosen:
                canForward = currentUserPage < len(users) - 1
                canBackward = currentUserPage > 0
                self._page('SELECT A USER')
                for index, user in enumerate(users[currentUserPage]):
                    print('[' + termcolor.colored(index, 'yellow') +
                          '] {}'.format(user['username']))
                if len(users) > 1:
                    if canForward and canBackward:
                        print('[' + termcolor.colored('f/b', 'yellow') +
                              '] {}'.format('Forward or Back'))
                    elif canBackward:
                        print(
                            '[' + termcolor.colored('b', 'yellow') + '] {}'.format('Back'))
                    elif canForward:
                        print('[' + termcolor.colored('f', 'yellow') +
                              '] {}'.format('Forward'))

                choice = self._optionInput(
                    'Select a user ', 0, len(users[currentUserPage]) - 1)
                if choice == 'f' and canForward:
                    currentUserPage += 1
                    continue
                if choice == 'b' and canBackward:
                    currentUserPage -= 1
                    continue
                try:
                    chosen = users[currentUserPage][choice]
                except:
                    print('[SELECT A VALID NUMBER]')

            self._page('CRAFT A MESSAGE')
            message = input(
                '[' + termcolor.colored('Message to {}'.format(chosen['username']), 'yellow') + '] ')
            publicKeyPayload = {
                'head': 'getPublicKey',
                'body': {
                    'username': chosen['username'],
                },
                'session': ''
            }
            publicKey = self._socket.send(publicKeyPayload)
            key = RSA.importKey(publicKey['response'][0][0].encode())
            cipher = PKCS1_OAEP.new(key)
            ciphertext = cipher.encrypt(message.strip().encode())
            p = {
                'head': 'sendMessage',
                'body': {
                    'message': base64.b64encode(ciphertext).decode(),
                    'recipitentId': chosen['id'],
                    'username': self._username,
                    'date': datetime.datetime.now().strftime("%b-%d-%Y %H:%M:%S"),
                },
                'session': self._session
            }
            response = self._socket.send(p)
            if response['code'] == '200':
                print('[SUCCESS]')
            else:
                print('[' + termcolor.colored('{}'.format(response['code']),
                                              'yellow') + ']' + response['message'])

    def inbox(self):
        self._page('INBOX')
        p = {
            'head': 'getMessages',
            'body': {
                'username': self._username.strip(),
            },
            'session': self._session
        }

        response = self._socket.send(p)
        if response['code'] == '200':
            senders = []
            for message in response['response']:
                if len(senders) == 0:
                    senders.append({
                        'user': message[1],
                        'messages': [{
                            'content': message[3],
                            'date': message[5],
                        }],
                    })
                else:
                    for sender in senders:
                        if message[1] == sender['user']:
                            sender['messages'].append({
                                'content': message[3],
                                'date': message[5],
                            })
                        elif sender == senders[-1]:
                            senders.append({
                                'user': message[1],
                                'messages': [{
                                    'content': message[3],
                                    'date': message[5],
                                }],
                            })
            for index, sender in enumerate(senders):
                print('[{}] {}'.format(index, sender['user']) + termcolor.colored(
                    ' [{} Message(s)]'.format(len(sender['messages'])), 'green'))
            print('[b] Back')
            choice = self._optionInput('Select a Sender ', 0, len(senders) - 1)
            if choice == 'b':
                self.currentFrame(menu)
                return
            self.messagesFromSender(senders[choice])
        if response['code'] == '400' or response['code'] == '401':
            print('[Error] ' + response['message'])

    def messagesFromSender(self, sender):
        p = {
            'head': 'deleteMesseges',
            'body': {
                    'sender': sender['user'],
                    'recipitent': self._username,
            },
            'session': self._session
        }
        self._socket.send(p)
        self._page('MESSAGES FROM {}'.format(sender['user'].upper()))
        for message in sender['messages']:
            try:
                key = RSA.importKey(
                    open('{}.pem'.format(self._username)).read())
                cipher = PKCS1_OAEP.new(key)
                decryptedMessage = cipher.decrypt(
                    base64.b64decode(message['content'])).decode()

                print('[' + termcolor.colored(message['date'],
                                              'yellow') + '] {}'.format(decryptedMessage))
            except Exception() as e:
                print(e)
        foo = input('\n[Enter]')

    def __enter__(self):
        self.currentFrame = self.loginMethod
        return self

    def __exit__(self, *exc_info):
        if exc_info[0]:
            import traceback
            traceback.print_exception(*exc_info)


if __name__ == '__main__':
    a = handleArgs()
    printAscciArt()
    config = readConfig()
    with ClientSocket(a['ip'], a['port']) as cSocket:
        with ClientScope(cSocket, config['username'], config['password']) as cScope:
            while True:
                cScope.currentFrame()
