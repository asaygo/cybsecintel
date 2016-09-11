#! python
###############################################
#   Windows Forensic Artefacts Extractor      #
#   Author: malwrforensics                    #
#   Conact: malwr at malwrforensics dot com   #
###############################################
import sys
import re
MIN_LEN = 5

GET_FILE_NAME       = 1
GET_FILE_PATH       = 1
GET_IP              = 1
GET_REG_KEY         = 1
GET_URL             = 1
GET_EMAIL           = 1

lFileName           = []
lIpAddress          = []
lRegKey             = []
lFilePath           = []
lUrl                = []
lEmail              = []

def extract_file_names(buffer):
    print "[+] Extract file names"
    r = re.compile(b'(\w+\.\w{2,5})\W')
    for match in r.finditer(buffer):
        if len(match.group(1)) >= MIN_LEN:
            if match.group(1) not in lFileName:
                lFileName.append(match.group(1))

def extract_ip_addresses(buffer):
    print "[+] Extract IP addresses"
    r = re.compile(b'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
    for match in r.finditer(buffer):
        if len(match.group(1)) >= MIN_LEN:
            if match.group(1) not in lIpAddress:
                lIpAddress.append(match.group(1))

def extract_registry_keys(buffer):
    print "[+] Extract registry keys"
    r = re.compile(b'(\w+\\\\[\w\\\\]+)\W')
    for match in r.finditer(buffer):
        if len(match.group(1)) >= MIN_LEN:
            if match.group(1) not in lRegKey:
                lRegKey.append(match.group(1))

def extract_file_paths(buffer):
    print "[+] Extract file paths"
    r = re.compile(b'([a-zA-Z]:\\\\[\w\\\\]+)\W')
    for match in r.finditer(buffer):
        if len(match.group(1)) >= MIN_LEN:
            if match.group(1) not in lFilePath:
                lFilePath.append(match.group(1))

def extract_urls(buffer):
    print "[+] Extract urls"
    r = re.compile(b'([a-zA-Z]{3,5}\:\/\/[\w\/\.\-\~\%\&\#\;]+)')
    for match in r.finditer(buffer):
        if len(match.group(1)) >= MIN_LEN:
            if match.group(1) not in lUrl:
                lUrl.append(match.group(1))

def extract_emails(buffer):
    print "[+] Extract emails"
    r = re.compile(b'([\w\.!#$%&*+-/=?^_{|}~\(\)]@[\w\.\[\]]+)')
    for match in r.finditer(buffer):
        if len(match.group(1)) >= MIN_LEN:
            if match.group(1) not in lEmail:
                lEmail.append(match.group(1))


def write_lists():
    if GET_FILE_NAME:
        print "[+] Write file names"
        with open("log_filenames.log.txt", "w") as f:
            for elem in lFileName:
                f.write(elem + "\r\n")

    if GET_IP:
        print "[+] Write IPs"
        with open("log_ips.log.txt", "w") as f:
            for elem in lIpAddress:
                f.write(elem + "\r\n")

    if GET_REG_KEY:
        print "[+] Write reg keys"
        with open("log_regkeys.log.txt", "w") as f:
            for elem in lRegKey:
                f.write(elem + "\r\n")

    if GET_FILE_PATH:
        print "[+] Write file paths"
        with open("log_paths.log.txt", "w") as f:
            for elem in lFilePath:
                f.write(elem + "\r\n")

    if GET_URL:
        print "[+] Write urls"
        with open("log_urls.log.txt", "w") as f:
            for elem in lUrl:
                f.write(elem + "\r\n")

    if GET_EMAIL:
        print "[+] Write email"
        with open("log_emails.log.txt", "w") as f:
            for elem in lEmail:
                f.write(elem + "\r\n")

def extract_from_file(filename):
    print "[+] Reading file " + filename
    with open(filename, mode='rb') as f:
        buffer = f.read()

    if GET_FILE_NAME:
        extract_file_names(buffer)
    if GET_IP:
        extract_ip_addresses(buffer)
    if GET_REG_KEY:
        extract_registry_keys(buffer)
    if GET_FILE_PATH:
        extract_file_paths(buffer)
    if GET_URL:
        extract_urls(buffer)
    if GET_EMAIL:
        extract_emails(buffer)

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print "Usage: program [filename]"
        sys.exit(0)
    else:
        extract_from_file(sys.argv[1])
        write_lists()
