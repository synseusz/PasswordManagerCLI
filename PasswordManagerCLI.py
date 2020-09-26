import sys
import os
import sqlite3
import bcrypt
from cryptography.fernet import Fernet
import getpass


print("\n"+"#"*39)
print("#   Welcome to Password Manager CLI   #")
print("#"*39)

# DB conn
try:
    conn = sqlite3.connect("password_manager.db")
except:
    print("Unable to create/connect the database")

cursor = conn.cursor()

# Master Passwd setup
try:
    conn.execute('''
    CREATE TABLE MasterPasswd (
        MP TEXT VARCHAR(100) NOT NULL
    );
    ''')
except:
    # table already exists
    pass

################# CRYPTOGRAPHY ####################

def generate_key(service):
    # Create keys directory
    filename = "keys/" + service + '.key'
    os.makedirs(os.path.dirname(filename), exist_ok=True)
    # Generating key and writing into the file
    key = Fernet.generate_key()
    file = open(filename, 'wb')
    file.write(key)
    file.close()
    return key

def get_key(service):
    file = open('keys/' + service + '.key', 'rb')
    decrypt_key = file.read()
    file.close()
    return decrypt_key

def remove_key(service):
    if os.path.exists("keys/" + service + ".key"):
        os.remove("keys/" + service + ".key")
    else:
        print("The key file for this password does not exist")

###################################################


def Access_check():
    query = "SELECT * FROM MasterPasswd"
    cursor.execute(query)

    results = cursor.fetchall()
    MP_quantity = len(results)

    if MP_quantity == 0:
        # MP setup
        MP_entry = getpass.getpass("""\nSetup your new Master Password
:""")

        add_MP_to_db(MP_entry)

    elif MP_quantity > 0:
        connect = getpass.getpass("""\nPlease enter your master password to gain access
:""")

        MASTER_PASSWORD_CHECK = MP_check(connect)

        if connect == "q":
            sys.exit()

        if MASTER_PASSWORD_CHECK == False:
            print("Sorry, that didn't match!")
            Access_check()
            
        elif MASTER_PASSWORD_CHECK:
            try:
                conn.execute("""CREATE TABLE PASSKEYS(
                ID INTEGER PRIMARY KEY,
                SERVICE TEXT VARCHAR(100) NOT NULL,
                PASSWD TEXT VARCHAR(100));""")
                print("\nYour safe has been created.\nWhat would you like to do next?")
            except:
                print("\nYou already have a safe.\nWhat would you like to do next?")

            # Main Menu call
            main_menu()


def add_MP_to_db(MP_entry):
    bMP = MP_entry.encode('utf-8')

    #passwd hashing
    MP_hashed = bcrypt.hashpw(bMP, bcrypt.gensalt())

    MPinsertQuery = "INSERT INTO MasterPasswd(MP) VALUES(?);"
    conn.execute(MPinsertQuery, [MP_hashed])
    conn.commit()

    Access_check()


def MP_check(input_MP):
    b_input_MP = input_MP.encode('utf-8')
    query = "SELECT * FROM MasterPasswd"
    cursor.execute(query)

    results = cursor.fetchall()

    for MP_hashed in results:
        MP_hashed = MP_hashed[0]

        MP_hash_check = bcrypt.checkpw(b_input_MP, MP_hashed)

        return MP_hash_check

####################### VIEWS ############################

def main_menu():
    print("\n" + "#"*20)
    print("1. Store password")
    print("2. Get password")
    print("3. Generate password\n")
    print("q = quit program")
    print("#"*20)

    input_ = input(":")

    if input_ == "q":
        sys.exit()

    elif input_ == "1":
        # Store passwd
        store_password_view()
        
    elif input_ == "2":
        # Get password
        get_services_view()

    elif input_ == "3":
        # Generate passwd
        pass

def store_password_view():
    service = input("\nName of the service: ")
    password = input("Password: ")

    # TODO - unique service check

    if len(service) > 0:
        # Generate crypto key for service
        crypto_key = generate_key(service)
        
        # Encode password
        encoded_passwd = password.encode('utf-8')

        # Encrypt password
        f = Fernet(crypto_key)
        encrypted_passwd = f.encrypt(encoded_passwd)

        command = "INSERT INTO PASSKEYS(SERVICE,PASSWD) VALUES(?,?);"
        cursor.execute(command, [service, encrypted_passwd])
        conn.commit()

        print("Password stored successfuly!")
        main_menu()

def get_services_view():
    query = "SELECT ID,SERVICE FROM PASSKEYS;"
    cursor.execute(query)

    results = cursor.fetchall()
    results_length = len(results)

    print("\nYou currently store passwords for %s service(s)"%(results_length))

    print("\n" + "#"*20)
    for service_id, service in results:
        print(service_id, ".", service)
    print("#"*20)


    print("\nWhich password would you like to see? (0-%s)"%(results_length))
    user_PW_choice = input(":")

##########################################################

Access_check()



