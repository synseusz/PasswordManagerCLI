import sys
import os
import sqlite3
import bcrypt
from cryptography.fernet import Fernet
import getpass
import string
from random import randint,choice


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

def get_password(user_PW_choice):
    query = "SELECT SERVICE,PASSWD FROM PASSKEYS WHERE ID = ?;"
    cursor.execute(query, [user_PW_choice])

    results = cursor.fetchall()

    for service,password in results:
        print("\nThe password for %s is:\n"%(service))

        # Get crypto key for service        
        decrypt_key = get_key(service)

        # Decrypt encrypted passwd 
        f2 = Fernet(decrypt_key)
        decrypted_passw = f2.decrypt(password)
        decoded_password = decrypted_passw.decode()

        print("#"*20)
        print(decoded_password)
        print("#"*20)

        print("\nWhat would you like to do next?")
        print("1. Delete")
        print("2. Back to Main Menu")
        option = input(":")

        if option == "1":
            delete_password(service, password)
            main_menu()
        elif option == "2":
            main_menu()

def delete_password(service, password):
    delete_query = "DELETE FROM PASSKEYS WHERE PASSWD = ?;"
    try:
        cursor.execute(delete_query, [password])
        conn.commit()

        # REMOVE KEY FILE IF EXISTS
        remove_key(service)

        print("Password has been deleted!")

    except:
        print("Unable to delete password")

def generate_passwd():
    # Generating passwd
    special_chars = ("!" + "?" + "@" + "&") * 2
    char_list = string.ascii_letters + string.digits + str(special_chars)

    x = ""
    generated_passwd = x.join(choice(char_list) for x in range(randint(10, 16)))
    return generated_passwd

def unique_service_check(service):
    s = service
    is_unique = ""

    sql_cmd = "SELECT SERVICE FROM PASSKEYS;"
    cursor.execute(sql_cmd)

    results = cursor.fetchall()
    number_of_passwords_stored = len(results)

    if number_of_passwords_stored == 0:
        is_unique = True
        return is_unique

    else:
        for services in results:
            x = services[0]
            
            if x == s:
                is_unique = False
                break
            elif x != s:
                is_unique = True
            else:
                print("is_unique value - ", str(is_unique))

    return is_unique


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
        store_password_view(password="none")
        
    elif input_ == "2":
        # Get password
        get_passwords_view()

    elif input_ == "3":
        # Generate passwd
        generate_password_view()

def store_password_view(password):
    service = input("\nName of the service: ")

    is_service_unique = unique_service_check(service)

    if len(service) > 0 and is_service_unique == True:
        if password == "none":
            password = input("Password: ")
        else:
            password = password
            if len(service) > 0:
                print("Generated password has been assigned to given service")
        try:
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
        except:
            print("Error while storing password!")

    elif is_service_unique == False:
        print("Password for given service already exists!")

        if password == "none":
            store_password_view(password="none")
        else:
            store_password_view(password=password)
        
    else:
        print("Please provide a name of the service first!")

        if password == "none":
            store_password_view(password="none")
        else:
            store_password_view(password=password)
       

def get_passwords_view():
    query = "SELECT ID,SERVICE FROM PASSKEYS;"
    cursor.execute(query)

    results = cursor.fetchall()
    results_length = len(results)

    print("\nYou currently store passwords for %s service(s)"%(results_length))

    print("\n" + "#"*20)
    for service_id, service in results:
        print(service_id, ".", service)
    print("#"*20)


    print("\nWhich password would you like to see? (1-%s)"%(results_length))
    user_PW_choice = input(":")


    get_password(user_PW_choice)

def generate_password_view():
    print("\nYour generated password is:")

    generated_password = generate_passwd()

    print("\n" + "#"*20)
    print(generated_password)
    print("#"*20)
    print("length -", len(generated_password))


    print("\nWhat would you like to do next?")
    print("1. Reroll")
    print("2. Add to storage")
    print("3. Back to Main Menu")
    option = input(":")

    if option == "1":
        generate_password_view()
    elif option == "2":
        store_password_view(password=generated_password)
    elif option == "3":
        main_menu()

##########################################################

Access_check()



