import sys
import sqlite3
import bcrypt

print("#"*35)
print("# Welcome to Password Manager CLI #")
print("#"*35)

# DB conn
try:
    conn = sqlite3.connect("password_manager.db")
    print("success")
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

###################################################


def Access_check():
    query = "SELECT * FROM MasterPasswd"
    cursor.execute(query)

    results = cursor.fetchall()
    MP_quantity = len(results)

    if MP_quantity == 0:
        # MP setup
        MP_entry = input("""\nSetup your new Master Password
--> """)

        add_MP_to_db(MP_entry)

    elif MP_quantity > 0:
        connect = input("""\nPlease enter your master password to connect
--> """)

        MASTER_PASSWORD_CHECK = MP_check(connect)

        if connect == "q":
            sys.exit()

        if MASTER_PASSWORD_CHECK == False:
            print("Sorry, that didn't match!")
            Access_check()
            
        if MASTER_PASSWORD_CHECK:
            try:
                conn.execute("""CREATE TABLE PASSKEYS(
                SERVICE TEXT VARCHAR(100) NOT NULL,
                PASSWD TEXT VARCHAR(100));""")
                print("\nYour safe has been created.\nWhat would you like to do next?")
            except:
                print("\nYou already have a safe.\nWhat would you like to do next?")

            while True:
                print("\n" + "#"*45)
                print("Please choose one of the following options:\n")
                print("1. Store password")
                print("2. Get password")
                print("3. Generate password\n")
                print("q = quit program")
                print("#"*45)

                input_ = input("--> ")

                if input_ == "q":
                    break
                if input_ == "1":
                    # Store passwd
                    pass
                if input_ == "2":
                    print(connect)
                if input_ == "3":
                    # Generate passwd
                    pass


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

###################################################

Access_check()



