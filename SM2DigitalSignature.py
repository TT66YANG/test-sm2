from hashlib import sha256
from random import randint

def get_hash256(data):
    data_hashed = sha256(str(data).encode("utf-8"))
    return data_hashed.hexdigest()

def initialize_curve():
    p = "8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3"
    a = "787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498"
    b = "63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A"
    G_x = "421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D"
    G_y = "0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2"
    n = "8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7"
    return p, a, b, G_x, G_y, n

def get_message(filename):
    file = open(filename, "r")
    message = file.read()
    print("message:\n" + message)
    message = bytes(message, encoding = "utf-8")
    file.close()
    print("change message to hex...")
    message = message.hex()
    return message

def get_user(username):
    print("user:\n" + username)
    username = bytes(username, encoding = "utf-8")
    print("change user to hex...")
    username = username.hex()
    return username

def generate_keys(p, a, b, n, G_x, G_y):
    p = int(p, 16)
    a = int(a, 16)
    b = int(b, 16)
    G_x = int(G_x, 16)
    G_y = int(G_y, 16)
    n = int(n, 16)
    while(1):
        d = randint(1, n - 2)
        P_x, P_y = multiply_point(d, p, a, G_x, G_y)
        if (P_y ** 2 % p) == ((P_x ** 3 + a * P_x + b) % p):
            d = "{:X}".format(d)
            P_x = "{:X}".format(P_x)
            P_y = "{:X}".format(P_y)
            return d, P_x, P_y
    

def multiply_point(k, p, a, x_1, y_1):
    k_bin = bin(k).replace("0b", "")
    x_2, y_2 = 0, 0
    for i in range(len(k_bin)):
        x_2, y_2 = add_point(p, a, x_2, y_2, x_2, y_2)
        if k_bin[i] == "1":
            x_2, y_2 = add_point(p, a, x_1, y_1, x_2, y_2)
    return x_2, y_2

def add_point(p, a, x_1, y_1, x_2, y_2):
    if ((x_1 == 0) & (y_1 == 0)):
        return x_2, y_2
    if ((x_2 == 0) & (y_2 == 0)):
        return x_1, y_1
    if (x_1 == x_2) & (y_1 == y_2):
        lamda = ((3 * x_1 ** 2 + a) % p * inverse_mod(2 * y_1, p)) % p
    else:
        lamda = ((y_2 - y_1) % p * inverse_mod(x_2 - x_1, p)) % p
    x_3 = (lamda ** 2 - x_1 - x_2) % p
    y_3 = (lamda * (x_1 - x_3) - y_1) % p
    return x_3, y_3

def inverse_mod(a, n):
    if a < 0:
        a = a % n
    x_1, x_2, x_3 = 1, 0, n
    y_1, y_2, y_3 = 0, 1, a
    while(1):
        if y_3 == 0:
            return -1
        elif y_3 == 1:
            return y_2
        else:
            k = x_3 // y_3
            t_1 = x_1 - k * y_1
            t_2 = x_2 - k * y_2
            t_3 = x_3 - k * y_3
            x_1, x_2, x_3 = y_1, y_2, y_3
            y_1, y_2, y_3 = t_1, t_2, t_3

def sign_message(message, Z, p, a, n, G_x, G_y, d):
    message_ = Z + message
    e = get_hash256(message_)
    e = int(e, 16)
    n = int(n, 16)
    p = int(p, 16)
    a = int(a, 16)
    G_x = int(G_x, 16)
    G_y = int(G_y, 16)
    d = int(d, 16)
    while(1):
        k = randint(1, n - 2)
        x_1, y_1 = multiply_point(k, p, a, G_x, G_y)
        r = (e + x_1) % n
        if(r == 0) | (r + k == n):
            continue
        s = (inverse_mod(1 + d, n) * (k - r * d) % n) % n
        if(s == 0):
            continue
        r = "{:X}".format(r)
        s = "{:X}".format(s)
        return r, s

def verify_signature(message, Z, r, s, p, a, n, G_x, G_y, P_x, P_y):
    r = int(r, 16)
    s = int(s, 16)
    p = int(p, 16)
    a = int(a, 16)
    n = int(n, 16)
    G_x = int(G_x, 16)
    G_y = int(G_y, 16)
    P_x = int(P_x, 16)
    P_y = int(P_y, 16)
    if (r < 1) | (r > n - 1):
        return False
    if (s < 1) | (s > n - 1):
        return False
    message_ = Z + message
    e = get_hash256(message_)
    e = int(e, 16)
    t = (r + s) % n
    if t == 0:
        return False
    temp1_x, temp1_y = multiply_point(s, p, a, G_x, G_y)
    temp2_x, temp2_y = multiply_point(t, p, a, P_x, P_y)
    x_1, y_1 = add_point(p, a, temp1_x, temp1_y, temp2_x, temp2_y)
    R = (e + x_1) % n
    if R == r:
        return True
    else:
        return False

print("\n")
print("**********************************************")
print("*   SM2 digital signature and verification   *")
print("**********************************************")
print("\n")
print("initialize the curve...")
p, a, b, G_x, G_y, n = initialize_curve()
print("p = ", p)
print("a = ", a)
print("b = ", b)
print("G_x = ", G_x)
print("G_y = ", G_y)
print("n = ", n)
print("\n")
print("generate keys...")
d, P_x, P_y = generate_keys(p, a, b, n, G_x, G_y)
print("P_x = ", P_x)
print("P_y = ", P_y)
print("d = ", d)
print("\n")
print("get the user who need to sign...")
user = get_user("cxl").upper()
print("the user in hex is:\n" + user)
print("hash user's identity...")
len_user = len(user) * 4
len_user_str = "{:04X}".format(len_user)
Z = get_hash256(len_user_str + user + a + b + G_x + G_y + P_x + P_y)
print("Z is:", Z)
print("\n")
print("get the message need to sign...")
message = get_message("message.txt").upper()
print("the message in hex is:\n" + message)
print("\n")
print("sign the message...")
r,s = sign_message(message, Z, p, a, n, G_x, G_y, d)
print("signature is over")
print("the signature is:")
print("r = ", r)
print("s = ", s)
print("\n")
print("sending signature...")
print("\n")
print("verify the signature...")
check = verify_signature(message, Z, r, s, p, a, n, G_x, G_y, P_x, P_y)
print("verification is over")
if check == True:
    print("signature verification success")
else:
    print("signature verification fail")
