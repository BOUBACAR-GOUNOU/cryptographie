####################################################################################################
##################################### HILL  #########################################################


import numpy as np

# calcule l'inverse d'une matrice modulo 26
def matrix_mod_inv(matrix, modulus):
    det = int(np.round(np.linalg.det(matrix)))
    det_inv = pow(det, -1, modulus)
    matrix_modulus_inv = det_inv * np.round(det * np.linalg.inv(matrix)).astype(int) % modulus
    return matrix_modulus_inv

def encrypt_hill(plaintext, matrix):
    """Encrypts a plaintext using a Hill cipher with a given matrix."""
    n = len(matrix)
    plaintext = plaintext.lower().replace(" ", "")
    if(len(plaintext) % 2 != 0):
        plaintext += "a" * (n - (len(plaintext) % n))
    ciphertext = ""
    # la fonction itère sur le texte clair par blocs de la taille de la matrice,
    for i in range(0, len(plaintext), n):
        # convertit chaque bloc en une matrice de nombres représentant les caractères
        block = plaintext[i:i + n]
        # convertit chaque bloc en une matrice de nombres représentant les caractères ASCII de chaque lettre
        block_nums = [ord(char) - 97 for char in block]
        block_nums = np.array(block_nums).reshape(-1, 1)
        # effectue la multiplication matricielle entre la matrice de clé et la matrice de blocs de texte clair
        cipher_nums = np.dot(matrix, block_nums) % 26
        # convertit les nombres en caractères ASCII pour obtenir le bloc de texte chiffré correspondant. Enfin, la fonction retourne le texte chiffré.
        cipher_block = "".join([chr(num + 97) for num in cipher_nums.flatten().tolist()])
        ciphertext += cipher_block
    return ciphertext

def decrypt_hill(ciphertext, matrix):
    """Decrypts a ciphertext using a Hill cipher with a given matrix."""
    n = len(matrix)
    matrix_inv = matrix_mod_inv(matrix, 26)
    plaintext = ""
    for i in range(0, len(ciphertext), n):
        block = ciphertext[i:i + n]
        block_nums = [ord(char) - 97 for char in block]
        block_nums = np.array(block_nums).reshape(-1, 1)
        plain_nums = np.dot(matrix_inv, block_nums) % 26
        plain_block = "".join([chr(num + 97) for num in plain_nums.flatten().tolist()])
        plaintext += plain_block
    return plaintext

def get_matrix():
    """Gets a matrix input from the user."""
    while True: #Pour la valider de la matrice
        try:
            matrix_str = input("Entrer la matrice (Exemple: 2 5 17 1 pour une matrice 2 * 2 ):\n")

            matrix_vals = [int(val) for val in matrix_str.split()]
            matrix_size = int(np.sqrt(len(matrix_vals)))
            #créer une matrice à partir de la liste
            matrix = np.array(matrix_vals).reshape(matrix_size, matrix_size)
            if np.linalg.det(matrix) == 0:
                print("Erreur: La matrice est singulier.")
                continue
            matrix_mod_26 = matrix % 26
            matrix_mod_inv_26 = matrix_mod_inv(matrix_mod_26, 26)
            if not np.allclose(np.dot(matrix_mod_26, matrix_mod_inv_26) % 26, np.eye(matrix_size)):
                print("Erreur: La matrice n'est pas inversible modulo 26.")
                continue
            return matrix_mod_26
        except ValueError:
            print("Erreur: input incorrect.")


def encrypt_file(input_file, output_file, matrix):
    with open(input_file, 'r') as f:
        message = f.read()
    encrypted_text = encrypt_hill(message, matrix)
    with open(output_file, 'w') as f:
        f.write(encrypted_text)

    print("Fichier chiffré générer avec sucess")


# Définition de la fonction pour déchiffrer un fichier avec la matrice de clé
def decrypt_file(input_file, output_file, matrix):
    with open(input_file, 'r') as f:
        encrypted_text = f.read()
    decrypted_text = decrypt_hill(encrypted_text, matrix)
    with open(output_file, 'w') as f:
        f.write(decrypted_text)
    print("Fichier déchiffré avec success")


def main():
    """Runs the Hill cipher program."""
    while True:
        print("\n======== HILL =========== ")
        print("\nSelectionner une option:")
        print("1. Chiffrage")
        print("2. Déchiffrage")
        print("3. Quitter")
        choice = input("> ")
        if choice == "1":
            # plaintext = input("Entrer le texte claire:\n").lower()
            matrix = get_matrix()
            # ciphertext = encrypt_hill(plaintext, matrix)
            # print("Texte chiffré :", ciphertext)
            fichier_name = input("Entrer le nom du fichier à chiffrer avec son extension (Exemple: message.txt) :\n")
            sorti_name = input("Entrer le nom du fichier de sortir avec son extension (Exemple: message.txt) :\n")
            encrypt_file(fichier_name, sorti_name, matrix)
        elif choice == "2":
            # ciphertext = input("Entrer le texte chiffré :\n").lower()
            matrix = get_matrix()
            try:
                fichier_name = input("Entrer le nom du fichier chiffré avec son extension (Exemple: message.txt) :\n")
                sorti_name = input("Entrer le nom du fichier de sortir avec son extension (Exemple: message.txt) :\n")
                decrypt_file(fichier_name, sorti_name, matrix)

                # print("Texte déchiffré :", plaintext)
            except ValueError:
                print("Erreur: La matrice n'est pas inversible modulo 26.")
        elif choice == "3":
            break
        else:
            print("Erreur: Choix invalide. ")

if __name__ == "__main__":
    main()







# ####################################################################################################
# ##################################### RSA #########################################################
# from Crypto.PublicKey import RSA
# from Crypto.Util.number import isPrime
# from Crypto.Cipher import PKCS1_OAEP
# import math, binascii
#
#
# def Generate_key_1(p, q):
#     n = p * q
#     euler_n = (p - 1) * (q - 1)
#     e = 0
#     for i in range(2, euler_n):
#         if math.gcd(i, euler_n) == 1:
#             e = i
#             break
#     d = pow(e, -1, euler_n)
#     return ((n, e), (n, d))
#
#
# def encrypt(message, cle):
#     n, e = cle
#     encrypt_message = [pow(ord(c), e, n) for c in message]
#     return encrypt_message
#
#
# def decrypt(message, cle):
#     n, d = cle
#     decrypt_message = [chr(pow(c, d, n)) for c in message]
#     return (''.join(decrypt_message))
#
#
# print("Génération des clés en utilisant RSA")
# print("1- Défini les valeurs de p et q")
# print("2- Défini la taille de la clé pour la génération")
# choice = int(input("Entrez votre choix : "))
# match choice:
#     case 1:
#         while True:
#             p = int(input("Entrez p : "))
#             q = int(input("Entrez q : "))
#             if isPrime(p) == False or isPrime(q) == False:
#                 print("p et q doit être des nombres premiers")
#             else:
#                 break
#         public_key = Generate_key_1(p, q)[0]
#         private_key = Generate_key_1(p, q)[1]
#         print("La clé publique est : ", public_key[0], " , ", public_key[1])
#         print("La clé privée est : ", private_key[0], " , ", private_key[1])
#         response = "O"
#         response = input("Voulez-vous tester cette paire de clés (O/N) :")
#         while response == "O":
#             message = input("Entrer votre message à chiffrer : ")
#             print("Le message chiffré est : ", encrypt(message, public_key))
#             message_encrypt = encrypt(message, public_key)
#             print("Le message déchiffré est : ", decrypt(message_encrypt, private_key))
#             response = input("Voulez-vous continuez : O/N ")
#     case 2:
#         length = int(input("Entrer la taille de la clé : "))
#         key = RSA.generate(length)
#         f = open('mykey.pem', 'wb')
#         f.write(key.public_key().export_key('PEM'))
#         f.close()
#         # print("La clé publique est : ", key.public_key().export_key())
#         # print("La clé privée est : ", key.export_key())
#         response = input("Voulez-vous tester cette paire de clés (O/N) :")
#         while response == "O":
#             message = input("Entrer votre message à chiffrer : ")
#             message_bytes = message.encode("utf-8")
#             public_key = key.public_key()
#             encryptor = PKCS1_OAEP.new(public_key)
#             encrypted = encryptor.encrypt(message_bytes)
#             print("Le message chiffré est : ", binascii.hexlify(encrypted))
#             decryptor = PKCS1_OAEP.new(key)
#             decrypted = decryptor.decrypt(encrypted)
#             print("Le message déchiffré est : ", decrypted)
#             response = input("Voulez-vous continuez : O/N ")
#     case _:
#         print("Vous devez rentrer un choix valide")



##########################################################################################################################
##################################### CHIFFREMENT CESARE & AUTRE #########################################################

#
# def cesare(letter, decalage):
#     if letter.islower():
#         val_position = ord('a')
#         if letter.isalpha():
#             return chr((ord(letter) - val_position + decalage) % 26 + val_position)
#         else:
#             return letter + "  "
#     else:
#         val_position = ord('A')
#         transformation = (ord(letter) - val_position + decalage) % 26 + val_position
#         return chr(transformation)
#
#
# def cryptage(text, decalage):
#     return ''.join([cesare(lettre, decalage) for lettre in text])
#
#
# def decriptage(text, decalge):
#     return ''.join([cesare(lettre, -1 * decalage) for lettre in text])
#
#
# choix = int(input("Entrer 1 pour le chiffrement de message ou 2 pour le dechiffrément : \n"))
#
# if (choix == 1):
#
#     message_claire = input("Entrer le message a crypté : ")
#     decalage = int(input("Entrer le decalage  : "))
#     print("Message cypté est : " + cryptage(message_claire, decalage))
#
# elif (choix == 2):
#     message_crypte = input("Entrer le message à decrypter : ")
#     decalage = int(input("Entrer le decalage  : "))
#     print("Message déchiffré est : " + decriptage(message_crypte, decalage))

###################################################################################################
##################################### BEZOUT  #########################################################


# au + bv = PGCD(a, b)
# il suffit de remonter les calcules, en exprimant le pgcd en fonction des autres nombres.

# def coef_bezout(a, b):
#     u, v, s, t = 1, 0, 0, 1  # s et t sont utilisés pour stocker les anciennes valeurs de u et v
#
#     while b != 0:    #Exemple sur 120 et 40
#         q = a // b    # 120//40 = 3
#         a, b = b, a % b # a = 40 et b = 0
#         u, s = s, u - q * s # u = 0 et s = 1 - 3 * 0
#         v, t = t, v - q * t #  v  = 1 et t = -3
#
#     return u, v, a
#
#
# if __name__ == "__main__":
#     a = int(input("Entrez la valeur de a : "))
#     b = int(input("Entrez la valeur de b : "))
#
#     u, v, pgcd = coef_bezout(a, b)
#
#     print("Pour a =", a, "et b =", b, ":")
#     print("u =", u)
#     print("v =", v)
#     print("pgcd =", pgcd)

#####################################################################################################
############################### CRIBLE DE ERASTHOSTHENE #############################################


""" def Supprimer_multiples(i, tableau):
  for x in tableau:
    if x > i and x % i == 0:
      tableau.remove(x)

def Crible(n):
  tableau = [i for i in range(2, n)]
  for i in tableau:
    Supprimer_multiples(i, tableau)
  return tableau

tableau = Crible(int(input("Entrez un nombre pour avoir les nombres prémiers: ")))
print(tableau)
 """
