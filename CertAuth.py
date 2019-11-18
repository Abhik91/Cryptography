#####################################################################################
# Assignment to implement Certificate Authentication                                # 
# Course - CSE 539: Applied Cryptography                                            #
# Project Number - 5                                                                #
# Project Description - Digital certificates are electronic documents that are used #
#                       to identify an individual, company, server, or other entity #
#                       while associating the identity with a public key. Digital   #
#                       certificates can be essential to security. The 	            #
#						implementation of digital certifications assists in the     #
#						problem of impersonation as it is privacy-based which will  #
#						allow the private data to be protected and prevents those   #
#						without access from viewing. The purpose of this project is #
#						to challenge students to write a program that interacts with#
#						given certificates.                                         #
# Author - Abhik Dey (1216907460)                                                   #
#          Abhilasha Mandal ()                                                      #
#####################################################################################

from OpenSSL import crypto
from Crypto.Util import asn1
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Util.asn1 import DerSequence, DerObject
import Crypto.Hash.SHA
import sys


def read_certificates(backup_file,root_cert_file,subject_cert_file,password):
	#####################################################################################
    #   read_certificates -> The function reads the content of the certificate files:   #
    #						a. subject.crt 												#		
    #						b. root.crt 											    #
    #						c. cert_bckup.p12 											#
	#   Parameters:																		#
	#   a.  	backup_file -> path of cert_bckup.p12 									#
	#   b. 	root_cert_file -> path of root.crt 											#
	#   c.   subject_cert_file -> path of subject.crt 									#	
	#   d.   password -> Password to open cert_bckup.p12 file 							#
	#																					#
	#   Returns:																		#
	#   a. sub_certificate -> X509 object containing certificate details of subject.crt #
	#   b. root_certificate -> X509 object containing certificate details of root.crt   #
	#   c. p12 -> PKCS12 object containing details of cert_bckup.p12                    #
	#       																			#
	#   Authors - Abhik Dey (1216907406) 												#			
	#   			 Abhilasha Mandal ()                                                #
	#####################################################################################

   # Read subject.crt
    with open(subject_cert_file, 'r') as sub_cert:
        sub = sub_cert.read()

    # Read root.crt
    with open(root_cert_file, 'r') as root_cert:
        root = root_cert.read()

    # Read cert_bckup.p12
    with open(backup_file, "rb") as cert_bckup:
    	bckup = cert_bckup.read()
    	p12 = crypto.load_pkcs12(bckup, password)


    sub_certificate = crypto.load_certificate(crypto.FILETYPE_PEM, sub)
    root_certificate = crypto.load_certificate(crypto.FILETYPE_PEM, root)

    return sub_certificate, root_certificate, p12

    
def verify_cert(sub, root):	
	############################################################################
	#  verify_cert -> The function verifies the validity of subject.crt        #
    #                                                                          #
	#  Parameters:                                                             #
	#  a. sub -> X509 object containing certificate details of subject.crt     #
	#  b. root -> X509 object containing certificate details of root.crt       # 
    #                                                                          #
	#  Returns: True or False based on the validity of the certificate         #
    #                                                                          # 
    #                                                                          #
	#  Authors - Abhik Dey (1216907406)                                        #
	#			 Abhilasha Mandal ()                                           #
    ############################################################################
    
    try:
    	# Create and fill a X509Sore with root
    	store = crypto.X509Store()
    	trusted_cert = crypto.load_certificate(crypto.FILETYPE_PEM, root)
    	store.add_cert(root)

    	# Create a X590StoreContext with the sub and root
    	store_ctx = crypto.X509StoreContext(store, sub)
    	
    	#Verify the sub certificate
    	#result - None means True
    	#if exception, will go to exception block as certificate is invalid and return False
    	result = store_ctx.verify_certificate()

    except:
    	result = False

    if result is None:
        return True
    else:
        return False

def print_subject_cert_details(sub):
    ########################################################################################
	#  print_subject_cert_details -> The function prints the below details of subject.crt  #
	#								 a. Subject                                            #  
	#								 b. Issued by                                          #
	#                                c. Serial Number                                      #
	#                                d. Encryption Algorithm                               #
	#                                e. Not Valid Before                                   #
	#                                f. Not Valid After                                    # 
    #                                                                                      #
	#   Parameters:                                                                        #
	#   a. sub -> X509 object containing certificate details of subject.crt                #
    #                                                                                      #
	#   Returns: N/A                                                                       # 
    #                                                                                      #
	#   Authors - Abhik Dey (1216907406)                                                   #
	#   		  Abhilasha Mandal ()                                                      #
    ########################################################################################

	subject = sub.get_subject()
	# issued_to = subject.CN    # the Common Name field
	issuer = sub.get_issuer()
	serial_number = sub.get_serial_number()
	encry_algo = sub.get_signature_algorithm()
	not_valid_before = sub.get_notBefore()
	not_valid_after = sub.get_notAfter()

	
	print ("2.")
	print ("a. Subject - ",subject.CN)
	print ("b. Issued by - ",issuer.CN)
	print ("c. Serial Number - ",serial_number)
	print ("d. Encryption Algorithm - ",encry_algo.decode('UTF-8'))
	print ("e. Not Valid Before- ",not_valid_before.decode('UTF-8'))
	print ("f. Not Valid After - ",not_valid_after.decode('UTF-8'))
	
def print_subject_pub_priv_key(sub,p12):
    ##################################################################################################
	#   print_subject_pub_priv_key -> The function prints the public and private keys of subject.crt #
	#								 a. Public Key Modulus (n)										 #
	#								 b. Public Key Exponent (e)										 #
	#								 c. Private Key Exponent (d) 									 #
    #																								 #
	#   Parameters:																					 #
	#   a. sub -> X509 object containing certificate details of subject.crt 						 #	
	#   b. p12 -> PKCS12 object containing details of cert_bckup.p12 								 #
    #																								 #
	#   Returns: 																					 #	
	#   a. pubkey -> Public key of subject.crt                                                       #
	#   b. private_key -> Private key of subject.crt                                                 #
    #                                                                                                #
    #                                                                                                #
	#   Authors - Abhik Dey (1216907406)                                                             #
	#   		  Abhilasha Mandal ()                                                                #
	##################################################################################################

	public_key = sub.get_pubkey()
	pubKeyString = crypto.dump_publickey(crypto.FILETYPE_PEM, public_key)
	pubkey = RSA.importKey(pubKeyString)
	
	print ("3. Subject Certificate Keys")
	print ("\na. Public key Modulus (n) : ")
	print(pubkey.n)
	print ("\nb. Public key Exponent (e) : ",pubkey.e)
	
	private_key = print_bckup_priv_key(p12)
	
	return pubkey,private_key


def print_bckup_priv_key(p12):
	###################################################################################################
	#  print_bckup_priv_key -> The function prints the private key of subject.crt from cert_bckup.p12 #
	#						   a. Private Key Exponent (d)											  #		
	# 																								  #
	#  Parameters:																					  #	
	#   a. p12 -> PKCS12 object containing details of cert_bckup.p12                                  #
	#  																								  #
	#   Returns: 																					  #
	#   a. private_key -> Private key of subject.crt 												  #				
	# 																								  # 		
	#																								  #	
	#   Authors - Abhik Dey (1216907406)															  #	
	#   	      Abhilasha Mandal ()																  #	
	###################################################################################################
    private_key = p12.get_privatekey()
    privKeyString = crypto.dump_privatekey(crypto.FILETYPE_PEM, private_key)
    privkey = RSA.importKey(privKeyString)
    print ("\nc. Private Key Exponent (d) : ")
    print (privkey.d)
    return privkey
    
	

def print_root_pub_key(root_cert_file):
    ###################################################################################################
	#  print_root_pub_key -> The function prints the public key of root.crt                           #
	#								 a. Public Key Modulus (n)                                        #
	#								 b. Public Key Exponent (e)										  #
	#   																							  #
	#  Parameters:																					  #	
	#   a. root_cert_file -> X509 object containing certificate details of root.crt                   #
	#  																								  #
	#   Returns: N/A 															      				  #				
	# 																								  # 		
	#																								  #	
	#   Authors - Abhik Dey (1216907406)															  #	
	#   	      Abhilasha Mandal ()																  #	
	###################################################################################################

	public_key_root = root_cert_file.get_pubkey()
	pubKeyStringRoot = crypto.dump_publickey(crypto.FILETYPE_PEM, public_key_root)
	pubkey = RSA.importKey(pubKeyStringRoot)
	print ("4. Root Public Keys: ")
	print ("\na. Public key Modulus (n) : ")
	print(pubkey.n)
	print ("\nb. Public key Exponent (e) : ",pubkey.e)



def print_signature_in_hex(sub):
    ###################################################################################################
	#  print_signature_in_hex -> The function prints the hex signature on the Subject’s certificate	  #	
	#   																							  #
	#  Parameters:																					  #	
	#  a. sub -> X509 object containing certificate details of subject.crt							  #
	#                                                                                                 #
	#  Returns: bytes_signature.hex() -> the hex signature on the Subject’s certificate  			  #				
	# 																								  # 		
	#																								  #	
	#   Authors - Abhik Dey (1216907406)															  #	
	#   	      Abhilasha Mandal ()																  #	
	###################################################################################################

    der = DerSequence()
    der.decode(crypto.dump_certificate(crypto.FILETYPE_ASN1, sub))
    signature = der[2]
    signature_der_obj = DerObject()
    signature_der_obj.decode(signature)
    bytes_signature=signature_der_obj.payload[1:] #skip leading zeros
    return bytes_signature.hex()

def encrypt(pubkey, message):
	###################################################################################################
	#  encrypt -> The function encrypts the message b'Hello World' using:							  #
	#              a. subject's public key,															  #	
	#              b. OEAP padding																	  #
	#              c. mask generation function MGF1													  #
	#              d. SHA256 hash function  #	 													  #
	#   																							  #
	#  Parameters:																					  #	
	#  a. pubkey -> public key of the subject.crt file                   							  #
	#  b. message -> Encrypt message b'Hello World'     											  #
	#                                                                                                 #
	#  Returns: ciphertext -> Encrypted text message                                     			  #				
	# 																								  # 		
	#																								  #	
	#   Authors - Abhik Dey (1216907406)															  #	
	#   	      Abhilasha Mandal ()																  #	
	###################################################################################################
	
	cipher_object = PKCS1_OAEP.new(key=pubkey, hashAlgo=Crypto.Hash.SHA256, mgfunc=lambda x,y: Crypto.Signature.PKCS1_PSS.MGF1(x,y,Crypto.Hash.SHA256) )
	ciphertext = cipher_object.encrypt(message)
	return ciphertext


def decrypt(privkey, ciphermessage):
	###################################################################################################
	#  decrypt -> The function decrypt the encrypted message using:									  #	
	#              a. subject's private key,														  #				
	#              b. OEAP padding																	  #
	#              c. mask generation function MGF1													  #			
	#              d. SHA256 hash function															  #
 	#																						          #
	#  Parameters:																					  #	
	#  a. privkey -> private key of the subject.crt file                  							  #
	#  b. ciphermessage -> Encrypted message of plain text b'Hello World'							  #
	#                                                                                                 #
	#  Returns: plaintext -> Decrypted ciphertext                                        			  #				
	# 																								  # 		
	#																								  #	
	#   Authors - Abhik Dey (1216907406)															  #	
	#   	      Abhilasha Mandal ()																  #	
	###################################################################################################
	
	cipher_object = PKCS1_OAEP.new(key=privkey, hashAlgo=Crypto.Hash.SHA256, mgfunc=lambda x,y: Crypto.Signature.PKCS1_PSS.MGF1(x,y,Crypto.Hash.SHA256) )
	plaintext = cipher_object.decrypt(ciphermessage)
	return plaintext

def main(backup_file,root_cert_file,subject_cert_file,password):
	#########################################################################################
	#  main -> The main function of the program that perform actions using the below files: #
    #		   a. subject.crt 																#
    #		   b. root.crt 																	#	
    #		   c. cert_bckup.p12 															#	
    #																						#	
	#   Parameters:																			#
	#   a.  	backup_file -> path of cert_bckup.p12 										#
	#   b. 	root_cert_file -> path of root.crt 												#		
	#   c.   subject_cert_file -> path of subject.crt 										#
	#   d.   password -> Password to open cert_bckup.p12 file 								#	
	#																						#	
	#   Returns: N/A 																		#	
	#																						#
	#   Authors - Abhik Dey (1216907406)													#
	#   		  Abhilasha Mandal ()   													#
	#########################################################################################

	sub, root, p12 = read_certificates(backup_file,root_cert_file,subject_cert_file,password)
	print ("******************************************************")
	print ("1. ",verify_cert(sub, root))
	print ("******************************************************")
	print_subject_cert_details(sub)
	print ("******************************************************")
	sub_pub_key, sub_priv_key = print_subject_pub_priv_key(sub, p12)
	print ("\n******************************************************")
	print_root_pub_key(root)
	print ("\n******************************************************")
	print ("5. Subject certificate signature in hex :")
	print (print_signature_in_hex(sub))
	print ("\n******************************************************")
	print ("\n6 a. Encrypted Message :")
	ciphertext = encrypt(sub_pub_key, b'Hello World')
	print (ciphertext)
	print ("\n6 b. Decrypted Message : ",decrypt(sub_priv_key, ciphertext),"\n")



if __name__ == '__main__':
	
	'''The program will start exection from here'''
	# Takes command line input
	backup_file = sys.argv[1]
	root_cert_file = sys.argv[2]
	subject_cert_file = sys.argv[3]
	password = sys.argv[4]
	main(backup_file,root_cert_file,subject_cert_file,password)
