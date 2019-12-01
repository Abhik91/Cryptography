/*
  #####################################################################################
  # Assignment to implement RSA Operations and Blind Certificates                     # 
  # Course - CSE 539: Applied Cryptography                                            #
  # Project Number - 6                                                                #
  # Author - Abhik Dey (1216907460)                                                   #
  #          Abhilasha Mandal (1217160477)                                            #
  #####################################################################################
*/

#include "RSA.h"
#include "BigInt.h"
#include <cstdlib>
#include <cmath>
#include <iostream>
#include <fstream>
using namespace std;
using namespace RSAUtil;

#define RAND_LIMIT32 0x7FFFFFFF

//To implement send and receive functionality
BigInt tosend, deciphered;

void blindsignature(){	
	/*
	Function to implement Blind Signature following the below steps:

	a.      Alice obtains the public key and Modulus N of the person (Bob) who is to sign the message

	b.      Obtain a random number and its inverse with respect to the Modulus [Not phi] of Bob

	c.      Alice obtains/generates a message to be signed.

	d.      Alice encrypts the random number with the public key.

	e.      Alice multiplies this value by the message

	f.      Alice then takes a modulus over N

	g.      Alice sends it to Bob

	h.      Bob simply decrypts the received value with the private key

	i.      Bob sends it back to Alice

	j.      Alice then multiplied the received value with the inverse and takes a modulus over N.

	k.      The value obtained above is the signed message. To obtain the original message from it, again encrypt it with Bob’s Public Key.

	**/

	unsigned long int *a;
	unsigned long int arr[4];
	a=&arr[0];

	BigInt randnum, inverse, randnum_encrypted, message, prod, sign, original;

	RSA bob;
	
	cout << "\n\n3. Blind Signature:" << "\n";
	cout << "---------------------------------"<<"\n";
	cout << "a.\tAlice obtains the public key and Modulus N of the person (Bob) who is to sign the message:\n\tPublic key: " << bob.getPublicKey().toHexString() << "\n\tModulus N: " << bob.getModulus().toHexString() << "\n\n";

	randnum = int(((double)std::rand()/RAND_MAX)*RAND_LIMIT32);
	randnum.toULong(a,4);
	
	inverse = modInverse(randnum, bob.getModulus());
	cout << "b.\tObtain a random number and its inverse with respect to the Modulus [Not phi] of Bob: \n\tRandom number: " << randnum.toHexString() << "\n\tInverse: " << inverse.toHexString() << "\n\n";

	message = int(((double)std::rand()/RAND_MAX)*RAND_LIMIT32);
	message.toULong(a,4);
	cout << "c.\tAlice obtains/generates a message to be signed: " << message.toHexString() << "\n\n";

	randnum_encrypted = bob.encrypt(randnum);
	cout << "d.\tAlice encrypts the random number with the public key: " << randnum_encrypted.toHexString() << "\n\n";
	
	prod = randnum_encrypted * message;
	cout << "e.\tAlice multiplies this value by the message: " << prod.toHexString() << "\n\n";

	tosend = prod % bob.getModulus();
	cout << "f.\tAlice then takes a modulus over N: " << tosend.toHexString() << "\n\n";

	cout << "g.\tAlice sends it to Bob\n\n";

	deciphered = bob.decrypt(tosend);
	cout << "h.\tBob simply decrypts the received value with the private key: " << deciphered.toHexString() << "\n\n";
	
	cout << "i.\tBob sends it back to Alice\n\n";

	sign = (deciphered * inverse) % bob.getModulus();
	cout << "j.\tAlice then multiplied the received value with the inverse and takes a modulus over N: " << sign.toHexString() << "\n\n";

	original = bob.encrypt(sign);
	cout << "k.\tThe value obtained above is the signed message. Encrypting it with Bob’s public Key to get original message: " << original.toHexString() << "\n\n";


};

void encryptDecryptUsingRSA(){

	/*
	1. Perform encryption and Decryption each using the RSA routines provided here.
		a. Create 10 instances of the RSA class without giving arguments, generate random message or assign messages, and perform encryption through each of the 10 classes.
		b. Create 5 instances of the RSA class by passing a large prime number [p](> 30,000), and perform encryption decryption
		c. Create 5 instances of the RSA class by passing 2 large prime numbers [p,q] (> 30,000) and perform encryption decryption
		d. Create 10 instances of the RSA class by passing 2 large non-prime numbers (> 30,000) and perform encryption decryption. In most of the cases the message should not get decrypted correctly.
		e. Show the results for encryption and decryption for each of the above cases. If you notice anything out of the ordinary, please record it. For example, if you are able to decrypt using non-prime numbers as the p,q values then it is out of ordinary.
	*/
	unsigned long int *a;
	unsigned long int arr[4];
	a=&arr[0];

	int instances = 10;
	RSA* rsa1;	
	BigInt message, encryptedMessage, decryptedMessage;

	cout << "\n\n1. Perform encryption and Decryption each using the RSA routines\n";
	cout << "----------------------------------------------------------------\n";
	cout << "a. Create 10 instances of RSA and perform encryption:\n";

	message = int(((double)std::rand()/RAND_MAX)*RAND_LIMIT32);
	message.toULong(a,4);
	cout << "\nMessage - "<<message.toHexString()<<"\n";;

	for (int i = 0; i<instances; i++){

		rsa1 = new RSA();
		encryptedMessage = rsa1->encrypt(message);
		decryptedMessage = rsa1->decrypt(encryptedMessage);

		cout <<"\nInstance :"<<i+1<<"\t";
		cout <<"Encrypted message :"<<encryptedMessage.toHexString()<<"\t";
		cout <<"Decrypted message :"<<decryptedMessage.toHexString();
		delete rsa1;
	}

	
	cout << "\n\nb. Create 5 instances of the RSA class by passing a large prime number [p](> 30,000), and perform encryption decryption\n";
	RSA* rsa2;
	int p[] = {32779, 43499, 45589, 39901, 31771};

	instances = 5;

	cout <<"\nMessage :" << message.toHexString() <<"\n";
	for (int i = 0; i<instances; i++){

		
		cout <<"\nInstance :"<<i+1<<"\t";
		cout <<"p = "<<p[i]<<"\t";
		rsa2 = new RSA(p[i]);
		encryptedMessage = rsa2->encrypt(message);
		decryptedMessage = rsa2->decrypt(encryptedMessage);

		cout <<"Encrypted message :"<<encryptedMessage.toHexString()<<"\t";
		cout <<"Decrypted message :"<<decryptedMessage.toHexString();

		delete rsa2;
	}

	cout << "\n\nc. Create 5 instances of the RSA class by passing 2 large prime numbers [p,q] (> 30,000) and perform encryption decryption\n";
	RSA* rsa3;
	int q[] = {52967, 52973, 52981, 52999, 53003};

	instances = 5;
	cout <<"\nMessage :" << message.toHexString() <<"\n";
		
	for (int i = 0; i<instances; i++){

		cout <<"\nInstance :"<<i+1<<"\t";
		cout <<"p = " << p[i] << "\tq = " << q[i] << "\t";
		rsa3 = new RSA(p[i],q[i]);
		encryptedMessage = rsa3->encrypt(message);
		decryptedMessage = rsa3->decrypt(encryptedMessage);

		cout <<"Encrypted message :"<<encryptedMessage.toHexString()<<"\t";
		cout <<"Decrypted message :"<<decryptedMessage.toHexString();

		delete rsa3;
	}

	cout << "\n\nd. Create 10 instances of the RSA class by passing 2 large non - prime numbers [p,q] (> 30,000) and perform encryption decryption\n";
	RSA* rsa4;
	int p1[] = {32772, 43494, 45586, 39908, 31770, 33772, 44494, 46586, 49908, 39770};
	int q1[] = {52962, 52974, 52986, 52998, 53000, 53012, 55964, 51978, 54986, 52990};

	instances = 10;
	cout <<"\nMessage :" << message.toHexString() <<"\n";
		
	for (int i = 0; i<instances; i++){

		cout <<"\nInstance :"<<i+1<<"\t";
		cout <<"p = " << p1[i] << "\tq = " << q1[i] << "\t";
		rsa4 = new RSA(p1[i],q1[i]);
		encryptedMessage = rsa4->encrypt(message);
		decryptedMessage = rsa4->decrypt(encryptedMessage);

		cout <<"Encrypted message :"<<encryptedMessage.toHexString()<<"\t";
		cout <<"Decrypted message :"<<decryptedMessage.toHexString();

		delete rsa4;
	}
	cout << "\nMessage did not decrypt correctly for non-prime numbers";
};

void challengeResponse(){
	
	/*
	2. Challenge Response-	
	a. Create an RSA object. Call it RSA1
	b. Create a new RSA object, call it RSA2. Obtain the public key and modulus [n] of RSA1. Assign these two to the public key and N value in RSA2.
	c. Generate a random message [random BigInt number]. Encrypt it using the public key of RSA2 [You have stored the pub key of RSA1 in RSA2].
	d. Decrypt the value using the private key of RSA1.
	e. Match both the values (original message vs decrypted message), they should be the same. If so Challenge Response scheme is completed.
	*/

	RSA* RSA1;
	RSA* RSA2;

	BigInt rsa1PubKey, rsa1Modulus, message, encrypt, decrypt;

	unsigned long int *a;
	unsigned long int arr[4];
	a=&arr[0];

	RSA1 = new RSA();
	RSA2 = new RSA();

	//Set RSA2 public key from RSA1	
	rsa1PubKey = RSA1->getPublicKey();
	RSA2->setPublicKey(rsa1PubKey);


	//Set RSA2 Modulus from RSA1	
	rsa1Modulus = RSA1->getModulus();
	RSA2->setN(rsa1Modulus);

	//Generate random messge
	message = int(((double)std::rand()/RAND_MAX)*RAND_LIMIT32);
	message.toULong(a,4);

	//encrypt with RSA2 public key
	encrypt = RSA2->encrypt(message);
	decrypt = RSA1->decrypt(encrypt);

	cout << "\n\n2. Challenge Response Scheme\n";
	cout << "----------------------------------------------------------------\n";
	cout << "\na. RSA2 Pubic Key: "<<RSA2->getPublicKey().toHexString();
	cout << "\nb. RSA2 Modulus : "<< RSA2->getModulus().toHexString();
	cout << "\nc. Random message [random BigInt number] : "<<message.toHexString();
	cout << "\nd. Encrypted message with RSA2 Public Key :"<< encrypt.toHexString();
	cout << "\ne. Decrypted message with RSA1 Private Key :" << decrypt.toHexString();

	if (message == decrypt)
		cout << "\nChallenge Response scheme is completed!!\n\n";
	else
		cout << "\nChallenge Response scheme failed\n\n";
};


int main(int argc, char* argv[]) {

	blindsignature();
	char response;
	
	cout << "\nDo you want to see output of Q1 and Q2? (y/n): ";
	cin >> response;

	cout<< ("\n");
	if (response == 'Y' ||response == 'y'){
		encryptDecryptUsingRSA();
		cout<< ("\n");
		challengeResponse();
	}
	 return(0);
}
