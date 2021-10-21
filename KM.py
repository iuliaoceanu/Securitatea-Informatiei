from Crypto import Random
from Crypto.Cipher import AES
import socket


HOST = "127.0.0.1"
PORT = 65432

#vectorul de initializare
IV = b"2406170719992000"


#generez K' cu modul CBC si o criptez
def generate_K1(key):
	k = Random.get_random_bytes(16)
	print("K1 = ", k)
	cipher = AES.new(key, AES.MODE_CBC, IV)
	return cipher.encrypt(k)


#generez cheia K
def generate_K2():
	return Random.get_random_bytes(16)


if __name__ == "__main__":
	with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
		s.bind((HOST, PORT))
		s.listen()

		#se conecteaza nodul A, apoi B
		connA, addrA = s.accept()
		connB, addrB = s.accept()

		#cheia K'
		private_key = generate_K2()
		print("1. Cheia generata (K) =", private_key, "\n")

		with connB:
			print("Node B: connected!", addrB)

			#trimit cheia la B
			connB.sendall(private_key)

			connB.close()
			print("Nodul B a primit cheia si inchide conexiunea!")

		with connA:
			print("Node A: connected!", addrA)
			#trimit cheia la A
			connA.sendall(private_key)

			print("Modul de comunicare ales de nodul A =", connA.recv(1024))

			#ii comunic si cheia K' criptata lui A
			private_key = generate_K1(private_key)
			connA.sendall(private_key)
			print("Nodul A a primit cheia de criptare si inchide conexiunea!")

			connA.close()