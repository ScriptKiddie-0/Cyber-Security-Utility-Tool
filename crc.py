# Import socket module
import socket		 

def xor(a, b):

	# initialize result
	result = []

	# Traverse all bits, if bits are
	# same, then XOR is 0, else 1
	for i in range(1, len(b)):
		if a[i] == b[i]:
			result.append('0')
		else:
			result.append('1')

	return ''.join(result)


# Performs Modulo-2 division
def mod2div(dividend, divisor):

	# Number of bits to be XORed at a time.
	pick = len(divisor)

	# Slicing the dividend to appropriate
	# length for particular step
	tmp = dividend[0 : pick]

	while pick < len(dividend):

		if tmp[0] == '1':

			# replace the dividend by the result
			# of XOR and pull 1 bit down
			tmp = xor(divisor, tmp) + dividend[pick]

		else: # If leftmost bit is '0'

			# If the leftmost bit of the dividend (or the
			# part used in each step) is 0, the step cannot
			# use the regular divisor; we need to use an
			# all-0s divisor.
			tmp = xor('0'*pick, tmp) + dividend[pick]

		# increment pick to move further
		pick += 1

	# For the last n bits, we have to carry it out
	# normally as increased value of pick will cause
	# Index Out of Bounds.
	if tmp[0] == '1':
		tmp = xor(divisor, tmp)
	else:
		tmp = xor('0'*pick, tmp)

	checkword = tmp
	return checkword

# Function used at the sender side to encode
# data by appending remainder of modular division
# at the end of data.
def encodeData(data, key):

	l_key = len(key)

	# Appends n-1 zeroes at end of data
	appended_data = data + '0'*(l_key-1)
	remainder = mod2div(appended_data, key)

	# Append remainder in the original data
	codeword = data + remainder
	return codeword 
	
# Create a socket object
s = socket.socket()	 

# Define the port on which you want to connect
port = 12345		

# connect to the server on local computer
s.connect(('127.0.0.1', port))

# Send data to server 'Hello world'

## s.sendall('Hello World')

input_string = input("Enter data you want to send->")
#s.sendall(input_string)
data =(''.join(format(ord(x), 'b') for x in input_string))
print("Entered data in binary format :",data)
key = "1001"

ans = encodeData(data,key)
print("Encoded data to be sent to server in binary format :",ans)
s.sendto(ans.encode(),('127.0.0.1', 12345))


# receive data from the server
print("Received feedback from server :",s.recv(1024).decode())

# close the connection
s.close()
