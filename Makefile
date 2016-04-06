all:
	g++ -std=c++14 CrackOpenSSL.cpp -o CrackOpenSSL.so -shared -fPIC -ldl
	
clean:
	rm -rf *so MasterKey.txt