# basic-encrypted-controller
Toy problem to figure out how to work with SEAL https://www.microsoft.com/en-us/research/project/simple-encrypted-arithmetic-library/ .

The idea is to implement a linear controller that operates with encrypted data. The linear time-invariant dynamics is:
x[k+1] = Ax[k] + Bu[k]
and the control input is computed as:
u[k] = Kx[k].

The class Controller gets the encrypted state x[k] and computes the control input either with plaintext control gain K or with encrypted control gain.

The class Dynamics then gets the encrypted control input u[k], decrypts it and updates the state x[k+1].

At the moment, the naive version is implemented, where each element is a different ciphertext. The more efficient but complex method that uses rotations will come soon.

This project needs SEAL to be installed. Then, one can run it with in the terminal with:
cmake .
make
./encrypted_controller
