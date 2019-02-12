#include <iostream>
#include <iomanip>
#include <vector>
#include <string>
#include <chrono>
#include <random>
#include <thread>
#include <mutex>
#include <memory>
#include <limits>

#include "seal/seal.h"
#include "Matrix.h"
#include "encrypted_controller.cpp"
#include "helper.h"

using namespace std;
using namespace seal;


int main()
{
	cout << "Hello SEAL! Let's try a basic encrypted controller." << endl;

    const int n = 2; // number of states
    const int m = 2; // number of control inputs
    const int T = 2; // time periods
    int x0_arr[n] = {1,1};
    vector<int> x0 (x0_arr, x0_arr + sizeof(x0_arr)/sizeof(int));
    int A_arr[n*n] = {1, 0, 0, 1};
    Matrix<int> A(n, n, A_arr);
    int B_arr[n*m] = {2, -2, -2, 2};
    Matrix<int> B(n, m, B_arr);
    int K_arr[m*n] = {-1,1,1,0};
    Matrix<int> K(m, n, K_arr);

	/*
	Instance of the EncryptionParameters class for the BFV scheme.
	*/
	EncryptionParameters parms(scheme_type::BFV);
    setup_params(parms);
    std::shared_ptr<seal::SEALContext> context = SEALContext::Create(parms);
    std::unique_ptr<seal::IntegerEncoder> encoder = make_unique<IntegerEncoder>(parms.plain_modulus()); // Encoder object.
    std::unique_ptr<seal::KeyGenerator> keygen = make_unique<KeyGenerator>(context);
    PublicKey public_key = keygen->public_key();
    SecretKey secret_key = keygen->secret_key();
    std::unique_ptr<seal::Encryptor> encryptor = make_unique<Encryptor>(context, public_key); // Encryptor object.
	std::unique_ptr<seal::Decryptor> decryptor = make_unique<Decryptor>(context, secret_key); // Decryptor object.
    /*
    Initialize the dynamics and the encryption parameters.
    */
    Dynamics dynamics = Dynamics(x0, A, B);
    dynamics.setEncryption(parms, context, public_key, secret_key);

    /*
    Initialize the controller with plaintext K and get the encryption parameters and public key.
    */
    Controller controller = Controller(K);
    controller.getEncryption(parms, context, public_key);

    /*
    Run the control loop for T-1 time steps.
    */
    for (int i=0; i < T; i++)
    {
        dynamics.get_control(controller.update_control(dynamics.return_state()));
    }
    
    cout << "Re-initialize." << endl;
    /*
    Initialize the dynamics and the encryption parameters for a different controller.
    */
    Dynamics dynamics2 = Dynamics(x0, A, B);
    dynamics2.setEncryption(parms, context, public_key, secret_key);

    /*
    Initialize the controller with ciphertext K and get the encryption parameters and public key.
    */
    Matrix<Plaintext> plain_K = encode_matrix(encoder, K);
    Ciphertext enc_zero;
    encryptor->encrypt(encoder->encode(0),enc_zero);
    Matrix<Ciphertext> enc_K = encrypt_matrix(encryptor, plain_K, enc_zero);

    Controller controller2 = Controller(enc_K);
    controller2.getEncryption(parms, context, public_key);

    /*
    Run the control loop for T-1 time steps.
    */
    for (int i=0; i < T; i++)
    {
        dynamics2.get_control(controller2.update_control(dynamics2.return_state()));
    }

	return 0;
}


