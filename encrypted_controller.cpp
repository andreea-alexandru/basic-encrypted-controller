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
#include "helper.h"

using namespace std;
using namespace seal;


/*
Class that simulates a linear time invariant plant: x[k+1] = A*x[k] + B*u[k].
*/
class Dynamics
{

private:
    vector<int> x0_, x_; // Initial state, state.
    Matrix<int> A_, B_; // State matrix and input matrix.
    vector<int> u_; // Control input.

	std::unique_ptr<seal::IntegerEncoder> encoder_; // Encoder object.
    std::unique_ptr<seal::Encryptor> encryptor_; // Encryptor object.
    std::unique_ptr<seal::Decryptor> decryptor_; // Decryptor object.

    vector<Plaintext> plain_x_;	// Plaintext state.
    vector<Ciphertext> encrypted_x_; // Ciphertext state.
    vector<Plaintext> plain_u_; // Plaintext control input.
    vector<int> Bu; // intermediate value B*u

    /*
    Update the state according to the dynamics.
    */
    void update_state()
    {
        x_ = A_ * x_;
        Bu = B_ * u_;
        transform (x_.begin(), x_.end(), Bu.begin(), x_.begin(), std::plus<int>());
        x_ = x_;
        k_ = k_ + 1;
        cout << "x[" << k_ <<"]: ";
        print_vector(x_);
    }    



public:
    int k_;  // time step

    /*
     Constructor: initializes the system at time 0.
     */
    Dynamics(vector<int> _x0, Matrix<int> _A, Matrix<int> _B)
    {
        k_ = 0;
        x0_ = _x0;
        x_ = x0_;
        A_ = _A;
        B_ = _B;
        cout << "A: ";
        A_.print();
        cout << "B: ";
        B_.print();
        cout << "x[0]: ";
        print_vector(x0_);

    }

	/*
	Construct a SEALContext object which deals with checking the validity of the parameters and pre-compute some other parameters.
	*/
    void setEncryption(const EncryptionParameters &_parms, const std::shared_ptr<seal::SEALContext> _context, 
    	const PublicKey _public_key, const SecretKey _secret_key)
    {
		PublicKey public_key = _public_key;
		encryptor_ = make_unique<Encryptor>(_context, public_key);
		SecretKey secret_key = _secret_key;
		decryptor_ = make_unique<Decryptor>(_context, secret_key);
		encoder_ = make_unique<IntegerEncoder>(_parms.plain_modulus());
    }


    /* 
    Get ciphertext of control action, decrypt it and perform the state update.
    */
    void get_control(vector<Ciphertext> encrypted_u)
    {	
    	cout << "Noise budget in encrypted_u: ";
    	print_noise_budget_vector(decryptor_, encrypted_u);
        plain_u_ = decrypt_vector(decryptor_, encrypted_u);
        u_ = decode_vector(encoder_, plain_u_);
        cout << "u[" << k_+1 <<"]: ";
        print_vector(u_);
        (*this).update_state();
    }

    /* 
    Get the curent state, encrypt it and send it to the controller.
    */
    vector<Ciphertext> return_state()
    {
        plain_x_ = encode_vector(encoder_, x_);
        encrypted_x_ = encrypt_vector(encryptor_, plain_x_);
        return encrypted_x_;
    }

    /*
    Destructor.
    */
    ~Dynamics() {}

};


/*
Class that simulates a linear controller: u[k] = K*x[k].
*/
class Controller
{
private:
    vector<int> u_; // Control input.
    Matrix<int> K_; // Control gain matrix.

	std::unique_ptr<seal::IntegerEncoder> encoder_; // Encoder object.
    std::unique_ptr<seal::Encryptor> encryptor_; // Encryptor object.
	std::unique_ptr<seal::Evaluator> evaluator_; // Evaluator object.

    Matrix<Plaintext> plain_K_;	// Plaintext control gain.
    Matrix<Ciphertext> enc_K_; // Ciphertext control gain
    vector<Ciphertext> encrypted_u_;  // Ciphertext control input.
    bool flag_enc_;	// Flag is 0 if K is plaintext and 1 if it is ciphertext

public:
    int k_;  // time step

    // Constructor: initializes the controller at time 0 with plaintext control gain.
    Controller(Matrix<int> _K)
    {
        k_ = 0;
        K_ = _K;
        cout << "K: ";
        K_.print();
        const int m = K_.get_rows();
        const int n = K_.get_cols();
        vector<int> u (m, 0);
        u_ = u;
        cout << "initialize u: ";
        print_vector(u_);
        flag_enc_ = 0;
    }

    // Constructor: initializes the controller at time 0 with ciphertext control gain.
    Controller(Matrix<Ciphertext> _K)
    {
        k_ = 0;
        enc_K_ = _K;
        const int m = _K.get_rows();
        const int n = _K.get_cols();
        vector<int> u (m, 0);
        u_ = u;
        cout << "initialize u: ";
        print_vector(u_);
        flag_enc_ = 1;
    }

    /*
    Initialize the encryption parameters.
    */
    void getEncryption(const EncryptionParameters _parms, const std::shared_ptr<seal::SEALContext> _context, const PublicKey _public_key)
    {
		encoder_ = make_unique<IntegerEncoder>(_parms.plain_modulus());
	    encryptor_ = make_unique<Encryptor>(_context, _public_key);
	    evaluator_ = make_unique<Evaluator>(_context);

	    if (flag_enc_ == 0)
	    	plain_K_ = encode_matrix(encoder_, K_);	// compute the plaintext for the constant matrix once
    }    

    /*
    Compute the control action according to the control law.
    */
    vector<Ciphertext> update_control(vector<Ciphertext> encrypted_x)
    {
    	if (flag_enc_ == 0)
    	{
	    	vector<int> zero_vector(K_.get_rows(),0);
	    	vector<Plaintext> enco_zero_vector = encode_vector(encoder_, zero_vector);
	    	vector<Ciphertext> encr_zero_vector = encrypt_vector(encryptor_, enco_zero_vector);
	        encrypted_u_ = mult_matrix_vector(evaluator_, plain_K_, encrypted_x, encr_zero_vector);
    	}
    	else
    	{
    		encrypted_u_ = mult_matrix_vector(evaluator_, enc_K_, encrypted_x);
    	}
        k_ = k_ + 1;
        return encrypted_u_;
    }

    // Destructor.
    ~Controller() {}

};


