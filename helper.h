#ifndef __HELPER_H
#define __HELPER_H


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

using namespace std;
using namespace seal;

/*
Print a vector object.
*/
void print_vector(const std::vector<int> v);

/*
Integer Encoder for a vector of int messages.
*/
std::vector<Plaintext> encode_vector(const std::unique_ptr<seal::IntegerEncoder> &encoder, const std::vector<int> message);

/*
Integer Encoder for a matrix of int messages.
*/
Matrix<Plaintext> encode_matrix(const std::unique_ptr<seal::IntegerEncoder> &encoder, const Matrix<int> message);

/*
Integer Decoder for a vector of plaintexts.
*/
std::vector<int> decode_vector(const std::unique_ptr<seal::IntegerEncoder> &encoder, const std::vector<Plaintext> plain);

/*
Encrypt a vector of plaintexts.
*/
std::vector<Ciphertext> encrypt_vector(const std::unique_ptr<seal::Encryptor> &encryptor, const std::vector<Plaintext> plain);

/*
Encrypt a matrix of plaintexts.
*/
Matrix<Ciphertext> encrypt_matrix(const std::unique_ptr<seal::Encryptor> &encryptor, const Matrix<Plaintext> plain);

/*
Decrypt a vector of ciphertexts.
*/
std::vector<Plaintext> decrypt_vector(const std::unique_ptr<seal::Decryptor> &decryptor, const std::vector<Ciphertext> encrypted);

/*
Decrypt a matrix of ciphertexts.
*/
Matrix<Plaintext> decrypt_vector(const std::unique_ptr<seal::Decryptor> &decryptor, const Matrix<Ciphertext> encrypted);

/*
Multiply a plaintext matrix by a plaintext vector. Pass a vector of encrypted zeros of appropiate size such that we don't need 
to pass encoder and encryptor. SEAL does not allow multiplication by zero plaintexts, so we have to perform a separate check 
for that.
*/
std::vector<Ciphertext> mult_matrix_vector(const std::unique_ptr<seal::Evaluator> &evaluator, const Matrix<Plaintext> plain_matrix, 
	const std::vector<Ciphertext> encrypted, std::vector<Ciphertext> result);

/*
Print the noise budget for an encrypted vector.
*/
void print_noise_budget_vector(const std::unique_ptr<seal::Decryptor> &decryptor, const std::vector<Ciphertext> encrypted);

/*
Helper function: Prints the `parms_id' to std::ostream.
*/
ostream &operator <<(ostream &stream, parms_id_type parms_id);

/*
Helper function from examples.cpp in SEAL: Prints the encryption parameters.
*/
void print_parameters(shared_ptr<SEALContext> context);

/*
Setup the encryption scheme and parameters.
*/
void setup_params(EncryptionParameters &parms);

#include "helper.cpp"

#endif