#include "helper.h"

using namespace std;
using namespace seal;

/*
Print a vector object.
*/
void print_vector(const std::vector<int> v)
{
    for(int i = 0; i < v.size(); i++)
        cout << v[i] << ' ';
    cout << endl;   
}

/*
Integer Encoder for a vector of int messages.
*/
std::vector<Plaintext> encode_vector(const std::unique_ptr<seal::IntegerEncoder> &encoder, const std::vector<int> message)
{
	vector<Plaintext> plain(message.size());
	for(int i = 0; i < message.size(); i++)
		plain[i] = encoder->encode(message[i]);
	return plain;
}


/*
Integer Encoder for a matrix of int messages.
*/
Matrix<Plaintext> encode_matrix(const std::unique_ptr<seal::IntegerEncoder> &encoder, const Matrix<int> message)
{
	Plaintext p = encoder->encode(0);
	Matrix<Plaintext> plain(message.get_rows(), message.get_cols(), p);
	for(int i = 0; i < plain.get_rows(); i++)
		for(int j = 0; j < plain.get_cols(); j++)
			plain(i,j) = encoder->encode(message(i,j));
	return plain;
}

/*
Integer Decoder for a vector of plaintexts.
*/
std::vector<int> decode_vector(const std::unique_ptr<seal::IntegerEncoder> &encoder, const std::vector<Plaintext> plain)
{
	vector<int> message(plain.size());
	for(int i = 0; i < plain.size(); i++)
		message[i] = encoder->decode_int32(plain[i]);
	return message;
}

/*
Encrypt a vector of plaintexts.
*/
std::vector<Ciphertext> encrypt_vector(const std::unique_ptr<seal::Encryptor> &encryptor, const std::vector<Plaintext> plain)
{
	vector<Ciphertext> encrypted(plain.size());
	for(int i = 0; i < plain.size(); i++)
		encryptor->encrypt(plain[i], encrypted[i]);
	return encrypted;
}

/*
Decrypt a vector of ciphertexts.
*/
std::vector<Plaintext> decrypt_vector(const std::unique_ptr<seal::Decryptor> &decryptor, const std::vector<Ciphertext> encrypted)
{
	vector<Plaintext> plain(encrypted.size());
	for(int i = 0; i < encrypted.size(); i++)
		decryptor->decrypt(encrypted[i], plain[i]);
	return plain;
}


/*
Multiply a plaintext matrix by a plaintext vector. Pass a vector of encrypted zeros of appropiate size such that we don't need 
to pass encoder and encryptor. SEAL does not allow multiplication by zero plaintexts, so we have to perform a separate check 
for that.
*/
std::vector<Ciphertext> mult_matrix_vector(const std::unique_ptr<seal::Evaluator> &evaluator, const Matrix<Plaintext> plain_matrix, 
	const std::vector<Ciphertext> encrypted, std::vector<Ciphertext> result)
{
	vector<Ciphertext> temp = encrypted;
	try 
	{
		if (result.size() != plain_matrix.get_rows()) 
			throw "Dimensions incompatible!";	
		for(int i = 0; i < plain_matrix.get_rows(); i++)
		{
			for(int j = 0; j < plain_matrix.get_cols(); j++)
			{
				if (!plain_matrix(i,j).is_zero())
				{
					evaluator->multiply_plain_inplace(temp[j], plain_matrix(i,j));
					evaluator->add_inplace(result[i], temp[j]);
					temp = encrypted;
				}
			}
		}
	}
	catch(const char* msg) 
	{
		cout << msg << endl;
	}	
	return result;
}

/*
Helper function: Prints the `parms_id' to std::ostream.
*/
ostream &operator <<(ostream &stream, parms_id_type parms_id)
{
    stream << hex << parms_id[0] << " " << parms_id[1] << " "
        << parms_id[2] << " " << parms_id[3] << dec;
    return stream;
}

/*
Helper function from examples.cpp in SEAL: Prints the encryption parameters.
*/
void print_parameters(shared_ptr<SEALContext> context)
{
    /* 
    Verify parameters
    */
    if (!context)
    {
        throw invalid_argument("context is not set");
    }
    auto &context_data = *context->context_data();

    string scheme_name;
    switch (context_data.parms().scheme())
    {
    case scheme_type::BFV:
        scheme_name = "BFV";
        break;
    case scheme_type::CKKS:
        scheme_name = "CKKS";
        break;
    default:
        throw invalid_argument("unsupported scheme");
    }

    cout << "/ Encryption parameters:" << endl;
    cout << "| scheme: " << scheme_name << endl;
    cout << "| poly_modulus_degree: " << 
        context_data.parms().poly_modulus_degree() << endl;

    /*
    Print the size of the true (product) coefficient modulus.
    */
    cout << "| coeff_modulus size: " << context_data.
        total_coeff_modulus_bit_count() << " bits" << endl;

    /*
    For the BFV scheme print the plain_modulus parameter.
    */
    if (context_data.parms().scheme() == scheme_type::BFV)
    {
        cout << "| plain_modulus: " << context_data.
            parms().plain_modulus().value() << endl;
    }

    cout << "\\ noise_standard_deviation: " << context_data.
        parms().noise_standard_deviation() << endl;
    cout << endl;
}

/*
Setup the encryption scheme and parameters.
*/
void setup_params(EncryptionParameters &parms)
{
    /*
    Set the degree of the polynomial modulus, which has to be a large power of 2.
    */
    int poly_modulus_deg_value = 2048;
    parms.set_poly_modulus_degree(poly_modulus_deg_value);

    /*
    Set the ciphertext coefficient modulus, which substantially affects the noise budget.
    */
    parms.set_coeff_modulus(coeff_modulus_128(poly_modulus_deg_value));

    /*
    Set the plaintext modulus, which also affects the noise budget.
    */
    parms.set_plain_modulus(1 << 6);    // 2^6 = 64 bits
}