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

    /*
    Initialize the dynamics and the encryption parameters.
    */
    Dynamics dynamics = Dynamics(x0, A, B);
    dynamics.setEncryption(parms);

    /*
    Initialize the controller and get the encryption parameters and public key.
    */
    Controller controller = Controller(K);
    controller.getEncryption(parms, dynamics.return_pubkey());

    /*
    Run the control loop for T-1 time steps.
    */
    for (int i=0; i < T; i++)
    {
        dynamics.get_control(controller.update_control(dynamics.return_state()));
    }
    
	return 0;
}


