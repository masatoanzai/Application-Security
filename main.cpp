/*
Masato Anzai 
N12725403
Implementation Project
Application Security
Professor Lum
*/

#include <iostream>
#include <string>
#include <fstream>
#include <stdio.h>
#include <vector>
#include <iomanip>
#include <sstream>
#include <openssl/aes.h>
#include <openssl/rand.h>


using namespace std;

//Please change the directory path!
string const dirPath = "/Users/masato/Documents/Course Work/Application Security/ImplementationProject/ImplementationProject/";
int const keylength = 256;
unsigned char const aes_key[keylength/8] = {"BB0F06261A049B908E1F1EAC4668802"};
class user;

bool checkUser(user, ifstream&);
user createUser(string, string);
void createDatabase(string);
bool checkDatabase(string);
string getPass(string, ifstream&);
string data_input(const void*, int);
string getEnc(string, ifstream&);
unsigned char getEnc_Out(unsigned char);
void print_data(const char*, const void* , int);
unsigned char cbcEncrypt(string);

class user{
public:
    user(string const username, string const password): username(username),password(password){}
    string getUser() const {return username;};
    string getPass() const {return password;};
private:
    string username;
    string password;
};


int main() {
    //TESTING THE ENCRYPTION
    // ECB AND CBC ENCRYPTION AND DECRYPTION WERE SUCCESFUllY IMPLEMENTED
    // CTR ENCRYPTION WAS NOT SUCCESSFUL
    string password = "test";
    long inputslength = password.size();
    unsigned char aes_input[password.size()];
    for (int i = 0; i < password.size(); i++){
        aes_input[i] = password[i];
    }
    
    unsigned char iv_enc[AES_BLOCK_SIZE], iv_dec[AES_BLOCK_SIZE];
    memcpy(iv_dec, iv_enc, AES_BLOCK_SIZE);
    
    //CBC OUTPUT
    unsigned char enc_out[inputslength];
    unsigned char dec_out[inputslength];
    memset(enc_out, 0, sizeof(enc_out));
    memset(dec_out, 0, sizeof(dec_out));
    
    //CTR OUTPUT
    unsigned char enc_out_ctr[inputslength];
    unsigned char dec_out_ctr[inputslength];
    unsigned char ecount_buf[AES_BLOCK_SIZE];
    unsigned int* num[AES_BLOCK_SIZE];
    memset(enc_out_ctr, 0, sizeof(enc_out_ctr));
    memset(dec_out_ctr, 0, sizeof(dec_out_ctr));
    memset(ecount_buf, 0, sizeof(AES_BLOCK_SIZE));
    memset(num, 0, sizeof(AES_BLOCK_SIZE));
  
    
    //ECB OUTPUT
    unsigned char enc_out_ecb[inputslength];
    unsigned char dec_out_ecb[inputslength];
    memset(enc_out_ecb, 0, sizeof(enc_out_ecb));
    memset(dec_out_ecb, 0, sizeof(dec_out_ecb));
    
    
    
    //CBC ENCRYPTION
    AES_KEY enc_key, dec_key;
    AES_set_encrypt_key(aes_key, keylength, &enc_key);
    AES_cbc_encrypt(aes_input, enc_out, inputslength, &enc_key, iv_enc, AES_ENCRYPT);
    
    AES_set_decrypt_key(aes_key, keylength, &dec_key);
    AES_cbc_encrypt(enc_out, dec_out, inputslength, &dec_key, iv_dec, AES_DECRYPT);

    
    //CTR ENCRYPTION
    AES_KEY enc_key_ctr, dec_key_ctr;
    AES_set_encrypt_key(aes_key, keylength, &enc_key);
    //AES_ctr128_encrypt(enc_out_ctr, dec_out_ctr, inputslength, &enc_key, iv_enc, &ecount_buf, &num);
    
    //ECB ENCRYPTION
    AES_KEY enc_key_ecb, dec_key_ecb;
    AES_set_encrypt_key(aes_key, keylength, &enc_key_ecb);
    AES_ecb_encrypt(aes_input, enc_out_ecb, &enc_key_ecb, AES_ENCRYPT);
    
    AES_set_decrypt_key(aes_key, keylength, &dec_key_ecb);
    AES_decrypt(enc_out_ecb, dec_out_ecb, &dec_key_ecb);

    
   // AES_ctr128_encrypt(aes_input, enc_out, inputslength, &enc_key, iv_enc, &ecount, AES_ENCRYPT);
    
    cout << " Original Plain Text: " << password << endl;
    
    print_data("\n Original ",aes_input, sizeof(aes_input));
    print_data("\n Encrypted ",enc_out, sizeof(enc_out));
    print_data("\n Decrypted ",dec_out, sizeof(dec_out));
    
    
    print_data("\n Originial ECB: ", aes_input, sizeof(aes_input));
    print_data("\n Encrypted ECB: ", enc_out_ecb, sizeof(enc_out_ecb));
    print_data("\n Decrypted ECB: ", dec_out_ecb, sizeof(dec_out_ecb));
    
    int selection;
    bool flag = true;
    
    while(flag){
        
        cout << "------------------------------------------------" << endl;
        cout << "--    Enter 1 to create new database          --" << endl;
        cout << "--    Enter 2 to input username and password  --" << endl;
        cout << "--    Enter 3 to retrieve password            --" << endl;
        cout << "------------------------------------------------" << endl;
        
        cin >> selection;
        
        
        if(selection == 1){
            string name;
            cout << "Specify the new database filename: ";
            cin >> name;
            createDatabase(name);
        }
        else if(selection == 2){
            bool flag1 = true;
            while(flag1){
                bool flag2;
                string name;
                cout << "Specify existing filename: ";
                cin >> name;
                flag2 = checkDatabase(dirPath + name);
                if(flag2){
                    ofstream myFile;
                    myFile.open(dirPath + name,fstream:: out | fstream::app);
                    string username;
                    string password;
                    cout << "Enter username: ";
                    cin >> username;
                    cout << "Enter password: ";
                    cin >> password;
                    user newUser = createUser(username, password);
                    ifstream iFile;
                    iFile.open(dirPath + name, ifstream:: out);
                    bool check;
                    check = checkUser(newUser, iFile);
                    if(check){
                        int encSelection;
                        cout << "------------------------------------------------" << endl;
                        cout << "--    Enter 1 for ECB                         --" << endl;
                        cout << "--    Enter 2 for CTR                         --" << endl;
                        cout << "--    Enter 3 for CBC                         --" << endl;
                        cout << "------------------------------------------------" << endl;
                        cin >> encSelection;
                        
                        //ECB SELECTION
                        if(encSelection == 1){
                            long inputslength = password.size();
                            unsigned char aes_input[password.size()];
                            for (int i = 0; i < password.size(); i++){
                                aes_input[i] = password[i];
                            }
                            
                            //ECB OUTPUT
                            unsigned char enc_out_ecb[inputslength];
                            unsigned char dec_out_ecb[inputslength];
                            memset(enc_out_ecb, 0, sizeof(enc_out_ecb));
                            memset(dec_out_ecb, 0, sizeof(dec_out_ecb));
                            
                            //ECB ENCRYPTION
                            AES_KEY enc_key_ecb, dec_key_ecb;
                            AES_set_encrypt_key(aes_key, keylength, &enc_key_ecb);
                            AES_ecb_encrypt(aes_input, enc_out_ecb, &enc_key_ecb, AES_ENCRYPT);
                            
                            AES_set_decrypt_key(aes_key, keylength, &dec_key_ecb);
                            AES_decrypt(enc_out_ecb, dec_out_ecb, &dec_key_ecb);

                            string s = data_input(enc_out_ecb, sizeof(enc_out_ecb));
                            myFile << newUser.getUser();
                            myFile << endl;
                            myFile << password;
                            myFile << endl;
                            myFile << s;
                            myFile << endl;
                            myFile << encSelection;
                            myFile << endl;
                            myFile << "###########################################";
                            myFile << endl;
                            flag1 = false;

                        }
                        //CTR SELECTION
                        else if(encSelection == 2)
                        {
                            //CTR OUTPUT
                            unsigned char enc_out_ctr[inputslength];
                            unsigned char dec_out_ctr[inputslength];
                            unsigned char ecount_buf[AES_BLOCK_SIZE];
                            unsigned int* num[AES_BLOCK_SIZE];
                            memset(enc_out_ctr, 0, sizeof(enc_out_ctr));
                            memset(dec_out_ctr, 0, sizeof(dec_out_ctr));
                            memset(ecount_buf, 0, sizeof(AES_BLOCK_SIZE));
                            memset(num, 0, sizeof(AES_BLOCK_SIZE));
                            
                            //CTR ENCRYPTION
                            AES_KEY enc_key_ctr, dec_key_ctr;
                            AES_set_encrypt_key(aes_key, keylength, &enc_key);
                            //UNABLE TO RUN
                            //AES_ctr128_encrypt(enc_out_ctr, dec_out_ctr, inputslength, &enc_key, iv_enc, &ecount_buf, &num);
                            
                            string s = data_input(enc_out_ecb, sizeof(enc_out_ecb));
                            myFile << newUser.getUser();
                            myFile << endl;
                            myFile << password;
                            myFile << endl;
                            myFile << s;
                            myFile << endl;
                            myFile << encSelection;
                            myFile << endl;
                            myFile << "###########################################";
                            myFile << endl;
                            flag1 = false;
                            
                            
                        }
                        //CBC SELECTION
                        else if(encSelection == 3)
                        {
                            long inputslength = password.size();
                            unsigned char aes_input[password.size()];
                            for (int i = 0; i < password.size(); i++){
                                aes_input[i] = password[i];
                            }
                            unsigned char iv_enc[AES_BLOCK_SIZE], iv_dec[AES_BLOCK_SIZE];
                            memcpy(iv_dec, iv_enc, AES_BLOCK_SIZE);
                        
                            unsigned char enc_out[inputslength];
                            unsigned char dec_out[inputslength];
                            unsigned char ecount_buf[inputslength];
                    
                            memset(enc_out, 0, sizeof(enc_out));
                            memset(dec_out, 0, sizeof(dec_out));
                            memset(ecount_buf, 0, sizeof(ecount_buf));
                        
                            AES_KEY enc_key, dec_key;
                            AES_set_encrypt_key(aes_key, keylength, &enc_key);
                            AES_cbc_encrypt(aes_input, enc_out, inputslength, &enc_key, iv_enc, AES_ENCRYPT);
                            AES_set_decrypt_key(aes_key, keylength, &dec_key);
                            AES_cbc_encrypt(enc_out, dec_out, inputslength, &dec_key, iv_dec, AES_DECRYPT);
                      
                            string s = data_input(enc_out, sizeof(enc_out));
                            myFile << newUser.getUser();
                            myFile << endl;
                            myFile << password;
                            myFile << endl;
                            myFile << s;
                            myFile << endl;
                            myFile << encSelection;
                            myFile << endl;
                            myFile << "###########################################";
                            myFile << endl;
                            flag1 = false;
                        }
                        
                        else{
                            cout << "INVALID SELECTION...." << endl;
                        }
                        
                    }
                    else if(!check){
                        cout << "Username taken......" << endl;
                        cout << "Try Again!" << endl;
                    }
                }
                if (!flag2){
                    cout << "Try another name: " << endl;
                }
            }
        }
        else if(selection == 3){
            string username;
            bool flag1 = true;
            while(flag1){
                bool flag2;
                string name;
                cout << "Specify existing filename: ";
                cin >> name;
                cout << "Enter username: ";
                cin >> username;
                flag2 = checkDatabase(dirPath + name);
                if(flag2){
                    ofstream myFile;
                    myFile.open(dirPath + name,fstream:: out | fstream::app);
                    ifstream iFile;
                    iFile.open(dirPath + name, ifstream:: out);
                    
                    string password = getPass(username, iFile);
                    iFile.close();
                    myFile.close();
                    
                    myFile.open(dirPath + name, fstream:: out | fstream::app);
                    iFile.open(dirPath + name, ifstream:: out);
                    
                    string encNum = getEnc(password, iFile);
                    
                    if(password != ""){
                        cout << "\nYour Password is: " << password << endl;
                        /*
                         
                        #### WASN'T ABLE TO UNENCRYPT DATA CORRECTLY...
                        #### THIS WAS THE ATTEMPTED CODE
                        if(encNum == "1"){
                            
                            unsigned char aes_input[password.size()];
                            for (int i = 0; i < password.size(); i++){
                                aes_input[i] = password[i];
                            }
                        
                            
                            unsigned char dec_out_ecb[inputslength];
                            memset(dec_out_ecb, 0, sizeof(dec_out_ecb));
                            
                            AES_KEY dec_key_ecb;
                            
                            AES_set_decrypt_key(aes_key, keylength, &dec_key_ecb);
                            AES_decrypt(aes_key, dec_out_ecb, &dec_key_ecb);
                            
                            string decrypted = data_input(dec_out_ecb, sizeof(dec_out_ecb));
                            cout << "\nPassword in plaintext: " << decrypted << endl;
                            flag1 = false;
                        }
                        else if(encNum == "2"){cout << "INVALID...."}
                        else if(encNum == "3"){
                            
                            long inputslength = password.size();
                            unsigned char aes_input[password.size()];
                            for (int i = 0; i < password.size(); i++){
                                aes_input[i] = password[i];
                            }
                            unsigned char iv_enc[AES_BLOCK_SIZE], iv_dec[AES_BLOCK_SIZE];
                            memcpy(iv_dec, iv_enc, AES_BLOCK_SIZE);
                            
                            unsigned char enc_out[inputslength];
                            unsigned char dec_out[inputslength];
                            unsigned char ecount_buf[inputslength];
                            
                            memset(enc_out, 0, sizeof(enc_out));
                            memset(dec_out, 0, sizeof(dec_out));
                            memset(ecount_buf, 0, sizeof(ecount_buf));
                            
                            AES_KEY enc_key, dec_key;
                            AES_set_encrypt_key(aes_key, keylength, &enc_key);
                            AES_cbc_encrypt(aes_input, enc_out, inputslength, &enc_key, iv_enc, AES_ENCRYPT);
                            AES_set_decrypt_key(aes_key, keylength, &dec_key);
                            AES_cbc_encrypt(enc_out, dec_out, inputslength, &dec_key, iv_dec, AES_DECRYPT);
                        }*/
                    }
                    else{
                        cout << "Username not found....." << endl;
                        flag1 = false;
                    }
                }
            }
        }
        else
        {
            cout << "Invalid Response...." << endl;
        }
        
        string answer;
        cout << "Would you like to continue?......" << endl;
        cout << "Enter y to continue: ";
        cin >> answer;

        if(answer != "y"){
            cout << "Exiting....";
            exit(0);
        }
    }
    
}

bool checkUser(user user, ifstream &myFile){
    bool flag = true;
    string username = user.getUser();
    string line;
    while(getline(myFile,line)) {
        if (line == username){
            flag = false;
        }
    }
    return flag;
}

string getPass(string username, ifstream &myFile){
    string password = "";
    string line;
    while(getline(myFile,line)) {
        if (line == username){
            getline(myFile,line);
            password = line;
        }
    }
    return password;
}

void createDatabase(string name){ofstream myFile(dirPath + name,ostream::app);}


user createUser(string username, string password){
    user newUser(username, password);
    return newUser;
}

bool checkDatabase(string name){
    ifstream myFile(name);
    if(myFile){return true;}
    else{return false;}
}

void print_data(const char *info, const void* data, int len)
{
    printf("%s : ",info);
    const unsigned char * p = (const unsigned char*)data;
    int i = 0;
    
    for (; i<len; ++i)
        printf("%02X ", *p++);
    
    printf("\n");
}


string data_input(const void* data, int len){
    stringstream s;
    const unsigned char * p = (const unsigned char*)data;
    s << std::hex;
    for (int i =0; i<len; ++i){
        s << setw(2) << setfill('0') << int(p[i]);
    }
    return s.str();
}

string getEnc(string password, ifstream &myFile){
    string encNum = "";
    string line;
    while(getline(myFile,line)){
        if(line == password){
            getline(myFile,line);
            encNum = line;
        }
    }
    return encNum;
}




