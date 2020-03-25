#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <gmpxx.h>
#include <gmp.h>
#include <vector>

using namespace std;

u_int32_t rot(u_int32_t ac , int l)
{
	l = l%32;
	return (ac << l) | (ac >> (32-l));
}

void quarteround(u_int32_t * state, u_int32_t a, u_int32_t b , u_int32_t c, u_int32_t d )
{
    state[a] += state[b]; state[d] ^=state[a]; state[d] = rot(state[d],16);
    state[c] += state[d]; state[b] ^=state[c]; state[b] = rot(state[b],12);
    state[a] += state[b]; state[d] ^=state[a]; state[d] = rot(state[d],8);
    state[c] += state[d]; state[b] ^=state[c]; state[b] = rot(state[b],7);
}

void print_state(u_int32_t * state)
{
    for(int i=0; i<4;i++)
    {
        for(int j=0; j<4;j++)
        {
            cout<<setfill('0') << setw(8) << right << hex<<state[4*i+j]<<" ";
        }
        cout<<"\n";
    }
}

void serialize(u_int32_t * state, u_int8_t * out)
{
    for(int i=0; i<16; i++)
    {
        for(int j=0; j<4; j++)
            out[4*i+j] = (state[i] >> (8*j)) & 0xff ;
    }
}

void chacha20_block(u_int32_t * key, u_int32_t counter, u_int32_t * nonce, u_int8_t * out)
{
    u_int32_t state[16];
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    copy(key, key+8, state+4 );
    state[12] = counter;
    copy(nonce, nonce +3, state+13);

    u_int32_t working_state[16];
    copy(state, state+16, working_state);

    for(int i=0; i<10;i++)
    {
        quarteround(working_state, 0,4,8,12);
        quarteround(working_state, 1,5,9,13);
        quarteround(working_state, 2,6,10,14);
        quarteround(working_state, 3,7,11,15);
        quarteround(working_state, 0,5,10,15);
        quarteround(working_state, 1,6,11,12);
        quarteround(working_state, 2,7,8,13);
        quarteround(working_state, 3,4,9,14);
    }

    for(int i=0; i<16;i++)
        state[i] += working_state[i];

    serialize(state,out);
}


void chacha20_encrypt(u_int32_t * key, u_int32_t counter, u_int32_t * nonce, u_int8_t * plaintext, u_int64_t mlength, u_int8_t * encrypted_message)
{
    u_int64_t nbBlocks = mlength/64;
    u_int8_t key_stream [64];

    for(u_int64_t j=0; j<nbBlocks; j++)
    {
        chacha20_block(key, counter + j, nonce, key_stream);
        for(u_int64_t i=j*64; i<(j+1)*64;i++)
            encrypted_message[i] = plaintext[i] ^ key_stream[i%64]; 
    }
    if(mlength%64 !=0)
    {
        u_int64_t j = mlength/64;
        chacha20_block(key, counter + j, nonce, key_stream);
        for(u_int64_t i=j*64; i<mlength;i++)
            encrypted_message[i] = plaintext[i] ^ key_stream[i%64];
    }
}

void clamp(u_int8_t * r)
{
    r[3] &= 15;
    r[7] &= 15;
    r[11] &= 15;
    r[15] &= 15;
    r[4] &= 252;
    r[8] &= 252;
    r[12] &= 252;
}

void poly1305(u_int8_t * key, u_int8_t * message, u_int64_t mlength, u_int8_t * out)
{
    u_int8_t r_tab[16];
    copy(key,key+16,r_tab);
    clamp(r_tab);

    mpz_t r;
    mpz_init (r);
    mpz_import (r, 16, -1, sizeof(r_tab[0]), 0, 0, r_tab);

    mpz_t s;
    mpz_init (s);
    mpz_import (s, 16, -1, sizeof(key[16]), 0, 0, key+16);

    mpz_t p;
    mpz_init(p);
    mpz_set_str(p,"3fffffffffffffffffffffffffffffffb",16);

    mpz_t n;
    mpz_init(n);

    mpz_t a;
    mpz_init(a);

    u_int64_t nbBlocks = mlength/16;
    u_int8_t messagesBytes[17];
    messagesBytes[16] = 0x01;
    for(u_int64_t i=0; i<nbBlocks; i++)
    {
        copy(message+i*16, message +(i+1)*16, messagesBytes);
        mpz_import (n, 17, -1, sizeof(messagesBytes[0]), 0, 0, messagesBytes);
        mpz_add(a,a,n);      
        mpz_mul(a,r,a);
        mpz_mod(a,a,p);
    }
    if(mlength%16 !=0)
    {
        messagesBytes[mlength%16] = 0x01;
        copy(message+nbBlocks*16, message + mlength, messagesBytes);
        mpz_import (n, mlength%16+1, -1, sizeof(messagesBytes[0]), 0, 0, messagesBytes);
        mpz_add(a,a,n);
        mpz_mul(a,r,a);
        mpz_mod(a,a,p);
    }

    mpz_add(a,a,s);
    size_t countp = 0;
    mpz_export(out, &countp, -1, 1, 1, 0, a);


}

void poly1305_key_gen(u_int32_t * key, u_int32_t * nonce, u_int8_t * out)
{
    int counter = 0;
    u_int8_t out_block[64];
    chacha20_block(key, counter, nonce, out_block);
    copy(out_block, out_block+32, out);
}

void num_to_8_le_bytes(u_int64_t ac, u_int8_t * out)
{
    for(int i=0; i<8;i++)
        out[i] = (ac>>(8*i)) & 0xff;
}

void chacha20_aead_encrypt(u_int8_t * aad, u_int64_t alength, u_int32_t * key, u_int32_t *  iv, u_int32_t constant, u_int8_t * plaintext, u_int64_t mlength)
{
    u_int32_t nonce[3];
    nonce[0] = constant;
    copy(iv,iv+2, nonce +1);

    u_int8_t otk[32];
    poly1305_key_gen(key, nonce, otk);

    u_int8_t ciphertext[mlength];
    chacha20_encrypt(key, 1, nonce, plaintext, mlength, ciphertext);

    int aadpad = 16 - alength%16;
    int cipherpad = 16 - mlength%16;
    u_int64_t total_length = aadpad + alength + mlength +cipherpad + 16;
    u_int8_t mac_data[total_length];
    memset(mac_data,0,total_length);
    copy(aad,aad+alength, mac_data);
    copy(ciphertext,ciphertext+mlength,mac_data + aadpad +alength);
    num_to_8_le_bytes(alength, mac_data + aadpad + alength + mlength +cipherpad);
    num_to_8_le_bytes(mlength, mac_data + aadpad + alength + mlength +cipherpad + 8);
    
    u_int8_t tag[16];
    poly1305(otk,mac_data,total_length,tag);

    cout<<"Cipher :\n";
    for(u_int64_t i=0; i< mlength;i++)
    {
        cout<<setfill('0')<<setw(2)<<hex<<(int)(ciphertext[i] & 0xff)<<" ";
        if(i%16==15)
            cout<<"\n";
    }
    cout<<"\n";

    cout<<"Tag :\n";
    for(int i=0; i< 16;i++)
    {
        cout<<setfill('0')<<setw(2)<<hex<<(int)(tag[i] & 0xff)<<" ";
        if(i%16==15)
            cout<<"\n";
    }
}

//Adapted from stackoverflow
//https://stackoverflow.com/questions/12505077/take-two-hex-characters-from-file-and-store-as-a-char-with-associated-hex-value
void readInt(istream & file, u_int32_t & out)
{
    char* buff = new char[3];
    stringstream ss_buff;
    int ac;
    for(int i=0; i<4; i++)
    {
        file.get(buff, 3);
        ss_buff.seekp(0); //VERY important lines
        ss_buff.seekg(0); //VERY important lines
        ss_buff.write(buff, 2);
        ss_buff >> std::hex >> ac;
        out += ac<<(8*i);
    }   
}

void readAad(istream & file, vector<u_int8_t> & out)
{
    char* buff = new char[3];
    stringstream ss_buff;
    int ac;

    while(file.get(buff, 3).gcount() ==2){
        ss_buff.seekp(0); //VERY important lines
        ss_buff.seekg(0); //VERY important lines
        ss_buff.write(buff, 2);
        ss_buff >> std::hex >> ac;
        out.push_back(ac);
    }   
}


int main (int argc, char * argv[]) {

    if(argc !=2)
    {
        cout<<"Usage is chacha20 yourkey.key"<<endl;
        return 1;
    }

    ifstream keyFile;
    keyFile.open(argv[1]);
    if (!keyFile) {
        cout << "Unable to open key file"<<endl;
        return 1;
    }
    u_int32_t iv[2] = {0};
    u_int32_t constant =0;
    u_int32_t key[8] = {0};
    vector <u_int8_t> aad;

    readInt(keyFile, constant);
    keyFile.get();
    for(int i=0; i<2; i++)
        readInt(keyFile, iv[i]);
    keyFile.get();
    for(int i=0; i<8; i++)
        readInt(keyFile, key[i]);
    keyFile.get();  
    readAad(keyFile, aad);
  
    vector<u_int8_t> input;
    char c;
	while (cin.get(c))
	{
		input.push_back(c);
	}

    u_int8_t aadAar[aad.size()];
    copy(aad.begin(),aad.end(),aadAar);
    u_int8_t plaintext[input.size()];
    copy(input.begin(), input.end(), plaintext);

    chacha20_aead_encrypt(aadAar,aad.size(),key,iv,constant,plaintext,input.size());
}