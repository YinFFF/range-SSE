#ifndef _ALGO_HMAC_H_
#define _ALGO_HMAC_H_
#include "stdafx.h"
using namespace std;

int HmacEncode(const char * algo,
	const char * key, unsigned int key_length,
	const char * input, unsigned int input_length,
	unsigned char * &output, unsigned int &output_length);

int Hash(const char * algo,
	const char * input, unsigned int input_length,
	unsigned char * &output, unsigned int &output_length);

string GGM_PRF(string &m, string &key);

int GenLeafNode(string &x, int h, unordered_map<string, int> &D_index);
int GenLeafNode2(string &x, int h);

int My_Setup(char * file_name, string &key, unordered_map<string, int> &D_user, unordered_map<string, int> &D_index);


int My_Search(string &key, unordered_map<string, int> &D_user, unordered_map<string, int> &D_index);

int Shao_Setup_Size(char * file_name, string &key, unordered_map<string, int> &D_user, unordered_map<string, int> &D_index);
int Shao_Setup_Time(char * file_name, string &key, RSA *keypair, unordered_map<string, class value_of_map> &D_user, unordered_map<string, int> &D_index);
int Shao_Search_Time();
int GenRangeCover(int KeywordBinarySize, int LeftEdge, int RightEdge, vector<pair<string, int>> &RC);

class value_of_map {
public:
    int cnt;
    char msg[2048/8];
    value_of_map(void) {
        cnt = 0;
        for (int i = 0; i < 2048 / 8; i++) {
            msg[i] = 1;
        }
    }
};

int Calculate_index_of_Shao(string &key, RSA *keypair, unsigned char * k, char *err, char *msg);
int Calculate_index(string &sub_attribute_string, class value_of_map &value, string &key, int id, unordered_map<string, int> &D_index);
#endif
