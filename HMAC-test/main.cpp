// HMAC-test.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
using namespace std;

void TestUpdate(string &key, unordered_map<string, int> &D_user, 
				unordered_map<string, int> &D_index) {
    LARGE_INTEGER nFreq;
    LARGE_INTEGER nBeginTime;
    LARGE_INTEGER nEndTime;
    double user_time = 0, server_time = 0;
    QueryPerformanceFrequency(&nFreq);

	string temp_attribute;
	long updated_attribute = 178748891;
	long updated_id = 6000001;
	int test_count = 10000;
	
	for (int i = 0; i < test_count; i++) {
		updated_attribute++;
		updated_id++;

		QueryPerformanceCounter(&nBeginTime);
		temp_attribute.assign((const char*)&updated_attribute, sizeof(updated_attribute));
		int cnt;

		if (D_user.find(temp_attribute) == D_user.end())
			cnt = 0;
		else {
			cnt = D_user[temp_attribute];
			cnt++;
		}
		D_user[temp_attribute] = cnt;

		// 计算 GGM-PRF 值
		string GGM_result = GGM_PRF(temp_attribute, key);

		// 计算 D_index 的 key = H(k||cnt)
		unsigned char* key_of_D = NULL;
		unsigned int length_of_D = 0;
		HmacEncode("sha256", GGM_result.c_str(), GGM_result.size(),
			(const char*)&cnt, sizeof(int), key_of_D, length_of_D);
		string string_key_of_D;
		string_key_of_D.assign((char *)key_of_D, length_of_D);
		QueryPerformanceCounter(&nEndTime);
		user_time += (double)(nEndTime.QuadPart - nBeginTime.QuadPart) / (double)nFreq.QuadPart;

		QueryPerformanceCounter(&nBeginTime);
		// 插入 D_index
		D_index[string_key_of_D] = ((*(int *)key_of_D) ^ updated_id);
		QueryPerformanceCounter(&nEndTime);
		server_time += (double)(nEndTime.QuadPart - nBeginTime.QuadPart) / (double)nFreq.QuadPart;

		free(key_of_D);
	}

	cout << "user_time:" << user_time / test_count << endl;
	cout << "server_time:" << server_time / test_count << endl;
}

void TestUpdateShao(string &key, RSA * keypair, unordered_map<string, class value_of_map> &D_user,
	unordered_map<string, int> &D_index) {

    LARGE_INTEGER nFreq;
    LARGE_INTEGER nBeginTime;
    LARGE_INTEGER nEndTime;
    double user_time = 0, server_time = 0;

	//unordered_map<string, int> D_user_test;

    QueryPerformanceFrequency(&nFreq);
	string temp_attribute;
	long updated_attribute = 178748891;
	long updated_id = 6000001;
	int test_count = 10000;
	char attribute_char[32] = { 0 };
	string attribute_string;
    char *err = (char *)malloc(130);
	int server_insert_count = 0;
	
	for (int i = 0; i < test_count; i++) {
		updated_attribute++;
		updated_id++;

		_itoa_s(updated_attribute, attribute_char, 2);
		attribute_string.assign(32 - strlen(attribute_char), '0');
		attribute_string.append(attribute_char, strlen(attribute_char));
		
		string sub_attribute_string;
		value_of_map value_of_D_user;
		for (int i = attribute_string.size(); i > 0; i--)
		{
			QueryPerformanceCounter(&nBeginTime);
			// 计算出 path 上的子串 
			sub_attribute_string = attribute_string.substr(0, i);
			// 更新 D_user 中的 cnt 值
			if (D_user.find(sub_attribute_string) == D_user.end()) {
				value_of_D_user.cnt = 0;
				// 赋随机值给 msg
				//RAND_bytes((unsigned char*)value_of_D_user.msg, 2048/8);
			}
			else {
				value_of_D_user.cnt = D_user[sub_attribute_string].cnt + 1;
				if ((RSA_public_encrypt(2048 / 8, (unsigned char*)D_user[sub_attribute_string].msg,
					(unsigned char*)value_of_D_user.msg, keypair, RSA_NO_PADDING)) == -1) {
					printf("RSA encrypt err\n");
					ERR_load_crypto_strings();
					ERR_error_string(ERR_get_error(), err);
					fprintf(stderr, "Error encrypting message: %s\n", err);
				}
			}
			// 计算 (l,v), 并插入 D_index
			Calculate_index(sub_attribute_string, value_of_D_user, key, updated_id, D_index);
			QueryPerformanceCounter(&nEndTime);
			user_time += (double)(nEndTime.QuadPart - nBeginTime.QuadPart) / (double)nFreq.QuadPart;

			// update D_user
			QueryPerformanceCounter(&nBeginTime);
			D_user[sub_attribute_string] = value_of_D_user;
			//D_user_test[sub_attribute_string] = 1;
			QueryPerformanceCounter(&nEndTime);
			server_insert_count++;
			server_time += (double)(nEndTime.QuadPart - nBeginTime.QuadPart) / (double)nFreq.QuadPart;
		}
	}
	cout << endl;
	cout << "user_time:" << user_time / test_count << endl;
	cout << "server_time:" << server_time / test_count << endl;
	cout << "server_insert_count:" << server_insert_count << endl;
}

void TestGenTrapdoor() {
	vector<pair<string, int>> RC;
	int keywordLen, leftEdge;// , rightEdge = 4;

    LARGE_INTEGER nFreq;
    LARGE_INTEGER nBeginTime;
    LARGE_INTEGER nEndTime;
    QueryPerformanceFrequency(&nFreq);

	ofstream outfile;
	outfile.open("Test_data.txt");

	//for (double j = 1; j <= 9; j += 1) {
	for (int rightEdge = 1; rightEdge <= pow(2, 22); rightEdge += pow(2, 10)) {
		double time;
		double time_all = 0;
		keywordLen = 32;
		leftEdge = 0;
		//rightEdge = (double)j/1000 * pow(2, 32);
		int test_count = 1000;
		int average_RC_size = 0;
		for (int i = 0; i < test_count; i++) {
			//cout << "keywordLen, leftEdge, rightEdge:";
			//cin >> keywordLen;
			//cin >> leftEdge;
			//cin >> rightEdge;

			//if (keywordLen == 0) { break; }

			QueryPerformanceCounter(&nBeginTime);
			GenRangeCover(keywordLen, leftEdge + i, rightEdge + i, RC);
			QueryPerformanceCounter(&nEndTime);
			time = (double)(nEndTime.QuadPart - nBeginTime.QuadPart) / (double)nFreq.QuadPart;
			time_all += time;
			//cout << "time: " << time * 1000  << "msec" << endl;
			//cout << "RC.size(): " << RC.size() << endl;
			average_RC_size += RC.size();

			//for (int i = 0; i < RC.size(); i++) {
			//	cout << RC[i].first << ", " << RC[i].second << endl;
			//}

			RC.clear();
		}
		//cout << "average_RC_size:" << average_RC_size/test_count << endl;
		//cout << " percentage:" << (double)j/1000 <<  ", time : " << 1000 * time_all / test_count << endl;
		//cout << " percentage:" << (double)rightEdge/(4 * pow(10, 9)) <<  ", time : " << 1000 * time_all / test_count << endl;
		cout <<  rightEdge << "    " << 1000 * time_all / test_count << endl;
		//rightEdge *= 10;
		outfile << rightEdge << "   " << 1000 * time_all / test_count << endl;
	}
	outfile.close();
}
int main(int argc, char * argv[])
{
    //unordered_map<string, int>  D_index;
    //unordered_map<string, class value_of_map>  D_user;
	TestGenTrapdoor();
    //unordered_map<string, int> D_user;
	//string key;
    //My_Setup("1000000_data", key, D_user, D_index);
	//TestUpdate(key, D_user, D_index);
    //D_index.clear();
 //   My_Setup("2000000_data", key, D_user, D_index);
	//TestUpdate(key, D_user, D_index);
 //   D_index.clear();
 //   My_Setup("3000000_data", key, D_user, D_index);
	//TestUpdate(key, D_user, D_index);
 //   D_index.clear();
 //   My_Setup("4000000_data", key, D_user, D_index);
	//TestUpdate(key, D_user, D_index);
 //   D_index.clear();
 //   My_Setup("5000000_data", key, D_user, D_index);
	//TestUpdate(key, D_user, D_index);
 //   D_index.clear();
 //   My_Setup("6000000_data", key, D_user, D_index);
	//TestUpdate(key, D_user, D_index);
 //   D_index.clear();
	/*
    for (int i = 1; i < 11; i++) {
        GenLeafNode2(key, i*pow(2,22));
    }*/
	/*
    string key;
    RSA *keypair = RSA_generate_key(2048, 3, NULL, NULL);
	
	for (int i = 0; i < 5; i++) {
		Shao_Setup_Time("1000000_data", key, keypair, D_user, D_index);
		TestUpdateShao(key, keypair, D_user, D_index);
		D_index.clear();
		D_user.clear();
	}

	free(keypair);
	*/
    //Shao_Search_Time();

   // RSA *keypair = RSA_generate_key(2048, 3, NULL, NULL);

   // char msg[256] = { 0 };

    system("pause");
	return 0;
}

    
/*
rocksdb::DB* db;
    rocksdb::Options options;
    string num = "0";
    string count;
    string value;
    options.create_if_missing = true;
    rocksdb::Status status = rocksdb::DB::Open(options, "test", &db);
    assert(status.ok());
    for (int i = 0; i < 100; i++) {
        status = db->Delete(rocksdb::WriteOptions(), "123");
        status = db->Put(rocksdb::WriteOptions(), "123", num);

        num.append(1, '1');
    }
    //status = db->Put(rocksdb::WriteOptions(), "123", "asdasdffasdf");
    status = db->Get(rocksdb::ReadOptions(), "123", &value);
    //assert(status.ok());
    db->GetProperty("rocksdb.estimate-num-keys", &count);
    assert(status.ok());
    cout << "num:" << count << endl;
    cout << value;
*/