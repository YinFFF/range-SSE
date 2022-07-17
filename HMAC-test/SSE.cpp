#include "stdafx.h"
using namespace std;

int HmacEncode(const char * algo, 
		const char * key, unsigned int key_length, 
		const char * input, unsigned int input_length, 
		unsigned char * &output, unsigned int &output_length) {
	const EVP_MD * engine = NULL;
    
	if(strcmp("sha512", algo) == 0) {
		engine = EVP_sha512();
	}
	else if(strcmp("sha256", algo) == 0) {
		engine = EVP_sha256();
	}
	else if(strcmp("sha1", algo) == 0) {
		engine = EVP_sha1();
	}
	else if(strcmp("md5", algo) == 0) {
		engine = EVP_md5();
	}
	else if(strcmp("sha224", algo) == 0) {
		engine = EVP_sha224();
	}
	else if(strcmp("sha384", algo) == 0) {
		engine = EVP_sha384();
	}
    /*
	else if(strcasecmp("sha", algo) == 0) {
		engine = EVP_sha();
	}
	else if(strcasecmp("md2", algo) == 0) {
		engine = EVP_md2();
	}*/
	else {
		cout << "Algorithm " << algo << " is not supported by this program!" << endl;
		return -1;
	}

	output = (unsigned char*)malloc(EVP_MAX_MD_SIZE);
	
	HMAC_CTX *ctx = HMAC_CTX_new();
	HMAC_CTX_reset(ctx);
	HMAC_Init_ex(ctx, key, key_length, engine, NULL);
	HMAC_Update(ctx, (unsigned char*)input, input_length);	// input is OK; &input is WRONG !!!

	HMAC_Final(ctx, output, &output_length);
	HMAC_CTX_free(ctx);	

	return 0;
}


int Hash(const char * algo, const char * input, unsigned int input_length, unsigned char * &output, unsigned int &output_length) {
        EVP_MD_CTX *ctx = EVP_MD_CTX_new();
        const EVP_MD * md = EVP_get_digestbyname(algo);
        if(!md) {
                printf("Unknown message digest algorithm: %s\n", algo);
                return -1;
        }
 
        output = (unsigned char *)malloc(EVP_MAX_MD_SIZE);
        memset(output, 0, EVP_MAX_MD_SIZE);
 
        EVP_MD_CTX_init(ctx);
        EVP_DigestInit_ex(ctx, md, NULL);
        EVP_DigestUpdate(ctx, input, input_length);
        EVP_DigestFinal_ex(ctx, (unsigned char *)output, &output_length);
        EVP_MD_CTX_destroy(ctx);
 
        return 0;
}

string GGM_PRF(string &m, string &key) {
    unsigned char * temp_result = NULL;
	unsigned int temp_length = 0;
    string input = key;
    unsigned int input_length = key.size();
    int ret;
    unsigned int k;
    for (int i = 0; i < m.size(); i++) {
        k = 0x80;
        for (int j = 0; j < 8; j++, k >>= 1) {
            ret = Hash("sha512", input.c_str(), input_length, temp_result, temp_length);	
            if(0 == ret) {
                ;//cout << "Algorithm succeeded!\n" << endl;
        	}
        	else {
        		cout << "Algorithm failed!\n" << endl;
        		return "";
            }
            //for (int m = 0; m < temp_length; m++)
                //printf("%-03x ", temp_result[m]);
            //printf("\n");

            if (m[i] & k)
                input.assign((char *)temp_result + temp_length / 2 , temp_length / 2);
            else
                input.assign((char *)temp_result, temp_length / 2);

            input_length = temp_length / 2;
            //for (int m = 0; m < input_length; m++)
                //printf("%-03x ", (unsigned char)input[m]);
            free(temp_result);
            temp_length = 0;
        }
	}
    return input;
}

//int GenLeafNode(string &x, int h, unordered_map<string, int> &D_index) {
//    if (h == 0) {
//        if (D_index.find(x) == D_index.end()) {
//            ;
//        }
//        else
//            ;
//    }
//    else {
//        int ret;
//        unsigned char * temp_result = NULL;
//    	unsigned int temp_length = 0;
//        string left_child, right_child;
//        ret = Hash("sha512", x.c_str(), x.size(), temp_result, temp_length);	
//        if(0 == ret) {
//            ;//cout << "Algorithm succeeded!\n" << endl;
//    	}
//    	else {
//    		cout << "Algorithm failed!\n" << endl;
//    		return 0;
//        }
//        left_child.assign((char *)temp_result, temp_length / 2);
//        right_child.assign((char *)temp_result + temp_length / 2 , temp_length / 2);
//        GenLeafNode(left_child, h-1, D_index);
//        GenLeafNode(right_child, h-1, D_index);
//    }
//    return 1;
//}

int GenLeafNode(string &x, int h, unordered_map<string, int> &D_index){
    stack<pair<string, int>> node_stack;
    node_stack.push(make_pair(x, h));
    pair<string, int> node;
    int ret;
    unsigned char * temp_result = NULL;
	unsigned int temp_length = 0;
    string left_child, right_child;
    while (node_stack.size()) {
        node = node_stack.top();
        node_stack.pop();
        if (node.second != 0) {
            // �������Ӻ��Һ��ӵ�keyֵ
            ret = Hash("sha512", node.first.c_str(), node.first.size(), temp_result, temp_length);	
            if(0 == ret) {
                ;//cout << "Algorithm succeeded!\n" << endl;
        	}
        	else {
        		cout << "Algorithm failed!\n" << endl;
        		return 0;
            }
            left_child.assign((char *)temp_result, temp_length / 2);
            right_child.assign((char *)temp_result + temp_length / 2 , temp_length / 2);
            node_stack.push(make_pair(left_child, node.second - 1));
            node_stack.push(make_pair(right_child, node.second - 1));
            free(temp_result);
        }
        else {
			// ����Ӧ��Ҫ�� D_index �в��ϳ��� node.first || cnt, ����������ʱ�䲻�࣬ ���Լ���ÿ��Ҷ�ӽڵ�Ĺؼ���ֻ��һ��
            if (D_index.find(x) == D_index.end()) {
               ;
            }
            else
                ;
        }
    }
    return 0;
}


int GenLeafNode2(string &x, int h){
    int ret;
    unsigned char * temp_result = NULL;
	unsigned int temp_length = 0;
    string left_child, right_child;
    LARGE_INTEGER nFreq;
    LARGE_INTEGER nBeginTime;
    LARGE_INTEGER nEndTime;
    double time;
    QueryPerformanceFrequency(&nFreq);
    QueryPerformanceCounter(&nBeginTime);
    for(int i = 0; i < h; i++){
        ret = Hash("sha512", x.c_str(), x.size(), temp_result, temp_length);	
        free(temp_result);
    }
    QueryPerformanceCounter(&nEndTime);
    time = (double)(nEndTime.QuadPart-nBeginTime.QuadPart)/(double)nFreq.QuadPart;
    cout << "\n 1% time:" << time << " ";
    return 0;
}

int My_Setup(char * file_name, string &key, unordered_map<string, int> &D_user, unordered_map<string, int> &D_index){
    unsigned char k_r[32];
    string GGM_result;
    string temp_attribute;
    long attribute;
    int cnt;
    unsigned char * key_of_D = NULL;
	unsigned int length_of_D = 0;
    string string_key_of_D;
    string string_value_of_D;
    long id = 1;

    LARGE_INTEGER nFreq;
    LARGE_INTEGER nBeginTime;
    LARGE_INTEGER nEndTime;
    double time;
    QueryPerformanceFrequency(&nFreq);
    char *err = (char *)malloc(130);

    // ��ʼ����Կ: k_r
    RAND_bytes(k_r, 32);
    key.assign((char *)k_r, 32);

    // ���ļ�
    fstream dataset;
    dataset.open(file_name, ios::in | ios::binary);
    QueryPerformanceCounter(&nBeginTime);
    while (!dataset.eof())
    {
        // temp_attribute ֱ�Ӷ�ȡ�ı���ʮ��������
        getline(dataset, temp_attribute);
        if (temp_attribute.size() == 0)
            break;
        // ��ʮ�������ִ��ַ�����ת��Ϊint��
        attribute = atoi(temp_attribute.c_str());
        //printf("attribute: %d\n", attribute);
        // ��ʱ temp_attribute �д�ŵ�������, �������ַ���(Ӧ����4���ֽ�)
        temp_attribute.assign((const char*)&attribute, sizeof(attribute));
        // ���� D_user �е� cnt ֵ
        if (D_user.find(temp_attribute) == D_user.end())
            cnt = 0;
        else {
            cnt = D_user[temp_attribute];
            cnt++;
        }
        // ���� GGM-PRF ֵ
        GGM_result = GGM_PRF(temp_attribute, key);
        // ���� D_index �� key = H(k||cnt)
        HmacEncode("sha256", GGM_result.c_str(), GGM_result.size(), (const char*)&cnt, sizeof(int), key_of_D, length_of_D);
        string_key_of_D.assign((char *)key_of_D, length_of_D);
        D_index[string_key_of_D] = ((*(int *)key_of_D) ^ id);
        free(key_of_D);
        D_user[temp_attribute] = cnt;
        id++;
    }
    QueryPerformanceCounter(&nEndTime);
    time = (double)(nEndTime.QuadPart-nBeginTime.QuadPart)/(double)nFreq.QuadPart;
    dataset.close();
    cout << "\n bukect number of D_index:" << D_index.bucket_count()*32/1024;
    cout << "\n bukect number of D_user:" << D_user.bucket_count()/1024;
	cout << "\n time:" << time << endl;
    return 0;
}

// RC.first �Ǵ���ڵ�·���Ķ����ƴ��� RC.second �Ǹ߶�
int GenRangeCover(int KeywordBinarySize, int LeftEdge, int RightEdge, vector<pair<string, int>> &RC) {
	vector<pair<string, int>> tempRC;
	tempRC.push_back(pair<string, int>("0", KeywordBinarySize - 1));
	tempRC.push_back(pair<string, int>("1", KeywordBinarySize - 1));
	
	//string ad(5, '1');
	//string test(20, '0');
	//test.replace(0, ad.size(), ad);
	//test.assign(10, '0');
	while (tempRC.size()) {
		pair<string, int> cur = tempRC.back();
		tempRC.pop_back();
		long curLeftEdge = stoi(cur.first, 0, 2) << cur.second;
		long curRightEdge = ((stoi(cur.first, 0, 2) + 1) << cur.second) - 1;
		if (LeftEdge <= curLeftEdge && RightEdge >= curRightEdge)
			RC.push_back(cur);
		else if (max(curLeftEdge, LeftEdge) <= min(curRightEdge, RightEdge)) {
			tempRC.push_back(pair<string, int>(cur.first + '0', cur.second - 1));
			tempRC.push_back(pair<string, int>(cur.first + '1', cur.second - 1));
		}
	}
	return 0;
}

int My_Search(string &key, unordered_map<string, int> &D_user, unordered_map<string, int> &D_index) {
    LARGE_INTEGER nFreq;
    LARGE_INTEGER nBeginTime;
    LARGE_INTEGER nEndTime;
    double time;
    QueryPerformanceFrequency(&nFreq);
    QueryPerformanceCounter(&nBeginTime);
    GenLeafNode(key, 21, D_index);
    QueryPerformanceCounter(&nEndTime);
    time = (double)(nEndTime.QuadPart-nBeginTime.QuadPart)/(double)nFreq.QuadPart;
    cout << "\n 0.1% time:" << time;


    QueryPerformanceFrequency(&nFreq);
    QueryPerformanceCounter(&nBeginTime);
    GenLeafNode(key, 22, D_index);
    QueryPerformanceCounter(&nEndTime);
    time = (double)(nEndTime.QuadPart-nBeginTime.QuadPart)/(double)nFreq.QuadPart;
    cout << "\n 0.2% time:" << time;


    QueryPerformanceFrequency(&nFreq);
    QueryPerformanceCounter(&nBeginTime);
    GenLeafNode(key, 21, D_index);
    GenLeafNode(key, 22, D_index);
    QueryPerformanceCounter(&nEndTime);
    time = (double)(nEndTime.QuadPart-nBeginTime.QuadPart)/(double)nFreq.QuadPart;
    cout << "\n 0.3% time:" << time;
        
    QueryPerformanceFrequency(&nFreq);
    QueryPerformanceCounter(&nBeginTime);
    GenLeafNode(key, 23, D_index);
    QueryPerformanceCounter(&nEndTime);
    time = (double)(nEndTime.QuadPart-nBeginTime.QuadPart)/(double)nFreq.QuadPart;
    cout << "\n 0.4% time:" << time;

    QueryPerformanceFrequency(&nFreq);
    QueryPerformanceCounter(&nBeginTime);
    GenLeafNode(key, 21, D_index);
    GenLeafNode(key, 23, D_index);
    QueryPerformanceCounter(&nEndTime);
    time = (double)(nEndTime.QuadPart-nBeginTime.QuadPart)/(double)nFreq.QuadPart;
    cout << "\n 0.5% time:" << time;

    QueryPerformanceFrequency(&nFreq);
    QueryPerformanceCounter(&nBeginTime);
    GenLeafNode(key, 22, D_index);
    GenLeafNode(key, 23, D_index);
    QueryPerformanceCounter(&nEndTime);
    time = (double)(nEndTime.QuadPart-nBeginTime.QuadPart)/(double)nFreq.QuadPart;
    cout << "\n 0.6% time:" << time;

    QueryPerformanceFrequency(&nFreq);
    QueryPerformanceCounter(&nBeginTime);
    GenLeafNode(key, 21, D_index);
    GenLeafNode(key, 22, D_index);
    GenLeafNode(key, 23, D_index);
    QueryPerformanceCounter(&nEndTime);
    time = (double)(nEndTime.QuadPart-nBeginTime.QuadPart)/(double)nFreq.QuadPart;
    cout << "\n 0.7% time:" << time;

    QueryPerformanceFrequency(&nFreq);
    QueryPerformanceCounter(&nBeginTime);
    GenLeafNode(key, 24, D_index);
    QueryPerformanceCounter(&nEndTime);
    time = (double)(nEndTime.QuadPart-nBeginTime.QuadPart)/(double)nFreq.QuadPart;
    cout << "\n 0.8% time:" << time;

    QueryPerformanceFrequency(&nFreq);
    QueryPerformanceCounter(&nBeginTime);
    GenLeafNode(key, 21, D_index);
    GenLeafNode(key, 24, D_index);
    QueryPerformanceCounter(&nEndTime);
    time = (double)(nEndTime.QuadPart-nBeginTime.QuadPart)/(double)nFreq.QuadPart;
    cout << "\n 0.9% time:" << time;

    QueryPerformanceFrequency(&nFreq);
    QueryPerformanceCounter(&nBeginTime);
    GenLeafNode(key, 22, D_index);
    GenLeafNode(key, 24, D_index);
    QueryPerformanceCounter(&nEndTime);
    time = (double)(nEndTime.QuadPart-nBeginTime.QuadPart)/(double)nFreq.QuadPart;
    cout << "\n 1% time:" << time;
    return 0;
}


int Shao_Setup_Size(char * file_name, string &key, unordered_map<string, int> &D_user, unordered_map<string, int> &D_index) {
    unsigned char k[32];
    unsigned char k_rsa[32];
    char attribute_char[32] = { 0 };
    string attribute_string;
    long attribute_int;
    long id = 1;
    long count = 0;
    char *err = (char *)malloc(130);
    LARGE_INTEGER nFreq;
    LARGE_INTEGER nBeginTime;
    LARGE_INTEGER nEndTime;
    double time;


    // ���ļ�
    fstream dataset;
    dataset.open(file_name, ios::in | ios::binary);
    QueryPerformanceCounter(&nBeginTime);
    while (!dataset.eof())
    {
        // temp_attribute ֱ�Ӷ�ȡ�ı���ʮ��������
        dataset.getline(attribute_char, sizeof(attribute_char));
        if (strlen(attribute_char) == 0)
            break;
        // ��ʮ�������ִ��ַ�����ת��Ϊint��
        attribute_int = atoi(attribute_char);
        // ��ʱ attribute_char �д�ŵ��Ƕ������ַ���
        _itoa_s(attribute_int, attribute_char, 2);
        // ���������ַ���ǰ�0
        attribute_string.assign(32 - strlen(attribute_char), '0');
        attribute_string.append(attribute_char, strlen(attribute_char));

        string sub_attribute_string;
        for (int i = attribute_string.size(); i > 0; i--)
        {
            // ����� path �ϵ�ֵ 
            sub_attribute_string = attribute_string.substr(0, i);
            // ���� D_user �е� cnt ֵ
            if (D_user.find(sub_attribute_string) == D_user.end()) {
                D_user[sub_attribute_string] = 1;
            }
            else {
                count++;
            }
        }
        if (id % 500000 == 0){
            printf("id: %d; \t number of D_user: %d; \t count: %ld\n", id, D_user.bucket_count(), count);
        }
        id++;
        //cout << id << "  ";
    }
    dataset.close();
    cout << "\n count : " << count;
    return 0;
}


int Shao_Setup_Time(char * file_name, string &key, RSA *keypair,
					unordered_map<string, class value_of_map> &D_user, 
					unordered_map<string, int> &D_index) {
    unsigned char k[32];
    unsigned char k_rsa[32];
    char attribute_char[32] = { 0 };
    string attribute_string;
    long attribute_int;
    long id = 1;
    char *err = (char *)malloc(130);
    LARGE_INTEGER nFreq;
    LARGE_INTEGER nBeginTime;
    LARGE_INTEGER nEndTime;
    double time;
    QueryPerformanceFrequency(&nFreq);

    // ��ʼ����Կ: keypair, key
    //RSA *keypair = RSA_generate_key(2048, 3, NULL, NULL);
    RAND_bytes(k, 32);
    key.assign((char *)k, 32);

    // ���ļ�
    fstream dataset;
    dataset.open(file_name, ios::in | ios::binary);
    QueryPerformanceCounter(&nBeginTime);
    while (!dataset.eof())
    {
        // temp_attribute ֱ�Ӷ�ȡ�ı���ʮ��������
        dataset.getline(attribute_char, sizeof(attribute_char));
        if (strlen(attribute_char) == 0)
            break;
        // ��ʮ�������ִ��ַ�����ת��Ϊint��
        attribute_int = atoi(attribute_char);
        // ��ʱ attribute_char �д�ŵ��Ƕ������ַ���
        _itoa_s(attribute_int, attribute_char, 2);
        // ���������ַ���ǰ�0
        attribute_string.assign(32 - strlen(attribute_char), '0');
        attribute_string.append(attribute_char, strlen(attribute_char));

        string sub_attribute_string;
        value_of_map value_of_D_user;
		// ��ȡ attribute_string ������ǰ׺�Ӵ� sub_attribute_string, ������Ϊ�ؼ��ֲ��� D_index ��
        for (int i = attribute_string.size(); i > 0; i--)
        {
            // ����� path �ϵ��Ӵ� 
            sub_attribute_string = attribute_string.substr(0, i);
            // ���� D_user �е� cnt ֵ
            if (D_user.find(sub_attribute_string) == D_user.end()) {
                value_of_D_user.cnt = 0;
                // �����ֵ�� msg
                //RAND_bytes((unsigned char*)value_of_D_user.msg, 2048/8);
            } else {
                value_of_D_user.cnt = D_user[sub_attribute_string].cnt + 1;
                if((RSA_public_encrypt(2048/8, (unsigned char*)D_user[sub_attribute_string].msg, 
                    (unsigned char*)value_of_D_user.msg, keypair, RSA_NO_PADDING)) == -1){
                    printf("RSA encrypt err\n");
                    ERR_load_crypto_strings();
                    ERR_error_string(ERR_get_error(), err);
                    fprintf(stderr, "Error encrypting message: %s\n", err);
                }
            }
            // ���� (l,v), ������ D_index
            Calculate_index(sub_attribute_string, value_of_D_user, key, id, D_index);
            // update D_user
            D_user[sub_attribute_string] = value_of_D_user;
        }
        id++;
        //printf("%d\t", id);
    }
    dataset.close();
    QueryPerformanceCounter(&nEndTime);
    time = (double)(nEndTime.QuadPart-nBeginTime.QuadPart)/(double)nFreq.QuadPart;
    cout << "\n bukect size of D_index:" << D_index.bucket_count();//*32/1024;
    cout << "\n bukect size of D_user:" << D_user.bucket_count();// / 1024;
    cout << "\n time:" << time;
    return 0;
}


int Shao_Search_Time() {
    string key;
    LARGE_INTEGER nFreq;
    LARGE_INTEGER nBeginTime;
    LARGE_INTEGER nEndTime;
    QueryPerformanceFrequency(&nFreq);
    char *err = (char *)malloc(130);
    unsigned char k[32];
    double time;

    // ��ʼ��k
    RSA *keypair = RSA_generate_key(2048, 3, NULL, NULL);
    RAND_bytes(k, 32);
    key.assign((char *)k, 32);
    class value_of_map input;

	// ����records���ȷֲ��� ֵ���ϣ� ��ô 0.1% �ķ�Χ��ѯ��Ӧ�� 6000000 * 0.1% = 6000 �ļ�¼
    for (int j = 1; j <= 10; j++) {
        QueryPerformanceCounter(&nBeginTime);
        for (int i = 1; i < 6000*j; i++) {
            Calculate_index_of_Shao(key, keypair, k, err, input.msg);
        }
        QueryPerformanceCounter(&nEndTime);
        time = (double)(nEndTime.QuadPart-nBeginTime.QuadPart)/(double)nFreq.QuadPart;
        printf("%d : %f\n", j, time);
    }
    free(err);
    return 0;
}

int Calculate_index_of_Shao(string &key, RSA *keypair, unsigned char * k, char *err, char *msg){
    unsigned char * Hmac_output1 = NULL;
	unsigned int len_of_Hmac_output = 0;
    if ((RSA_public_encrypt(2048 / 8, (unsigned char*)msg,
        (unsigned char*)msg, keypair, RSA_NO_PADDING)) == -1) {
        printf("RSA encrypt err\n");
        ERR_load_crypto_strings();
        ERR_error_string(ERR_get_error(), err);
        fprintf(stderr, "Error encrypting message: %s\n", err);
    }
    HmacEncode("sha256", key.c_str(), key.size(), (const char*)msg, 32,
        Hmac_output1, len_of_Hmac_output);
    free(Hmac_output1);
    return 0;
}

// sub_attribute_string: �����Ĺؼ���(С��32���ֽ�)
// rsa_msg: ��ǰ�ؼ��ֵ� rsa ֵ (256 byte)
// key: PRF��key
// id: D_index ��value
int Calculate_index(string &sub_attribute_string, class value_of_map &value, string &key, int id, unordered_map<string, int> &D_index) {
    unsigned char * Hmac_output1 = NULL;
    unsigned char * Hmac_output2 = NULL;
	unsigned int len_of_Hmac_output = 0;
    string key_of_D_index;
    HmacEncode("sha256", key.c_str(), key.size(), (const char*)sub_attribute_string.c_str(), sub_attribute_string.size(),
        Hmac_output1, len_of_Hmac_output);
    HmacEncode("sha256", (const char*)Hmac_output1, len_of_Hmac_output, value.msg, 256, Hmac_output2, len_of_Hmac_output);
    key_of_D_index.assign((char*)Hmac_output2, len_of_Hmac_output);
    D_index[key_of_D_index] = (*(int *)Hmac_output2) ^ id;
    free(Hmac_output1);
    free(Hmac_output2);
    return 0;
}