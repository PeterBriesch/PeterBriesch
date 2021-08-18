#include <iostream>
#include <fstream>
#include <cstring>
#include <algorithm>
#include <cryptopp/filters.h>
#include <cryptopp/hex.h>
#include <cryptopp/sha.h>
#include <cryptopp/files.h>
#include "json.hpp"

using namespace CryptoPP;
using json = nlohmann::json;
using namespace std;

string rotation(string srcdigest, string datadigest, string outdigest, int *x, string y, string sData, string sSrc){

    //for printing
    HexEncoder encoder(new FileSink(cout));
    
    
    // initial variable decleration
    SHA256 hash;
    const string src = srcdigest;
    const string data = datadigest;
    string concat;
    string outhash;
    string compare;
    int nonce = *x;
    string target = y;
    transform(target.begin(), target.end(), target.begin(), ::toupper);
    string s1 ,s2, s3;

    StringSource(outdigest, true, new HexEncoder(new StringSink(compare)));
    
    //compare whether the first few value of the hash match the target
    while (compare.substr(0, target.length()) != target){
        s1 = "";
        s2 = "";
        outhash = "";
        StringSource(src, true, new HexEncoder(new StringSink(s1)));
        StringSource(data, true, new HexEncoder(new StringSink(s2)));

        concat = s1 + s2 + to_string(nonce);
        
        /* cout << "";
        StringSource(concat, true, new Redirector(encoder));
        cout << endl; */
        

        //hash sourcehash + datahash + nonce
        StringSource(concat, true, new HashFilter(hash, new StringSink(outhash)));

        /* cout << "";
        StringSource(outhash, true, new Redirector(encoder));
        cout << endl; */

        //increment nonce
        nonce++;
        //update comparer
        compare = "";
        StringSource(outhash, true, new HexEncoder(new StringSink(compare)));
        //cout << compare << endl;
    } 

    s2 = "";
    StringSource(data, true, new HexEncoder(new StringSink(s2)));
    s3 = "";
    StringSource(outhash, true, new HexEncoder(new StringSink(s3)));
    *x = nonce;

    json j;
    j["data"] = sData;
    j["datahash"] = s2;
    j["n"] = to_string(nonce);
    j["rotation"] = s3;
    j["source"] = sSrc;
    j["target"] = target;

    fstream myfile;
    myfile.open("data.txt", ios_base::app | ios_base::in);
    myfile << "\n";
    myfile << j.dump();
    myfile.close();
    cout << "finished rotation" << endl;
    cout << "Hash: " + j["rotation"].get<std::string>() << endl;
    return outhash;
}

void rotate(string srcdigest, string datadigest, string outdigest, int *x, string y, string sData, string sSrc, int itter){

    SHA256 hash;
    string src;
    string data;
    string newoutdigest;
    int nonce = 1;
    src = rotation(srcdigest, datadigest, outdigest, &nonce, y, sData, sSrc);
    for(int i=2; i == itter; i++){
        nonce = 1;
        sSrc = "";
        StringSource(src, true, new HexEncoder(new StringSink(sSrc)));
        //First Rotation
    
        string s;
        StringSource(datadigest, true, new HexEncoder(new StringSink(s)));
        string x;
        StringSource(src, true , new HexEncoder(new StringSink(x)));

        cout << "new source: " + x << endl;
        data = x + s;

        //hash sourcehash + datahash
        StringSource(data, true, new HashFilter(hash, new StringSink(newoutdigest)));

        src = rotation(src, datadigest, newoutdigest, &nonce, y, sData, sSrc);
    }

}

void fork(string srcdigest, string datadigest, string outdigest, int *x, string y, string sData, string sSrc, int itter){
    SHA256 hash;
    string src;
    string data;
    string newoutdigest;
    int nonce = 1;
    src = rotation(srcdigest, datadigest, outdigest, &nonce, y, sData, sSrc);
    for(int i=2; i == itter; i++){
        src = "";
        //First Rotation

        //hash the source 
        StringSource(sSrc, true, new HashFilter(hash, new StringSink(src)));

        string s;
        StringSource(datadigest, true, new HexEncoder(new StringSink(s)));
        string x;
        StringSource(srcdigest, true , new HexEncoder(new StringSink(x)));

        data = x + s + to_string(nonce);
        nonce++;

        //hash sourcehash + datahash
        StringSource(data, true, new HashFilter(hash, new StringSink(newoutdigest)));

        src = rotation(src, datadigest, newoutdigest, &nonce, y, sData, sSrc);
    }
}



int main(int argc, char* argv[]){

    HexEncoder encoder(new FileSink(cout));


    SHA256 srchash;
    SHA256 datahash;
    SHA256 outhash;
    string sdata;
    string src;
    string target;
    int itter;
    int nonce = 1;


    //get user input 
    cout << "Source: ";
    cin >> src;
    cout << endl;
    cout << "Data: ";
    cin >> sdata;
    cout << endl;
    cout << "Target: ";
    cin >> target;
    cout << endl;
    cout << "itterations: ";
    cin >> itter;
    cout << endl;

    string srcdigest;
    string datadigest;
    string outdigest;

//First Rotation

    //hash the source 
    StringSource(src, true, new HashFilter(srchash, new StringSink(srcdigest)));
    //hash the data 
    StringSource(sdata, true, new HashFilter(datahash, new StringSink(datadigest)));
   

    string s;
    StringSource(datadigest, true, new HexEncoder(new StringSink(s)));
    string x;
    StringSource(srcdigest, true , new HexEncoder(new StringSink(x)));

    string data = x + s;

    //hash sourcehash + datahash
    StringSource(data, true, new HashFilter(outhash, new StringSink(outdigest)));


    rotate(src, datadigest, outdigest, &nonce, target, sdata, src, itter);

    return 0;
}