#include <iostream>
#include <stdlib.h>
#include <algorithm>
#include <iterator>
#include <list>
#include <set>
#include <time.h>
#include <sstream>
#include <vector>
#include <iomanip>
#include <random>

#include "CryptoPP/sha3.h"
#include "CryptoPP/aes.h"
#include "CryptoPP/cryptlib.h"
#include "CryptoPP/files.h"
#include "CryptoPP/filters.h"
#include "CryptoPP/modes.h"
#include "CryptoPP/hex.h"

typedef unsigned char byte;

std::random_device rd; 
std::mt19937 rng(rd());

class GraphGenerator {
public:
	GraphGenerator(int nodes) : nodes(nodes), edges(0) {
		generateGraphs();
	}
	std::vector<std::vector<bool>> getG() {
		return G;
	}

	std::vector<int> getSolutionG() {
		return solG;
	}

	int getDimension() {
		return nodes;
	}

private:
	int nodes;
	int edges;
	std::vector<std::vector<bool>> G;
	std::vector<int> solG;

	void generateGraphs() {
		for (int i = 0; i < nodes; i++) {
			G.emplace_back(std::vector<bool>(nodes));
		}

		for (int i = 0; i < nodes; i++) {
			solG.push_back(i + 1);
			G[i][(i + 1) % nodes] = true;
			G[(i + 1) % nodes][i] = true;
			edges++;
		}

		std::uniform_int_distribution<int> uni(0, 1);
		for (int i = 0; i < nodes; i++) {
			for (int j = 0; j < nodes; j++) {
				if (i != j) {
					if (G[i][j] == false) {
						if (uni(rng)) { 
							G[i][j] = true;
							G[j][i] = true;
							edges++;
						}
					}
				}
			}
		}
	}
};

class NIZKP {
public:

	NIZKP(GraphGenerator gg) {
		G = gg.getG();
		solutionG = gg.getSolutionG();
		DIMENSION = gg.getDimension();
	}

	std::string getPackage(int segments, std::string secret) {
		std::string message;
		std::string segment;

		
		try {
			if (segments == 0)
				return message;

			message = getSegment(false, std::vector<byte>());
			// std::cout << "first segment, no cipher: " << duration.count() * 1000 << std::endl;
			// std::cout << "segment: "  << message << std::endl;
			for (int i = 1; i < segments; i++) {
				segment = getSegment(true, key);
				// std::cout << "segment: "  << message << std::endl;
				message += segment;
			}

		std::vector<byte> bytes(secret.begin(), secret.end()); 
		std::vector<byte> c = cipher(bytes, key);
		message += bytes2Hex(c) + "|";

		} catch (CryptoPP::Exception e) {
			std::cout << "got crypto exception" << e.what(); 
		}

		return message;
	}

	std::string processPackage(std::string message) {
		std::vector<std::string> segments = splitString(message, '|');
		std::string ret;

		if (!checkReto(unwrapSegment(segments.at(0)), Gi, solutionGi, isomorphism)) {
			return ret;
		}

		for (unsigned int i = 1; i < segments.size() - 1; i++) {
			if (!checkReto(unwrapSegmentCipher(segments.at(i), key), Gi, solutionGi, isomorphism)) {
				return ret;
			}
		}

		std::string seg = segments.at(segments.size() - 1);
		std::vector<byte> result = decipher2(segments.at(segments.size() - 1), key);

		return std::string(result.begin(), result.end());
	}

	bool unwrapSegment(std::string segment) {
		std::vector<std::string> parts(splitString(segment, ':'));

		try {
			Gi.clear(); 
			Gi = bin2Graph(parts.at(0));
		}
		catch (...) {
			std::cout << "caught";
			return false;
		}
		
		std::string part(parts.at(0)); 

		if (hashBinary(std::vector<byte>(part.begin(), part.end()))) {
			solutionGi = string2Vector(parts.at(1));
			isomorphism.clear();
			return true;
		}
		else {
			isomorphism = string2Vector(parts.at(1));
			solutionGi.clear();
			return false;
 		}
	}

	bool unwrapSegmentCipher(std::string segmentCipher, std::vector<byte> key) {
		try {
			std::vector<byte> seg = decipher2(segmentCipher, key);

			std::string segment(seg.begin(), seg.end());
			
			bool res = unwrapSegment(segment); 

			return res; 
		}
		catch (...) {
			std::cout << "exception: " << std::endl;
			return false;
		}
	}


	std::vector<byte> cipher(std::vector<byte> plainText, std::vector<byte> vectorKey) {
		byte iv[CryptoPP::AES::BLOCKSIZE];
		byte key[CryptoPP::AES::MAX_KEYLENGTH];

		for (int i = 0; i < CryptoPP::AES::MAX_KEYLENGTH; i++) {
			key[i] = vectorKey[i % vectorKey.size()];
		}
		for (int i = 0; i < CryptoPP::AES::BLOCKSIZE; i++) {
			iv[i] = vectorKey[i % vectorKey.size()];
		}

		std::string encoded; 
		std::string plain(bytes2Hex(plainText));

		std::string cipher; 

		CryptoPP::CFB_Mode<CryptoPP::AES>::Encryption encryption;
		encryption.SetKeyWithIV(key, sizeof(key), iv); 
		CryptoPP::StringSource(plain, true, new CryptoPP::StreamTransformationFilter(encryption, new CryptoPP::StringSink(cipher)));
		
		return std::vector<byte>(cipher.begin(), cipher.end());
	}

	std::vector<byte> decipher2(std::string cipher, std::vector<byte> vectorKey) {
		byte iv[CryptoPP::AES::BLOCKSIZE];
		byte key[CryptoPP::AES::MAX_KEYLENGTH];

		for (int i = 0; i < CryptoPP::AES::MAX_KEYLENGTH; i++) {
			key[i] = vectorKey[i % vectorKey.size()];
		}
		for (int i = 0; i < CryptoPP::AES::BLOCKSIZE; i++) {
			iv[i] = vectorKey[i % vectorKey.size()];
		}

		std::string encoded;
		std::string recovered;

		CryptoPP::CFB_Mode<CryptoPP::AES>::Decryption decryption;
		decryption.SetKeyWithIV(key, sizeof(key), iv);

		CryptoPP::StringSource s(cipher, true, new CryptoPP::HexDecoder(new CryptoPP::StreamTransformationFilter(decryption, new CryptoPP::StringSink(recovered))));
		std::vector<byte> bytes = hex2Bytes(recovered);

		return bytes;
	}


	bool checkReto0(std::vector<std::vector<bool>> Gi_, std::vector<int> isomorphism_) {
		std::vector<std::vector<bool>> Gi_aux;
		for (int i = 0; i < DIMENSION; i++) {
			Gi_aux.emplace_back(std::vector<bool>(DIMENSION));
		}

		std::vector<int> indexVector(DIMENSION + 1); 
		for (int i = 1; i < DIMENSION + 1; i++) {
			indexVector[isomorphism_[i - 1]] = i - 1; 
		}

		for (int i = 0; i < DIMENSION; i++) {
			for (int j = 0; j < DIMENSION; j++) {
				ptrdiff_t first = indexVector[i + 1]; 
				ptrdiff_t second = indexVector[j + 1]; 
				Gi_aux[i][j] = G[first][second];
			}
		}

		for (int i = 0; i < DIMENSION; i++) {
			for (int j = 0; j < DIMENSION; j++) {
				if (Gi_aux[i][j] != Gi_[i][j]) {
					return false;
				}
			}
		}

		std::vector<int> SolGi_;
		for (int i = 0; i < DIMENSION; i++) {
			SolGi_.push_back(isomorphism_.at(solutionG.at(i) - 1));
		}

		this->key.clear(); 
		this->key = hash(vector2String(SolGi_));
		return true;
	}

	bool checkReto1(std::vector<std::vector<bool>> Gi_, std::vector<int> solutionGi_) {
		std::vector<bool> visited(DIMENSION);
		visited[solutionGi_.at(0) - 1] = true;

		for (int i = 0; i < DIMENSION - 1; i++) {
			if (Gi_[solutionGi_.at(i) - 1][solutionGi_.at(i + 1) - 1]) {
				if (visited[solutionGi_.at(i + 1) - 1])
					return false;
				else
					visited[solutionGi_.at(i + 1) - 1] = true;
			}
			else {
				return false;
			}
		}

		for (int i = 0; i < DIMENSION; i++) {
			if (!visited[i])
				return false;
		}

		this->key.clear(); 
		this->key = hash(vector2String(solutionGi_));

		return true;
	}

	bool checkReto(bool reto, std::vector<std::vector<bool>> Gi_, std::vector<int> SolGi_, std::vector<int> Iso_) {
		if (reto) {
			return checkReto1(Gi_, SolGi_);
		}
		else {
			return checkReto0(Gi_, Iso_);
		}	
	}

	std::string getSegment(bool toCipher, std::vector<byte> key) {
		generateGi();
		
		std::string graphL = graph2Bin(Gi);
		std::string seg = graphL + ":";

		if (hashBinary(std::vector<byte>(graphL.begin(), graphL.end()))) {
			std::string str(vector2String(solutionGi));
			seg += str;
			this->key = hash(str);
		} else {
			std::string str(vector2String(isomorphism)); 
			seg += str;
			std::string stringSolution = vector2String(solutionGi);
			this->key = hash(stringSolution);
		}

		if (toCipher) {
			seg = bytes2Hex(cipher(std::vector<byte>(seg.begin(), seg.end()), key));
		}

		seg += "|";
		return seg;
	}

	bool hashBinary(std::vector<byte> text) {
		std::string str(text.begin(), text.end());
		bool lsb = getLSB(hash(str)[0]); 

		return lsb;
	}

	bool getLSB(byte b) {
		return (b >> 7 != 0);
	}

	std::vector<byte> hash(std::string text) {
		CryptoPP::SHA3_256 hash; 
		std::string digest; 
		hash.Update((const byte*)text.data(), text.size()); 
		digest.resize(hash.DigestSize());
		hash.Final((byte*)&digest[0]); 
		return std::vector<byte>(digest.begin(), digest.end()); 
	}

	std::string graph2Bin(std::vector<std::vector<bool>> graph) {
		std::string n, out;
		int b, i, j;

		for (i = 0; i < DIMENSION * DIMENSION - 1; i += 8) {
			b = 0;
			for (j = std::min(i + 7, DIMENSION * DIMENSION - 1); j >= i; j--) {
				b = (b << 1) | (graph[j / DIMENSION][j % DIMENSION] ? 1 : 0); //TODO valja li ovo?
			}

			out += std::to_string(b) + ",";
		}

		b = 0;

		for (j = std::min(i + 7, DIMENSION * DIMENSION - 1); j >= i; j--) {
			b = (b << 1) | (graph[j / DIMENSION][j % DIMENSION] ? 1 : 0);
		}

		out += std::to_string(b);
		return out;
	}

	std::vector<std::vector<bool>> bin2Graph(std::string in) {
		std::vector<std::vector<bool>> graph;
		for (int i = 0; i < DIMENSION; i++) {
			graph.emplace_back(std::vector<bool>(DIMENSION));
		}
		std::vector<std::string> values(splitString(in, ','));
		// std::vector<std::string> values(splitString2(in, ","));
		int cont = 0;

		for (int i = 0; i < DIMENSION * DIMENSION; i += 8) {
			int b = std::strtol(values[cont++].c_str(), nullptr, 10);
			if (b < 0) throw "this is not fine";
			for (int j = i; (j < i + 8) && (j < DIMENSION * DIMENSION); j++) {
				graph[j / DIMENSION][j % DIMENSION] = ((b & 1) != 0);
				b =(int)((unsigned int) b >> 1); 
			}
		}

		return graph;
	}

	std::string vector2String(std::vector<int> vector) {
		std::string res;
		for (unsigned int i = 0; i < vector.size() - 1; i++) {
			res += std::to_string(vector.at(i)) + ",";
		}
		res += std::to_string(vector.at(vector.size() - 1));

		return res;
	}

	std::vector<int> string2Vector(std::string str) {
		std::vector<int> result;
		std::vector<std::string> split(splitString(str, ','));
		// std::vector<std::string> split(splitString2(str, ","));
		for (std::string s : split) {
			result.push_back(std::strtol(s.c_str(), nullptr, 10));
		}
		return result;
	}

	std::string bytes2Hex(std::vector<byte> bytes) {
		std::ostringstream ss;
		ss << std::hex << std::setfill('0');

		for (byte b : bytes) {
			ss << std::setw(2) << static_cast<int>(b);
		}
		return ss.str();
	}

	std::vector<byte> hex2Bytes(std::string str) {
		std::vector<byte> res;

		for (unsigned int i = 0; i < str.length(); i += 2) {
			std::string byteString = str.substr(i, 2);
			byte b = static_cast<byte>( std::strtol(byteString.data(), nullptr, 16));
			res.push_back(b);
		}

		return res;
	}

	std::vector<std::string> splitString(std::string str, char delimiter) {
		std::vector<std::string> parts;
		std::string token;
		std::istringstream tokenStream(str);

		while (std::getline(tokenStream, token, delimiter)) {
			parts.push_back(std::move(token));
		}

		return parts;
	}

	void generateGi() {
		isomorphism = generateIsomorphism(DIMENSION);
		Gi.clear(); 
		for (int i = 0; i < DIMENSION; i++) {
			Gi.emplace_back(std::vector<bool>(DIMENSION));
		}

		std::vector<int> indexVector(DIMENSION + 1); 
		for (int i = 1; i < DIMENSION + 1; i++) {
			indexVector[isomorphism[i - 1]] = i - 1; 
		}

		for (int i = 0; i < DIMENSION; i++) {
			for (int j = 0; j < DIMENSION; j++) {
				ptrdiff_t first = indexVector[i + 1];
				ptrdiff_t second = indexVector[j + 1]; 
				Gi[i][j] = G[first][second];
			}
		}

		solutionGi.clear(); 
		for (int i = 0; i < DIMENSION; i++) {
			solutionGi.push_back(isomorphism.at(solutionG.at(i) - 1));
		}
	}

	std::vector<int> generateIsomorphism(int nodes) {
		std::set<int> generated;
		std::vector<int> v;
		std::uniform_int_distribution<int> uni(1, nodes);

		while (generated.size() < (unsigned int) nodes) {
			int next = uni(rng); 
			if (!generated.count(next)) {
				generated.insert(next);
				v.push_back(next); 
			}
			
		}
		return v;
	}

private:
	std::vector<std::vector<bool>> G;
	std::vector<std::vector<bool>> Gi;
	int DIMENSION;
	std::vector<int> isomorphism;
	std::vector<int> solutionG;
	std::vector<int> solutionGi;
	std::vector<byte> key;
};

int main(int argc, char* argv[]) {
	// int nodes = strtol(argv[1], nullptr, 10);
	int nodes = 41; 
	// int nodesArray[] = {10, 20, 30, 40, 50, 60, 70, 80, 90, 100, 150, 200, 250, 300}; 
	// int segments = 41;
	int segments = strtol(argv[1], nullptr, 10); 
	std::string secret = "testing";
	
	// for (int nodes: nodesArray) {
		double madeSum = 0;
		double processedSum = 0; 

		for (int i = 0; i < 10; i++) {
			GraphGenerator gg(nodes);
			NIZKP nizkp(gg);
			std::cout << "starting " << i << std::endl;
			auto start = std::chrono::system_clock::now(); 

			std::string p = nizkp.getPackage(segments, secret);
			// std::cout << p << std::endl;
			auto mid = std::chrono::system_clock::now();
			std::string des = nizkp.processPackage(std::move(p));

			auto end = std::chrono::system_clock::now();
			std::chrono::duration<double> duration = end - start;
			std::chrono::duration<double> receiver = end - mid;
			std::chrono::duration<double> madePackage = mid - start; 

			madeSum += madePackage.count() * 1000; 
			processedSum += receiver.count() * 1000; 
		}
		std::cout << nodes << " nodes, made package in: " << madeSum/10 << "ms, processed in: " << processedSum/10 << "ms, total: "  << madeSum/10 + processedSum/10<< std::endl;	
	// }
	
}