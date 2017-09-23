#include <cstdint>
#include <iomanip>
#include <iostream>
#include <string>
#include <vector>

#include <openssl/opensslv.h>
#include <openssl/sha.h>

int main()
{
	std::cout << OPENSSL_VERSION_TEXT << std::endl;

	std::vector<std::uint8_t> hash(SHA256_DIGEST_LENGTH);
	auto msg = std::string{"Hello"};

	SHA256_CTX sha256;
	SHA256_Init(&sha256);
	SHA256_Update(&sha256, msg.c_str(), msg.length());
	SHA256_Final(hash.data(), &sha256);

	for (auto b : hash)
		std::cout << std::uppercase << std::setfill('0') << std::setw(2) << std::hex << static_cast<std::uint32_t>(b);

	std::cout << std::endl;
	return 0;
}
