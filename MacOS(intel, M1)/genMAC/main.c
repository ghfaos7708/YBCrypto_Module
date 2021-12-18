
#include <stdio.h>
#include "SHA256.h"
#include "HMAC_SHA256.h"

void computeHMAC()
{
	genIntegrityData("YBCrypto.dylib");
}


int main(int argc, char** argv)
{
	computeHMAC();
	return 0;
}
// EOF
