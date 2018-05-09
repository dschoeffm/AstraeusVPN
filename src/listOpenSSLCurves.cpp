#include <openssl/ec.h>
#include <openssl/objects.h>

#include <iostream>

int main(int argc, char **argv) {
	(void)argc;
	(void)argv;

	size_t num = EC_get_builtin_curves(NULL, 0);

	EC_builtin_curve *curves =
		reinterpret_cast<EC_builtin_curve *>(malloc(sizeof(EC_builtin_curve) * num));

	EC_get_builtin_curves(curves, num);
	for (unsigned int i = 0; i < num; i++) {
		std::cout << "NID: " << curves[i].nid << " Name: " << OBJ_nid2sn(curves[i].nid)
				  << " Comment: " << curves[i].comment << std::endl;
	}

	free(curves);
	return 0;
}
