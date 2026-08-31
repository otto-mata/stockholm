patch: pkey stub patcher
	./patcher stub/stockholm public.pem
pkey:
	openssl genrsa -out private.pem 4096
	openssl pkey -in private.pem -pubout -out public.pem

stub:
	$(MAKE) re -C ./stub

patcher:
	clang -Wall -Wextra -Werror patch.c -o patcher -lelf


.PHONY: stub
