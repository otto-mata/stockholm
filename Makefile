pkey:
	openssl genrsa -out private.pem 4096
	openssl pkey -in private.pem -pubout -out public.pem
