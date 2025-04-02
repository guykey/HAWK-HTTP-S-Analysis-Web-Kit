run generate_trusted_ca.py, get the ca_cert.pem and ca_key.pem
add ca_cert.pem to trusted root

make new directory: "temp_certificates" next to the myfiddler file

run my fiddler and then run setregistry

WORKS

works by making a certificate for every url, that certificate is signed by the ca_cert.pem
and so chrome trusts it, 
there is a tunnel list, urls that would be tunneled instead of proxied