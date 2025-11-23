//////////////////////////////////////////////////////////////////////
// SPDX-License-Identifier: MIT
//
// This example shows how to generate and store an RSA key pair and a
// x509 certificate (RFC 5980) with OpenSSL 3.0.0+.
//
// openssl: https://github.com/openssl/openssl/
// x509:    https://www.rfc-editor.org/rfc/rfc5280
//
// Author:   Giovanni Santini
// Mail:     giovanni.santini@proton.me
// License:  MIT
//

#define _POSIX_C_SOURCE 1  // fdopen
#include <string.h>
#include <stdio.h>
#include <fcntl.h>   // open
#include <unistd.h>  // close

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/core_names.h>
#include <openssl/pem.h>

//
// Function signatures
//

// A property query used for selecting algorithm implementations
// It is a sequence of comma separated property query clauses, for
// example "fips=yes", "provider!=default" or "?iteration.count=3".
//
// We will leave this empty.
static const char *propq = NULL;

// Generates an RSA public-private key pair with [bits] number of
// bits, and returns it or NULL.
//
// This uses the long way of generating an RSA key.
static EVP_PKEY *generate_rsa_keys(OSSL_LIB_CTX *libctx,
                                   unsigned int bits);

// Opens / creates the files [public_key_filename] and
// [private_key_filename], and writes [pkey] using
// PEM_write_{PUBKEY|PrivateKey}
static int write_rsa_keys(const EVP_PKEY *pkey,
                          const char *public_key_filename,
                          const char *private_key_filename);

// Generate a x509 certificate for [pkey] with arguments
X509* generate_x509_cert(EVP_PKEY *pkey,
                         const char* issuer_name,
                         unsigned int expire_in_days);

// Writes a X509 [cert] to [cert_filename]
int write_x509_cert(X509* cert, const char* cert_filename);

//
// Implementation
//

// Implementation based on an official example:
// https://github.com/openssl/openssl/blob/e66332418f84144478df43df91cf4cedf412fc85/demos/pkey/EVP_PKEY_RSA_keygen.c
static EVP_PKEY *generate_rsa_keys(OSSL_LIB_CTX *libctx,
                                   unsigned int bits)
{
  EVP_PKEY_CTX *genctx = NULL;
  EVP_PKEY *pkey = NULL;

  // Create context using RSA algorithm. "RSA-PSS" could also be used
  // here.
  genctx = EVP_PKEY_CTX_new_from_name(libctx, "RSA", propq);
  if (!genctx)
  {
    fprintf(stderr, "EVP_PKEY_CTX_new_from_name() failed: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    goto cleanup;
  }

  if (EVP_PKEY_keygen_init(genctx) <= 0)
  {
    fprintf(stderr, "EVP_PKEY_keygen_init() failed: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    goto cleanup;
  }
 
  // Here we set the number of bits to use in the RSA key. Should not
  // be below 2048
  if (EVP_PKEY_CTX_set_rsa_keygen_bits(genctx, bits) <= 0)
  {
    fprintf(stderr, "EVP_PKEY_CTX_set_rsa_keygen_bits() failed: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    goto cleanup;
  }

  // It is possible to create an RSA key using more than two primes.
  // Do not do this unless you know why you need this.  You
  // ordinarily do not need to specify this, as the default is two.
  //
  // Both of these parameters can also be set via
  // EVP_PKEY_CTX_set_params, but these functions provide a more
  // concise way to do so.
  //
  // unsigned int primes = 2;
  // if (EVP_PKEY_CTX_set_rsa_keygen_primes(genctx, primes) <= 0) {
  //   fprintf(stderr, "EVP_PKEY_CTX_set_rsa_keygen_primes() failed: %s\n",
  //   ERR_error_string(ERR_get_error(), NULL));
  //   goto cleanup;
  // }

  // Generating an RSA key with a number of bits large enough to be
  // secure for modern applications can take a fairly substantial
  // amount of time (e.g.  one second). If you require fast key
  // generation, consider using an EC key instead.
  //
  // If you require progress information during the key generation
  // process, you can set a progress callback using EVP_PKEY_set_cb;
  // see the example in EVP_PKEY_generate(3).
  //
  fprintf(stdout, "Generating RSA key, this may take some time...\n");
  if (EVP_PKEY_generate(genctx, &pkey) <= 0)
  {
    fprintf(stderr, "EVP_PKEY_generate() failed: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    goto cleanup;
  }

 cleanup:
  if (genctx) EVP_PKEY_CTX_free(genctx);
  return pkey;
}

static int write_rsa_keys(const EVP_PKEY *pkey,
                          const char *public_key_filename,
                          const char *private_key_filename)
{
  int ret = 0;
  int priv_fd;
  FILE *public_key_file  = NULL;
  FILE *private_key_file = NULL;
  
  public_key_file = fopen(public_key_filename, "w+");
  if (!public_key_file)
  {
    perror("Error opening public key file");
    goto cleanup;
  }
  
  priv_fd = open(private_key_filename, O_CREAT | O_WRONLY, 0600);
  if (priv_fd == -1)
  {
    perror("Error opening private key file fd");
    goto cleanup;
  }
  
  private_key_file = fdopen(priv_fd, "w");
  if (!private_key_file)
  {
    perror("Error opening private key file");
    goto cleanup;
  }
    
  if (PEM_write_PUBKEY(public_key_file, pkey) == 0)
  {
    fprintf(stderr, "Failed to output PEM-encoded public key: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    goto cleanup;
  }

  // Please note that this output is not encrypted. You may wish to
  // use the arguments to specify encryption of the key if you are
  // storing it on disk. See PEM_write_PrivateKey(3).
  if (PEM_write_PrivateKey(private_key_file, pkey,
                           NULL, NULL, 0, NULL, NULL) == 0)
  {
    fprintf(stderr, "Failed to output PEM-encoded private key: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    goto cleanup;
  }

  ret = 1;
cleanup:
  if (public_key_file) fclose(public_key_file);
  if (private_key_file) fclose(private_key_file);
  if (priv_fd != -1) close(priv_fd);
  return ret;
}

X509* generate_x509_cert(EVP_PKEY *pkey,
                         const char* issuer_name,
                         unsigned int expire_in_days)
{
  X509* cert   = NULL;
  X509_NAME *name = NULL;
  
  if (!pkey)
  {
    fprintf(stderr, "Invalid pkey\n");
    return 0;
  }

  cert = X509_new();
  if (!cert)
  {
    fprintf(stderr, "X509_new failed: %s\n",
            ERR_error_string(ERR_get_error(), NULL));
    goto cleanup;
  }

  if (!ASN1_INTEGER_set(X509_get_serialNumber(cert), 1))
  {
    fprintf(stderr, "ASN1_INTEGER_set failed\n");
    goto cleanup;
  }

  if (!X509_gmtime_adj(X509_get_notBefore(cert), 0) ||
      !X509_gmtime_adj(X509_get_notAfter(cert), expire_in_days * 24 * 3600))
  {
    fprintf(stderr, "X509_gmtime_adj failed\n");
    goto cleanup;
  }

  if (!X509_set_pubkey(cert, pkey))
  {
    fprintf(stderr, "X509_set_pubkey failed\n");
    goto cleanup;
  }

  name = X509_get_subject_name(cert);
  if (!name)
  {
    fprintf(stderr, "X509_get_subject_name failed\n");
    goto cleanup;
  }

  if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                  (unsigned char*)issuer_name, -1, -1, 0))
  {
    fprintf(stderr, "X509_NAME_add_entry_by_txt failed\n");
    goto cleanup;
  }

  if (!X509_set_issuer_name(cert, name))
  {
    fprintf(stderr, "X509_set_issuer_name failed\n");
    goto cleanup;
  }

  if (!X509_sign(cert, pkey, EVP_sha256()))
  {
    fprintf(stderr, "X509_sign failed\n");
    goto cleanup;
  }

 cleanup:
  return cert;
}

int write_x509_cert(X509* cert, const char* cert_filename)
{
  int ret         = 0;
  FILE *certfile  = NULL;

  certfile = fopen(cert_filename, "wb");
  if (!certfile)
  {
    perror("fopen failed");
    goto cleanup;
  }

  if (!PEM_write_X509(certfile, cert))
  {
    fprintf(stderr, "PEM_write_X509 failed\n");
    goto cleanup;
  }

  ret = 1;
 cleanup:
  if (certfile) fclose(certfile);
  return ret;
}

int main(void)
{
  int             ret       = EXIT_FAILURE;
  unsigned int    key_bits  = 4096;
  OSSL_LIB_CTX*   libctx    = NULL;
  EVP_PKEY*       pkey      = NULL;
  X509*           cert      = NULL;

  //
  // RSA keys
  //
  
  pkey = generate_rsa_keys(libctx, key_bits);
  if (!pkey)
    goto cleanup;

  if (write_rsa_keys(pkey, "public.pem", "private.key") == 0)
  {
    fprintf(stderr, "Failed to write rsa keys\n");
    goto cleanup;
  }

  //
  // x509 Certificate
  //
  
  cert = generate_x509_cert(pkey, "example autority", 365);
  if (!cert)
  {
    fprintf(stderr, "Failed to generate x509 cert\n");
    goto cleanup;
  }
  // Note: pkey can be freed from now on
  EVP_PKEY_free(pkey);
  pkey = NULL;

  if (write_x509_cert(cert, "cert.crt") == 0)
  {
    fprintf(stderr, "Failed to write x509 cert\n");
    goto cleanup;
  }

  //
  // Exit
  //

  ret = EXIT_SUCCESS;
 cleanup:
  if (cert) X509_free(cert);
  if (pkey) EVP_PKEY_free(pkey);
  if (libctx) OSSL_LIB_CTX_free(libctx);
  return ret;
}
