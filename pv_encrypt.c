#include "pv.h"

void encrypt_file_ecb (const char *ctxt_fname, void *raw_sk, size_t raw_len, int fin){
  int ctxt = 0;
  int bytes_read=0;
  int i=0;

  aes_ctx aesEnc;
  char ctxt_buf[CCA_STRENGTH], buf[CCA_STRENGTH];

  char* sk_enc;

  if ((ctxt = open (ctxt_fname, O_WRONLY|O_TRUNC|O_CREAT, 0600)) == -1) {
    perror (getprogname ());
    scrub_buffer(raw_sk);
    exit (-1);
  }

  sk_enc = raw_sk;
  aes_setkey(&aesEnc, sk_enc, CCA_STRENGTH);
  while((bytes_read = read(fin, buf, CCA_STRENGTH)) == CCA_STRENGTH){
    aes_encrypt(&aesEnc, ctxt_buf, buf);
    (void) (write(ctxt, ctxt_buf, CCA_STRENGTH)+1);
  }
  for(i=bytes_read; i<CCA_STRENGTH; ++i)
    buf[i]=0; 
  aes_encrypt(&aesEnc, ctxt_buf, buf);
  (void) (write(ctxt, ctxt_buf, CCA_STRENGTH)+1);
  return;
}
void encrypt_file (const char *ctxt_fname, void *raw_sk, size_t raw_len, int fin){
  /*************************************************************************** 
   * Task: Read the content from file descriptor fin, encrypt it using raw_sk,
   *       and place the resulting ciphertext in a file named ctxt_fname.
   *       The encryption should be CCA-secure, which is the level of 
   *       cryptographic protection that you should always expect of any 
   *       implementation of an encryption algorithm.
   * 
   * As we have learned in class, the gold standard for encryption is
   * CCA-security. The approach that we will take in this lab is to
   * use AES in CTR-mode (AES-CTR), and then append an AES-CBC-MAC mac
   * of the resulting ciphertext. (Always mac after encrypting!) The
   * dcrypt library contains an implementation of AES but you need to implement
   * the logic for using AES in CTR-mode and in CBC-MAC'ing.
   *
   * Notice that the keys used to compute AES-CTR and AES-CBC-MAC mac
   * must be different. Never use the same cryptographic key for two
   * different purposes: bad interference could occur.  For this
   * reason, the key raw_sk actually consists of two pieces, one for
   * use in AES-CTR and the other for AES-CBC-MAC. The length of each
   * piece (and hence the cryptographic strength of the encryption) is
   * specified by the constant CCA_STRENGTH in pv.h; the default is
   * 128 bits, or 16 bytes.
   * 
   * Recall that AES works on blocks of 128 bits; in the case that the
   * length (in bytes) of the plaintext is not a multiple of 16, just
   * discard the least-significant bytes that you obtains from the
   * CTR-mode operation.
   * 
   * Thus, the overall layout of an encrypted file will be:
   *
   *         +--------------------------+---+
   *         |             Y            | W |
   *         +--------------------------+---+
   *
   * where Y = AES-CTR (K_CTR, plaintext)
   *       W = AES-CBC-MAC (K_MAC, Y)
   *
   * As for the sizes of the various components of a ciphertext file,
   * notice that:
   *
   * - the length of Y (in bytes) is just 16 bytes more than the length
   *   of the plaintext, and thus it may not be a multiple of 16; 
   * - the hash value AES-CBC-MAC (K_MAC, Y) is 16-byte long;
   *
   ***************************************************************************/

  int ctxt = 0;
  int bytes_read=0;
  int i=0;

  aes_ctx aesEnc, aesMac;

  char ctxt_buf[CCA_STRENGTH], buf[CCA_STRENGTH], mac_buf[CCA_STRENGTH];
  char ctr[CCA_STRENGTH], mac_buf_temp[CCA_STRENGTH];

  char *sk_enc, *sk_mac;
  /* Create the ciphertext file---the content will be encrypted */

  if ((ctxt = open (ctxt_fname, O_WRONLY|O_TRUNC|O_CREAT, 0600)) == -1) {
    perror (getprogname ());

    /* scrub the buffer that's holding the key before exiting */

    /* YOUR CODE HERE */
    scrub_buffer(raw_sk);

    exit (-1);
  }

  /* initialize the pseudorandom generator (for the IV) */

  ri();

  /* The buffer for the symmetric key actually holds two keys: */
  /* use the first key for the AES-CTR encryption ...*/

  sk_enc = raw_sk;
  aes_setkey(&aesEnc, sk_enc, CCA_STRENGTH);
  /* ... and the second part for the AES-CBC-MAC */

  sk_mac = raw_sk+CCA_STRENGTH;
  aes_setkey(&aesMac, sk_mac, CCA_STRENGTH);

  /* Now start processing the actual file content using symmetric encryption */
  /* Remember that CTR-mode needs a random IV (Initialization Vector) */

  prng_getbytes(ctr, CCA_STRENGTH);

  (void) (write(ctxt, ctr, CCA_STRENGTH)+1);

  /* start CBC-MAC */
  aes_encrypt(&aesMac, mac_buf, ctr);

  while( (bytes_read = read(fin, buf, CCA_STRENGTH)) == CCA_STRENGTH) {
    inc_counter(ctr);
    aes_encrypt(&aesEnc, ctxt_buf, ctr);

    /* XOR with ctr */
    for(i=0; i<CCA_STRENGTH; ++i) {
      ctxt_buf[i] = ctxt_buf[i] ^ buf[i];
    }

   (void) (write(ctxt, ctxt_buf, CCA_STRENGTH)+1);

    /* add to MAC */
    for(i=0; i<CCA_STRENGTH; ++i) {
      mac_buf[i] = mac_buf[i] ^ ctxt_buf[i];
    }
    aes_encrypt(&aesMac, mac_buf_temp, mac_buf);
    for(i=0; i<CCA_STRENGTH; ++i) {
      mac_buf[i] = mac_buf_temp[i];
    }

  }

  inc_counter(ctr);
  /* Don't forget to pad the last block with trailing zeroes */

  for(i=bytes_read; i<CCA_STRENGTH; ++i) {
    buf[i] = 0;
  }

  /* write the last chunk */
  aes_encrypt(&aesEnc, ctxt_buf, ctr);

  /* XOR with ctr */
  for(i=0; i<CCA_STRENGTH; ++i) {
    ctxt_buf[i] = ctxt_buf[i] ^ buf[i];
  }

  (void)( write(ctxt, ctxt_buf, bytes_read)+1);

  /* Finish up computing the AES-CBC-MAC and write the resulting
   * 16-byte MAC after the last chunk of the AES-CTR ciphertext */


  for(i=0; i<CCA_STRENGTH; ++i) {
    mac_buf[i] = mac_buf[i] ^ ctxt_buf[i];
  }
  aes_encrypt(&aesMac, mac_buf_temp, mac_buf);
  for(i=0; i<CCA_STRENGTH; ++i) {
    mac_buf[i] = mac_buf_temp[i];
  }
  

  (void) (write(ctxt,mac_buf, CCA_STRENGTH)+1);

  close(ctxt);
}

void 
usage (const char *pname)
{
  printf ("Personal Vault: Encryption \n");
  printf ("Usage: %s SK-FILE PTEXT-FILE CTEXT-FILE\n", pname);
  printf ("       Exits if either SK-FILE or PTEXT-FILE don't exist.\n");
  printf ("       Otherwise, encrpyts the content of PTEXT-FILE under\n");
  printf ("       sk, and place the resulting ciphertext in CTEXT-FILE.\n");
  printf ("       If CTEXT-FILE existed, any previous content is lost.\n");

  exit (1);
}

int 
main (int argc, char **argv)
{
  int fdsk, fdptxt;
  char *raw_sk;
  size_t raw_len;

  /* YOUR CODE HERE (if needed)*/


  if (argc < 4) {
    usage (argv[0]);
  }   /* Check if argv[1] and argv[2] are existing files */
  else if (((fdsk = open (argv[1], O_RDONLY)) == -1)
	   || ((fdptxt = open (argv[2], O_RDONLY)) == -1)) {
    if (errno == ENOENT) {
      usage (argv[0]);
    }
    else {
      perror (argv[0]);
      
      exit (-1);
    }
  }
  else {
    setprogname (argv[0]);
    
    /* Import symmetric key from argv[1] */
    if (!(import_sk_from_file (&raw_sk, &raw_len, fdsk))) {
      printf ("%s: no symmetric key found in %s\n", argv[0], argv[1]);
      
      close (fdsk);
      exit (2);
    }
    close (fdsk);

    /* Enough setting up---let's get to the crypto... */
    if (argc>4)
       encrypt_file_ecb (argv[3], raw_sk, raw_len, fdptxt); 
    else
        encrypt_file (argv[3], raw_sk, raw_len, fdptxt);    

    /* scrub the buffer that's holding the key before exiting */
    /* YOUR CODE HERE */
    scrub_buffer(raw_sk);


    close (fdptxt);
  }

  return 0;
}
