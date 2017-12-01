#include "pv.h"
#include "errno.h"


void decrypt_file_ecb (const char *ptxt_fname,void *raw_sk, size_t raw_len, int fin, int file_size){
   /*TODO: Mac? CBC or ECB or what?*/
   int ptxt=0;
   int bytes_read=0;
   int bytes_total_read=0;
   int num_blocks=0;

   aes_ctx aesEnc;

   char ptxt_buf[CCA_STRENGTH], buf[CCA_STRENGTH];

   char*sk_enc;
   int j=0;

   if ((ptxt = open(ptxt_fname, O_WRONLY|O_TRUNC|O_CREAT, 0600))==-1){
      perror(getprogname());
      scrub_buffer(raw_sk);
      exit(-1);
   }

   sk_enc = raw_sk;
   aes_setkey(&aesEnc, sk_enc, CCA_STRENGTH);

   num_blocks = file_size/CCA_STRENGTH; /*-1 if we add a MAC*/

   for(j=0; j<num_blocks; ++j){
      bytes_read = read(fin, buf, CCA_STRENGTH); /*read the cipher text 16 bytes at a time*/
      if(bytes_read != CCA_STRENGTH){
         scrub_buffer(raw_sk);
         exit(-1);
      }

      aes_decrypt(&aesEnc, ptxt_buf, buf);/*Invert aes to decrypt buf into ptxt*/
      if(j!=num_blocks-1){
        (void) (write(ptxt, ptxt_buf, CCA_STRENGTH)+1);
        bytes_total_read+= CCA_STRENGTH;
      }
      /*MAC stuff?*/
   }
   /*This doesnt work, trying to strip the null terms off*/
   for(j=CCA_STRENGTH-1; ptxt_buf[j]==0; j--);
   (void) (write(ptxt, ptxt_buf, j+1)+1);
}

   
    
    
void decrypt_file (const char *ptxt_fname, const char *ctxt_fname, void *raw_sk, size_t raw_len, int fin, int file_size){
  /*************************************************************************** 
   * Task: Read the ciphertext from the file descriptor fin, decrypt it using
   *       sk, and place the resulting plaintext in a file named ptxt_fname.
   *
   * This procedure basically `undoes' the operations performed by pv_encrypt;
   * it expects a ciphertext featuring the following structure (please refer 
   * to the comments in pv_encrypt.c for more details):
   *
   *
   *         +--------------------------+---+
   *         |             Y            | W |
   *         +--------------------------+---+
   *
   * where Y = AES-CTR (K_CTR, plaintext)
   *       W = AES-CBC-MAC (K_MAC, Y)
   *
   */

  int ptxt = 0;
  int bytes_read=0;
  int bytes_total_read=0;
  int num_blocks=0;

  aes_ctx aesEnc, aesMac;

  char ptxt_buf[CCA_STRENGTH], buf[CCA_STRENGTH];
  char ctr[CCA_STRENGTH];
  char mac_buf[CCA_STRENGTH], mac_buf_tmp[CCA_STRENGTH];

  char *sk_enc, *sk_mac;
  int i=0, j=0;

  /* use the first part of the symmetric key for the AES-CTR decryption ...*/
  /* ... and the second for the AES-CBC-MAC */

  if ((ptxt = open (ptxt_fname, O_WRONLY|O_TRUNC|O_CREAT, 0600)) == -1) {
    perror (getprogname ());

    /* scrub the buffer that's holding the key before exiting */
    /* YOUR CODE HERE */
    scrub_buffer(raw_sk);

    exit (-1);
  }

  /* get file size in bytes:*/


  /*printf("File size: %i\n", file_size);*/

  sk_enc = raw_sk;
  aes_setkey(&aesEnc, sk_enc, CCA_STRENGTH);
  /* ... and the second part for the AES-CBC-MAC */

  sk_mac = raw_sk+CCA_STRENGTH;
  aes_setkey(&aesMac, sk_mac, CCA_STRENGTH);


  /* First, read the IV (Initialization Vector) */
  (void) (read(fin, ctr, CCA_STRENGTH)+1);

  num_blocks = file_size / CCA_STRENGTH-2;
  bytes_total_read = CCA_STRENGTH;

  /* SETUP CBC-MAC */
  /* YOUR CODE HERE */
  aes_encrypt(&aesMac, mac_buf, ctr);

  for(j=0; j<num_blocks; ++j) {
    inc_counter(ctr);
    bytes_read = read(fin, buf, CCA_STRENGTH);
    if(bytes_read != CCA_STRENGTH) {
      /* Error: shut down everything - scrub buffers*/
      /* YOUR CODE HERE */
      scrub_buffer(raw_sk);

      exit(-1);
    }

    aes_encrypt(&aesEnc, ptxt_buf, ctr);
    for(i=0; i<CCA_STRENGTH; ++i) {
      ptxt_buf[i] = ptxt_buf[i] ^ buf[i];
    }
    (void) (write(ptxt, ptxt_buf, CCA_STRENGTH)+1);
    bytes_total_read += CCA_STRENGTH;

    /* COMPUTE CBC-MAC AS YOU GO */
    /* YOUR CODE HERE */
    for(i=0; i<CCA_STRENGTH; ++i) {
      mac_buf[i] = mac_buf[i] ^ buf[i];
    }
    aes_encrypt(&aesMac, mac_buf_tmp, mac_buf);
    for(i=0; i<CCA_STRENGTH; ++i) {
      mac_buf[i] = mac_buf_tmp[i];
    }
  }
  inc_counter(ctr);

  /* now read the last block of size (file_size-CCA_STR-bytes_total_read)*/
  (void) (read(fin, buf, file_size-CCA_STRENGTH-bytes_total_read)+1);
  /* pad rest with zeros:*/
  for(i=file_size-CCA_STRENGTH-bytes_total_read; i<CCA_STRENGTH; ++i)
    buf[i] = 0;
  
  /* and decrypt:*/
  aes_encrypt(&aesEnc, ptxt_buf, ctr);
  for(i=0; i<CCA_STRENGTH; ++i) {
    ptxt_buf[i] = ptxt_buf[i] ^ buf[i];
  }

  (void) ( write(ptxt, ptxt_buf, file_size-CCA_STRENGTH-bytes_total_read)+1);

  close(ptxt);

  /* COMPUTE LAST BLOCK OF CBC-MAC */
  /* YOUR CODE HERE */
  aes_encrypt(&aesEnc, ptxt_buf, ctr);
  for(i=file_size-CCA_STRENGTH-bytes_total_read; i<CCA_STRENGTH; ++i)
    buf[i] = ptxt_buf[i];

  for(i=0; i <CCA_STRENGTH; ++i) {
    mac_buf[i] = mac_buf[i] ^ buf[i];
  }
  aes_encrypt(&aesMac, mac_buf_tmp, mac_buf); 
  for(i=0; i<CCA_STRENGTH; ++i){
    mac_buf[i] = mac_buf_tmp[i];
  }
  /* CHECK CBC-MAC IS CORRECT BY COMPARING YOUR RESULT COMPUTED HERE */
  /* WITH THE LAST CCA_STRENGTH BYTES IN THE FILE (READ THEM IN) */
  /* IF IT DOESN'T MATCH, DELETE THE C-TEXT FILE! */

  /* YOUR CODE HERE */
  (void) (read(fin, buf, CCA_STRENGTH)+1);
  int match = 0;
  for (i=0;i<CCA_STRENGTH; i++){
    match = mac_buf[i] == buf[i];
    if (!match){
        printf("Mac invalid\n");
        /* this is not done*/
        /*(void) (ftruncate(fin, 0)+1);*/
        remove(ctxt_fname);
        return;
    }
  }
  

}

void 
usage (const char *pname)
{
  printf ("Simple File Decryption Utility\n");
  printf ("Usage: %s SK-FILE CTEXT-FILE PTEXT-FILE\n", pname);
  printf ("       Exits if either SK-FILE or CTEXT-FILE don't exist, or\n");
  printf ("       if a symmetric key sk cannot be found in SK-FILE.\n");
  printf ("       Otherwise, tries to use sk to decrypt the content of\n");
  printf ("       CTEXT-FILE: upon success, places the resulting plaintext\n");
  printf ("       in PTEXT-FILE; if a decryption problem is encountered\n"); 
  printf ("       after the processing started, PTEXT-FILE is truncated\n");
  printf ("       to zero-length and its previous content is lost.\n");

  exit (1);
}

int 
main (int argc, char **argv)
{
  int fdsk, fdctxt;
  char *sk = NULL;
  size_t sk_len = 0;
  int file_size=0;

  FILE* f = 0;
  if(argc < 4) {
    usage(argv[0]);
  }
  /* get file size of ctxt */
  f = fopen(argv[2], "r");
  fseek(f, 0, SEEK_END);
  file_size = ftell(f);
  fclose(f);

  if (argc < 4) {
    usage (argv[0]);
  }   /* Check if argv[1] and argv[2] are existing files */
  else if (((fdsk = open (argv[1], O_RDONLY)) == -1)
	   || ((fdctxt = open (argv[2], O_RDONLY)) == -1)) {
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
    if (!(sk = import_sk_from_file (&sk, &sk_len, fdsk))) {
      printf ("%s: no symmetric key found in %s\n", argv[0], argv[1]);
      
      close (fdsk);
      exit (2);
    }
    close (fdsk);

    /* Enough setting up---let's get to the crypto... */
    if (argc > 4)
        decrypt_file_ecb(argv[3], sk, sk_len, fdctxt, file_size); 
    else
        decrypt_file(argv[3],argv[2], sk, sk_len, fdctxt, file_size);    

    /* scrub the buffer that's holding the key before exiting */
    scrub_buffer(sk);

    close (fdctxt);
  }

  return 0;
}
