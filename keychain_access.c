/*
 * Copyright (C) 2008 Torsten Becker <torsten.becker@gmail.com>.
 * All rights reserved.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
 * THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER 
 * IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * keychain_access.c, created on 31-Oct-2008.
 */

#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/pkcs12.h>


/**
 *  @param p_password NULL here means no password.
 */
int kca_print_private_key(SecKeychainItemRef p_keyItem,
    const char *p_password)
{
  // SecKeychainItemFreeContent(); each time after a CopyContent
  
  // const CSSM_KEY *cssmKeyPtr;
  // 
  // status = SecKeyGetCSSMKey(
  //    (SecKeyRef)itemRef, &cssmKeyPtr);
  // 
  // printf("status: %d size: %lu data: %s size: %i\n",
  //     status, cssmKeyPtr->KeyData.Length, attrz[0].data,
  //     cssmKeyPtr->KeyHeader.LogicalKeySizeInBits);
  
  
  CFDataRef exportKey;
  
  if(p_password)
    exportKey = CFDataCreate(
        NULL, (unsigned char*)p_password, strlen(p_password));
  
  else
    exportKey = CFDataCreate(NULL, (unsigned char*)"12345", 5);
  
  
  SecKeyImportExportParameters keyParams;
  keyParams.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
  keyParams.flags = 0; // kSecKeySecurePassphrase
  keyParams.passphrase = exportKey;
  keyParams.alertTitle = 0;
  keyParams.alertPrompt = 0;
  
  
  CFDataRef exportedData;
  OSStatus status;
  
  status = SecKeychainItemExport(
      p_keyItem,
      kSecFormatWrappedPKCS8,
      kSecItemPemArmour,
      &keyParams,
      &exportedData);
  
  if(status == noErr)
  {
    // If the user did set a password, just print the key
    if(p_password)
    {
      write(fileno(stdout),
          CFDataGetBytePtr(exportedData), CFDataGetLength(exportedData));
      
      return 0;
    }
    
    // It no password was given, use openssl to create a key with no password...
    
    int opensslPipe[2];
    if(pipe(opensslPipe) != 0)
    {
      perror("pipe(2) error");
      return 1;
    }
    
    FILE *fp;
    fp = fdopen(opensslPipe[0], "r");
    if(fp == NULL)
    {
      perror("fdopen(3) error");
      return 1;
    }
    
    ssize_t written;
    written = write(opensslPipe[1],
        CFDataGetBytePtr(exportedData), CFDataGetLength(exportedData));
    
    if(written < CFDataGetLength(exportedData))
    {
      perror("write(2) error");
      return 1;
    }
    
    // Close pipe, so OpenSSL sees an end
    close(opensslPipe[1]);
    
    // Init OpenSSL
    ERR_load_crypto_strings();
    OpenSSL_add_all_algorithms();
    
    // Read key through this pipe
    X509_SIG *p8;
    p8 = PEM_read_PKCS8(fp, NULL, NULL, NULL);
    
    // Try to decrypt
    PKCS8_PRIV_KEY_INFO *p8inf;
    p8inf = PKCS8_decrypt(p8, "12345", 5);
    
    X509_SIG_free(p8);
    
    
    EVP_PKEY *pkey;
    
    
    if(!p8inf)
    {
      fprintf(stderr, "Error decrypting key\n");
      ERR_print_errors_fp(stderr);
      return 1;
    }
    
    if(!(pkey = EVP_PKCS82PKEY(p8inf)))
    {
      fprintf(stderr, "Error converting key\n");
      ERR_print_errors_fp(stderr);
      return 1;
    }
    
    if(p8inf->broken)
    {
      fprintf(stderr, "Warning: broken key encoding: ");
      
      switch(p8inf->broken)
      {
      case PKCS8_NO_OCTET:
        fprintf(stderr, "No Octet String in PrivateKey\n");
        break;
        
      case PKCS8_EMBEDDED_PARAM:
        fprintf(stderr, "DSA parameters included in PrivateKey\n");
        break;
        
      case PKCS8_NS_DB:
        fprintf(stderr, "DSA public key include in PrivateKey\n");
        break;
        
      default:
        fprintf(stderr, "Unknown broken type\n");
        break;
      }
    }
    
    PKCS8_PRIV_KEY_INFO_free(p8inf);
    
    PEM_write_PrivateKey(stdout, pkey, NULL, NULL, 0, NULL, NULL);
  }
  else
  {
    fprintf(stderr, "Export error: %ld\n", status);
    return 1;
  }
  
  return 0;
}


int kca_print_public_key(SecKeychainItemRef p_keyItem)
{
  CFDataRef exportedData = 0;
  OSStatus status;
  
  SecKeyImportExportParameters keyParams;
  keyParams.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
  keyParams.flags = 0;
  keyParams.passphrase = 0;
  keyParams.alertTitle = 0;
  keyParams.alertPrompt = 0;
  
  status = SecKeychainItemExport(
      p_keyItem,
      0,
      kSecItemPemArmour,
      &keyParams,
      &exportedData);
  
  if(status != noErr || exportedData == 0)
  {
    fprintf(stderr,
        "keychain_access: Exporting public key failed: %ld\n", status);
    return 1;
  }
  
  char *pemBytes = (char*)CFDataGetBytePtr(exportedData);
  
  // Search for the first newline to know where the key data starts
  char *firstNewLine = index(pemBytes, '\n');
  
  if(firstNewLine == NULL)
  {
    // This should not happen in practice, but just in case...
reformat_panic:
    fprintf(stderr, "keychain_access: Panic while reformating pubkey.\n");
    return 1;
  }
  
  int beginDiff = firstNewLine - pemBytes;
  if(beginDiff < 0)
    goto reformat_panic;
  
  
  // Search for the end marker to know where the key data ends
  char *endMarker = strnstr(
      pemBytes, "\n-----END ", CFDataGetLength(exportedData));
  
  if(endMarker == NULL)
    goto reformat_panic;
  
  int endDiff = endMarker - pemBytes;
  if(endDiff < 0)
    goto reformat_panic;
  
  
  // Just print what is between the previous markers with 2 new markers around
  // them, this new markers are acutally compatible with openssl now.
  printf("-----BEGIN PUBLIC KEY-----");
  fflush(stdout);
  
  write(fileno(stdout),
      CFDataGetBytePtr(exportedData) + beginDiff, endDiff - beginDiff);
  
  puts("\n-----END PUBLIC KEY-----");
  
  return 0;
}


int kca_print_key(const char *p_keyName, const char *p_keyPassword)
{
  OSStatus status = 0;
  SecKeychainSearchRef searchRef = 0;
  SecKeychainItemRef itemRef = 0;
  SecItemClass itemClass;

  SecKeychainAttribute labelAttr;
  labelAttr.tag = kSecLabelItemAttr;
  labelAttr.length = strlen(p_keyName);
  labelAttr.data = (void*)p_keyName;

  SecKeychainAttributeList searchList;
  searchList.count = 1;
  searchList.attr = &labelAttr;


  status = SecKeychainSearchCreateFromAttributes(
      NULL, // Search all kechains
      CSSM_DL_DB_RECORD_ANY,
      &searchList,
      &searchRef);


  char *errorMessage = "Search for item named %s failed: %d\n";


  if(status != noErr)
  {
searchFailed:
    if(searchRef)
      CFRelease(searchRef);

    if(itemRef)
      CFRelease(itemRef);

    if(status == errSecItemNotFound)
      fprintf(stderr, "Could not find a item named %s.\n", p_keyName);

    else
      fprintf(stderr, errorMessage,
          p_keyName, (int)status);

    return 1;
  }


  status = SecKeychainSearchCopyNext(
      searchRef, &itemRef);

  if(status != noErr)
    goto searchFailed;

  // TODO: cleanup search



  status = SecKeychainItemCopyContent(
      itemRef, &itemClass, NULL, NULL, NULL);

  if(status != noErr)
  {
    errorMessage = "Copy content failed for %s: %d\n";
    goto searchFailed;
  }


  if(itemClass == CSSM_DL_DB_RECORD_PRIVATE_KEY)
    return kca_print_private_key(itemRef, p_keyPassword);

  else if(itemClass == CSSM_DL_DB_RECORD_PUBLIC_KEY)
    return kca_print_public_key(itemRef);

  else
  {
    printf("Handling ");

    switch(itemClass)
    {
    case kSecInternetPasswordItemClass:
      printf("kSecInternetPasswordItemClass");
      break;
    case kSecGenericPasswordItemClass:
      printf("kSecGenericPasswordItemClass");
      break;
    case kSecAppleSharePasswordItemClass:
      printf("kSecAppleSharePasswordItemClass");
      break;
    // Causes: "warning: overflow in constant expression"
    // case kSecCertificateItemClass:
    //   printf("kSecCertificateItemClass");
    //   break;
    case CSSM_DL_DB_RECORD_SYMMETRIC_KEY:
      printf("CSSM_DL_DB_RECORD_SYMMETRIC_KEY");
      break;
    case CSSM_DL_DB_RECORD_ALL_KEYS:
      printf("CSSM_DL_DB_RECORD_ALL_KEYS");
      break;
    /*
    case CSSM_DL_DB_RECORD_PUBLIC_KEY:
      printf("CSSM_DL_DB_RECORD_PUBLIC_KEY");
      break;
    case CSSM_DL_DB_RECORD_PRIVATE_KEY:
      printf("CSSM_DL_DB_RECORD_PRIVATE_KEY");
      break;
    */
    default:
      printf("unknown item class (%lu)", itemClass);
    }

    printf(" is not yet implemented.\n");

    return 1;
  }


  return 0;
}


void kca_print_help(FILE *p_fp, const char *p_arg0)
{
  fprintf(p_fp,
  "Usage: %s [-vh] [-p <password>] <key_name>\n"
  "Options:\n"
  "  -p <password>   Encrypt exported private keys with <password>.\n"
  "                  The default is to export them without a password.\n"
  "  -h              Show this information.\n"
  "  -v              Print current version number.\n"
  "  <key_name>      The name of the keychain item you want to access.\n"
  "                  Has to be a public or private key.\n",
  p_arg0);
}

void kca_print_version()
{
#ifndef KCA_VERSION
#define KCA_VERSION "v0"
#endif
#ifndef KCA_REV
#define KCA_REV "n/a"
#endif
  
  printf("keychain_access "KCA_VERSION" ("KCA_REV")\n");
}


int main(int p_argc, char **p_argv)
{
  int option;
  const char *keyPassword = NULL;
  
  // TODO:
  // -t for "type"
  // -a to limit to a certain attribute
  // -o to specify output format
  // --pem
  // -k keyname
  // -p pwname for searching a password
  
  const char *arg0 = "keychain_access";
  if(p_argc >= 1)
    arg0 = p_argv[0];
  
  while((option = getopt(p_argc, p_argv, "vhp:")) != -1)
  {
    switch(option)
    {
    case 'h':
      kca_print_help(stdout, arg0);
      return 0;
    
    case 'v':
      kca_print_version();
      return 0;
    
    case 'p':
      keyPassword = optarg;
      break;
      
    case '?':
    default:
      kca_print_help(stderr, arg0);
      return 1;
    }
  }
  
  int argcAfter = p_argc - optind;
  char *keyName = *(p_argv + optind);
  
  if(argcAfter > 1)
  {
    fprintf(stderr, "%s: Too many key names given.\n", arg0);
    kca_print_help(stderr, arg0);
    return 1;
  }
  else if(argcAfter < 1)
  {
    fprintf(stderr, "%s: Missing key name.\n", arg0);
    kca_print_help(stderr, arg0);
    return 1;
  }
  
  return kca_print_key(keyName, keyPassword);
}
