/*
 * Copyright (C) 2008 Torsten Becker. All rights reserved.
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
 * keychain_access.cc, created on 04-Nov-2008.
 */

// http://ianhenderson.org/repos/delimport/Keychain/

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
  
  
  // CFDataRef exportKey;
  // exportKey = CFDataCreate(NULL, "1234", 4);
  
  
  SecKeyImportExportParameters keyParams;
  keyParams.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
  keyParams.flags = 0; // kSecKeySecurePassphrase
  keyParams.passphrase = CFSTR("12345"); //exportKey;
  keyParams.alertTitle = 0; // CFSTR("TITLE");
  keyParams.alertPrompt = 0; // CFSTR("PROMPT");
  
  
  // uint32_t                version;
  // SecKeyImportExportFlags flags;
  // CFTypeRef               passphrase;
  // CFStringRef             alertTitle;
  // CFStringRef             alertPrompt;
  
  
  
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
  printf("Public keys are not yet implemented.\n");
  return 1;
}


int main(int argc, char const *argv[])
{
  if(argc != 2)
  {
    fprintf(stderr, "Usage: keychain_access [-v] item_name\n");
    return 1;
    
    // TODO:
    // -t for "type"
    // -a to limit to a certain attribute
    // -o to specify output format
    // -v version
    // -h help
    // --pem
    // -P for encrypting the key with passphrase
    // -k keyname
    // -p pwname for searching a password
  }
  
  if(strcmp(argv[1], "-v") == 0)
  {
#ifndef KCA_VERSION
#define KCA_VERSION "v0"
#endif
#ifndef KCA_REV
#define KCA_REV "n/a"
#endif
    printf("This is keychain_access "KCA_VERSION" ("KCA_REV").\n");
    return 0;
  }
  
  
  const char *itemName = argv[1];
  
  OSStatus status = 0;
  SecKeychainSearchRef searchRef = 0;
  SecKeychainItemRef itemRef = 0;
  SecItemClass itemClass;
  
  SecKeychainAttribute labelAttr;
  labelAttr.tag = kSecLabelItemAttr;
  labelAttr.length = strlen(itemName);
  labelAttr.data = (void*)itemName;
  
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
      fprintf(stderr, "Could not find a item named %s.\n", itemName);
    
    else
      fprintf(stderr, errorMessage,
          itemName, (int)status);
    
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
    return kca_print_private_key(itemRef, NULL);
  
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
