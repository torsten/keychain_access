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

#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>


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
  
  
  SecKeyImportExportParameters keyParams;
  keyParams.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
  keyParams.flags = 0; // kSecKeySecurePassphrase
  keyParams.passphrase = CFSTR("1234");
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
    write(fileno(stdout),
        CFDataGetBytePtr(exportedData), CFDataGetLength(exportedData));
  
    // Now decrypt it with openssl, see crypto(3)
  
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
  printf("Not yet implemented.\n");
  return 1;
}


int main(int argc, char const *argv[])
{
  if(argc != 2)
  {
    fprintf(stderr, "Usage: keychain_access [-vh] item_name\n");
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
    printf("This is keychain_access version v0 (f4ad).\n");
    return 0;
  }
  
  
  const char *itemName = argv[1];
  
  OSStatus status = 0;
  SecKeychainSearchRef searchRef = 0;
  SecKeychainItemRef itemRef = 0;
  
  
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
  
  
  SecItemClass itemClass;
  
  
  // UInt32 length;
  // void *outData;
  
  // SecKeychainAttributeList *attrListPtr;
  
  
  // SecKeychainAttribute attrz[2];
  // attrz[0].tag = kSecLabelItemAttr;
  
  // SecKeychainAttributeList attrList;
  // attrList.count = 0;
  // attrList.attr = attrz;
  
  status = SecKeychainItemCopyContent(
      itemRef, &itemClass, NULL, NULL, NULL);
  
  
  // status = SecKeychainItemCopyAttributesAndData(
  //     itemRef,
  //     NULL,
  //     &itemClass,
  //     &attrListPtr,
  //     &length,
  //     NULL);
  
  
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
    case kSecCertificateItemClass:
      printf("kSecCertificateItemClass");
      break;
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
