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

#include <cstdarg>
#include <cstdio>
#include <cstring>

#include <unistd.h>
#include <sys/uio.h>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>


void ka_print_attribute_list(const SecKeychainAttributeList *p_list)
{
  printf("count: %u\n", p_list->count);
  
  
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
  
  
  const char *itemName = argv[1];
  
  OSStatus status = 0;
  SecKeychainItemRef itemRef = 0;
  SecKeychainSearchRef searchRef = 0;
  
  
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
  
  if(status != noErr)
  {
searchFailed:
    if(searchRef)
      CFRelease(searchRef);
    
    if(itemRef)
      CFRelease(itemRef);
    
    // Maybe show the full name of the error
    fprintf(stderr, "Search for item named %s failed: %d\n",
        itemName, (int)status);
    
    return 1;
  }
  
  
  SecItemClass itemClass;
  UInt32 length;
  void *outData;
  SecKeychainAttributeList *attrListPtr;
  
  
  for(;;)
  {
    status = SecKeychainSearchCopyNext(
        searchRef, &itemRef);
    
    if(status != noErr)
      break;
    
    
    SecKeychainAttribute attrz[2];
    attrz[0].tag = kSecLabelItemAttr;
    attrz[1].tag = kSecKeyKeySizeInBits;
    
    SecKeychainAttributeList attrList;
    attrList.count = 1;
    attrList.attr = attrz;
    
    status = SecKeychainItemCopyContent(
        itemRef, &itemClass, &attrList, &length, &outData);
    
    
    // status = SecKeychainItemCopyAttributesAndData(
    //     itemRef,
    //     NULL,
    //     &itemClass,
    //     &attrListPtr,
    //     &length,
    //     NULL);
    
    
    
    if(status != noErr)
      break;
    
    printf("item class: ");
    
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
    case CSSM_DL_DB_RECORD_PUBLIC_KEY:
      printf("CSSM_DL_DB_RECORD_PUBLIC_KEY");
      break;
    case CSSM_DL_DB_RECORD_PRIVATE_KEY:
      printf("CSSM_DL_DB_RECORD_PRIVATE_KEY");
      break;
    case CSSM_DL_DB_RECORD_SYMMETRIC_KEY:
      printf("CSSM_DL_DB_RECORD_SYMMETRIC_KEY");
      break;
    case CSSM_DL_DB_RECORD_ALL_KEYS:
      printf("CSSM_DL_DB_RECORD_ALL_KEYS");
      break;
    default:
      printf("Unknown item class: %lu", itemClass);
    }
    
    printf("\n");
    
    // ka_print_attribute_list(attrListPtr);
    
    printf("<%s> (%u)\n", (char*)outData, length);
    // SecKeychainItemFreeContent(); each time after a CopyContent
    
    const CSSM_KEY *cssmKeyPtr;
    
    status = SecKeyGetCSSMKey(
       (SecKeyRef)itemRef, &cssmKeyPtr);
    
    
    
    printf("status: %d size: %lu data: %s size: %i\n",
        status, cssmKeyPtr->KeyData.Length, attrz[0].data,
        cssmKeyPtr->KeyHeader.LogicalKeySizeInBits);
    
    
    SecKeyImportExportParameters keyParams;
    keyParams.version = SEC_KEY_IMPORT_EXPORT_PARAMS_VERSION;
    keyParams.flags = 0; // kSecKeySecurePassphrase
    keyParams.passphrase = CFSTR("1234");
    keyParams.alertTitle = CFSTR("TITLE");
    keyParams.alertPrompt = CFSTR("PROMPT");
    
    
    // uint32_t                version;
    // SecKeyImportExportFlags flags;
    // CFTypeRef               passphrase;
    // CFStringRef             alertTitle;
    // CFStringRef             alertPrompt;
    
    
    
    CFDataRef exportedData;
    
    status = SecKeychainItemExport(
        itemRef,
        kSecFormatWrappedPKCS8,
        kSecItemPemArmour,
        &keyParams,
        &exportedData);
      
    printf("status: %d\n", status);
    
    if(status == noErr)
    {
      write(fileno(stdout),
          CFDataGetBytePtr(exportedData), CFDataGetLength(exportedData));

      // Now decrypt it with openssl, see crypto(3)
      
    }
    
    
  }
  
  if(status != errSecItemNotFound)
    goto searchFailed;
  
  
  // 
  // SecKeychainSearchCopyNext(
  //    SecKeychainSearchRef searchRef,
  //    SecKeychainItemRef *itemRef
  // );
  // 
  // 
  // CFRelease();
  // 
  // 
  // status1 = SecKeychainFindGenericPassword(
  //     NULL,           // default keychain
  //     strlen(argv[1]),             // length of service name
  //     argv[1],   // service name
  //     0,             // length of account name
  //     "torsten.becker@gmail.com",   // account name
  //     &passwordLength, // length of password
  //     &passwordData,   // pointer to password data
  //     &itemRef         // the item reference
  // );
  // 
  // 
  // //If call was successful, authenticate user and continue
  // if(status1 == noErr)       
  // {
  //   //Free the data allocated by SecKeychainFindGenericPassword:
  //   SecKeychainItemFreeContent(
  //       NULL,           // No attribute data to release
  //       &passwordData    // Release data buffer allocated by
  //   );
  //   
  //   printf("Hmm: %s\n", passwordData);
  // }
  // else
  //   printf("Error: %d\n", status1);
  
  
  return 0;
}
