#include <cstdarg>
#include <cstdio>
#include <cstring>

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>


int main(int argc, char const *argv[])
{
  if(argc != 2)
  {
    fprintf(stderr, "Usage: keychain_access item_name\n");
    return 1;
    
    // TODO:
    // * -t for "type"
    // * -a to limit to a certain attribute
    // * -o to specify output format
  }
  
  
  const char *itemName = argv[1];
  OSStatus status = 0;
  SecKeychainItemRef itemRef = 0;
  SecKeychainSearchRef searchRef = 0;
  
  
  status = SecKeychainSearchCreateFromAttributes(
      NULL, // Search all kechains
      CSSM_DL_DB_RECORD_ALL_KEYS,
      NULL, // Get all attributes
      &searchRef);
  
  if(status != noErr)
  {
searchFailed:
    if(searchRef)
      CFRelease(searchRef);
    
    fprintf(stderr, "Search for item named %s failed: %d\n",
        itemName, status);
    
    return 1;
  }
  
  for(;;)
  {
    status = SecKeychainSearchCopyNext(
        searchRef, &itemRef);
    
    if(status != noErr)
      break;
    
    
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




#if 0



#include <Security/Security.h>
#include <CoreServices/CoreServices.h>
 
//Call SecKeychainAddGenericPassword to add a new password to the keychain:
OSStatus StorePasswordKeychain (void* password,UInt32 passwordLength)
{
 OSStatus status;
 status = SecKeychainAddGenericPassword (
                NULL,            // default keychain
                10,              // length of service name
                "SurfWriter",    // service name
                10,              // length of account name
                "MyUserAcct",    // account name
                passwordLength,  // length of password
                password,        // pointer to password data
                NULL             // the item reference
    );
    return (status);
 }
 
//Call SecKeychainFindGenericPassword to get a password from the keychain:
OSStatus GetPasswordKeychain (void *passwordData,UInt32 *passwordLength,
                                                SecKeychainItemRef *itemRef)
{
 OSStatus status1 ;
 
 
 status1 = SecKeychainFindGenericPassword (
                 NULL,           // default keychain
                 10,             // length of service name
                 "SurfWriter",   // service name
                 10,             // length of account name
                 "MyUserAcct",   // account name
                 passwordLength,  // length of password
                 passwordData,   // pointer to password data
                 itemRef         // the item reference
    );
     return (status1);
 }
 
//Call SecKeychainItemModifyAttributesAndData to change the password for
// an item already in the keychain:
OSStatus ChangePasswordKeychain (SecKeychainItemRef itemRef)
{
    OSStatus status;
    void * password = "myNewP4sSw0rD";
    UInt32 passwordLength = strlen(password);
 
 status = SecKeychainItemModifyAttributesAndData (
                 itemRef,         // the item reference
                 NULL,            // no change to attributes
                 passwordLength,  // length of password
                 password         // pointer to password data
    );
     return (status);
 }
 
 
/* ********************************************************************** */
 
int main (int argc, const char * argv[]) {
    OSStatus status;
    OSStatus status1;
 
     void * myPassword = "myP4sSw0rD";
     UInt32 myPasswordLength = strlen(myPassword);
 
     void *passwordData = nil; // will be allocated and filled in by
                               //SecKeychainFindGenericPassword
     SecKeychainItemRef itemRef = nil;
     UInt32 passwordLength = nil;
 
    status1 = GetPasswordKeychain (&passwordData,&passwordLength,&itemRef);  //Call
                                                //SecKeychainFindGenericPassword
        if (status1 == noErr)       //If call was successful, authenticate user
                                    //and continue.
        {
        //Free the data allocated by SecKeychainFindGenericPassword:
    status = SecKeychainItemFreeContent (
                 NULL,           //No attribute data to release
                 passwordData    //Release data buffer allocated by
                 //SecKeychainFindGenericPassword
    );
 }
 
    if (status1 == errSecItemNotFound) { //Is password on keychain?
    /*
    If password is not on keychain, display dialog to prompt user for
    name and password.
    Authenticate user.  If unsuccessful, prompt user again for name and password.
    If successful, ask user whether to store new password on keychain; if no, return.
    If yes, store password:
    */
    status = StorePasswordKeychain (myPassword,myPasswordLength); //Call
                                                      // SecKeychainAddGenericPassword
    return (status);
    }
 
    /*
    If password is on keychain, authenticate user.
    If authentication succeeds, return.
    If authentication fails, prompt user for new user name and password and
     authenticate again.
    If unsuccessful, prompt again.
    If successful, ask whether to update keychain with new information.  If no, return.
    If yes, store new information:
    */
    status = ChangePasswordKeychain (itemRef);  //Call
                                            // SecKeychainItemModifyAttributesAndData
    if (itemRef) CFRelease(itemRef);
    return (status);
 
 }

#endif
