
#import <Foundation/Foundation.h>


@interface DDRSAWrapper : NSObject

#pragma mark - SecKeyRef
- (BOOL)generateSecKeyPairWithKeySize:(NSUInteger)keySize publicKeyRef:(SecKeyRef *)publicKeyRef privateKeyRef:(SecKeyRef *)privateKeyRef;

- (NSData *)publicKeyBitsFromSecKey:(SecKeyRef)givenKey;
- (SecKeyRef)publicSecKeyFromKeyBits:(NSData *)givenData;

- (NSData *)privateKeyBitsFromSecKey:(SecKeyRef)givenKey;
- (SecKeyRef)privateSecKeyFromKeyBits:(NSData *)givenData;


- (NSData *)encryptWithKey:(SecKeyRef)key plainData:(NSData *)plainData padding:(SecPadding)padding;
- (NSData *)decryptWithKey:(SecKeyRef)key cipherData:(NSData *)cipherData padding:(SecPadding)padding;

/*
     尽量不要直接使用，要根据场景对数据进行处理
 */
- (NSData *)decryptWithPublicKey:(SecKeyRef)publicKey cipherData:(NSData *)cipherData;
#pragma mark - 指数和模数
- (NSData *)getPublicKeyExp:(NSData *)pk;
- (NSData *)getPublicKeyMod:(NSData *)pk ;
- (SecKeyRef)publicKeyDataWithMod:(NSData *)modBits exp:(NSData *)expBits;
@end
