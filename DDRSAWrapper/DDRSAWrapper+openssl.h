//
//  DDRSAWrapper+openssl.h
//  RSADemo
//
//  Created by 张桂杨 on 2017/10/27.
//  Copyright © 2017年 Ive. All rights reserved.
//

#import "DDRSAWrapper.h"
#import <openssl/rsa.h>

@interface DDRSAWrapper (openssl)
#pragma mark - openssl

+ (BOOL)generateRSAKeyPairWithKeySize:(int)keySize publicKey:(RSA **)publicKey privateKey:(RSA **)privateKey;

+ (RSA *)openssl_publicKeyFromBase64:(NSString *)publicKey;
+ (RSA *)openssl_privateKeyFromBase64:(NSString *)privateKey;
+ (RSA *)openssl_publicKeyFromPEM:(NSString *)publicKeyPEM;
+ (RSA *)openssl_privateKeyFromPEM:(NSString *)privatePEM;

+ (NSData *)openssl_encryptWithPublicKey:(RSA *)publicKey plainData:(NSData *)plainData padding:(int)padding;
+ (NSData *)openssl_decryptWithPrivateKey:(RSA *)privateKey cipherData:(NSData *)cipherData padding:(int)padding;

+ (NSData *)openssl_encryptWithPrivateRSA:(RSA *)privateKey plainData:(NSData *)plainData padding:(int)padding;
+ (NSData *)openssl_decryptWithPublicKey:(RSA *)publicKey cipherData:(NSData *)cipherData padding:(int)padding;

+ (NSString *)base64EncodedStringPublicKey:(RSA *)publicKey;
+ (NSString *)base64EncodedStringPrivateKey:(RSA *)privateKey;

+ (RSA *)openssl_publicKeyFormMod:(NSString *)mod exp:(NSString *)exp;
+ (char *)openssl_expFromPublicKey:(RSA *)publicKey;
+ (char *)openssl_modFromPublicKey:(RSA *)publicKey;
@end
