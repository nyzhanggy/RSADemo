//
//  RSADemoTests.m
//  RSADemoTests
//
//  Created by 张桂杨 on 2017/11/23.
//  Copyright © 2017年 Ive. All rights reserved.
//

#import <XCTest/XCTest.h>
#import <openssl/rsa.h>
#import "DDRSAWrapper.h"
#import "DDRSAWrapper+openssl.h"

@interface RSADemoTests : XCTestCase {
    
    DDRSAWrapper *_wrapper;
    
    
    
    NSString *_plainString;
}

@end

@implementation RSADemoTests

- (void)setUp {
    [super setUp];
    // Put setup code here. This method is called before the invocation of each test method in the class.
    _wrapper = [[DDRSAWrapper alloc] init];
    _plainString = @"中文dsakdskahdskah中文dksahdkjashdsadjsajdlsajkl123890210890%&*(*()_@#$%^&*()*&^%$hjdksakdhksjhkfhjsk0.164103201中文3dsakdskahdskahdksahdkjashdsadjsajdlsajkl123890210890%&*(*()_@#$%^&*()*&^%$hjdksakdhksjhkfhjsk0.1641032013dsakdska中文hdskahdksahdkjashdsadjsajdlsajkl123890210890%&*(*()_@#$%^&*()*&^%$hjdksakdhksjhkfhjsk0.1641032013dsakdskahdskahd中文sahdkjashdsadjsajdlsajkl123890210890%&*(*()_@#$%^&*()*&^%$hjdksakdhksjhkfhjsk0.164103201中文3dsakdskahdskahdksahdkjashdsadjsajdlsajkl123890210890%&*(*()_@#$%^&*()*&^%$hjdksakdhksjhkfhjsk0.1641032013中文dsakdskahdskahdk中文sahdkjashdsadjsajdlsajkl123890210890%&*(*()_@#$%^&*()*&^%$hjdksakdhksjhkfhjsk0.1641032013dsakdskahdskahdksa中文hdkjashdsadjsajdlsajkl123890210890%&*(*()_@#$%^&*()*&^%$hjdksakdhksjhkfhjsk0.1641032013dsakdskahdskahdksahdkjashdsad中文jsajdlsajkl12389021中文0890%&*(*()_@#$%^&*()*&^%$hjdksakdhksjhkfhjsk0.1641032013";
    
}

- (void)tearDown {
    // Put teardown code here. This method is called after the invocation of each test method in the class.
    [super tearDown];
}

/*
 公钥加密私钥解密
 */
- (void)test_SecRef_PubcliKeyEncryptAndPrivateKeyDecrypt {
    for (NSInteger i = 0; i< 100; i ++) {
        SecKeyRef publicKeyRef = NULL;
        SecKeyRef privateKeyRef = NULL;
        
        BOOL result = [_wrapper generateSecKeyPairWithKeySize:1024 publicKeyRef:&publicKeyRef privateKeyRef:&privateKeyRef];
        NSAssert(result, @"生成密钥对失败");
        
        NSData *plainData = [_plainString dataUsingEncoding:NSUTF8StringEncoding];
        NSData *cipherData = [_wrapper encryptWithKey:publicKeyRef plainData:plainData padding:kSecPaddingPKCS1];
        
        NSData *resultData = [_wrapper decryptWithKey:privateKeyRef cipherData:cipherData padding:kSecPaddingPKCS1];
        
        NSString *outputPlainString = [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
        NSAssert([outputPlainString isEqualToString:_plainString], @"公钥加密私钥解密失败");
    }
}

- (void)test_SecRef_PubcliKeyEncryptAndPrivateKeyDecrypt_BiggerThanModuleData {
    for (NSInteger i = 0; i< 100; i ++) {
        SecKeyRef publicKeyRef = NULL;
        SecKeyRef privateKeyRef = NULL;
        
        BOOL result = [_wrapper generateSecKeyPairWithKeySize:1024 publicKeyRef:&publicKeyRef privateKeyRef:&privateKeyRef];
        NSAssert(result, @"生成密钥对失败");
        NSData *pd = [_wrapper publicKeyBitsFromSecKey:publicKeyRef];
        
        NSData *moduleData = [[_wrapper getPublicKeyMod:pd] subdataWithRange:NSMakeRange(1, 127)];
        
        const char fixByte = 0xff;
        NSMutableData * biggerThanModuleData = [NSMutableData dataWithBytes:&fixByte length:1];
        [biggerThanModuleData appendData:moduleData];
        
        NSData *cipherData = [_wrapper encryptWithKey:publicKeyRef plainData:biggerThanModuleData padding:kSecPaddingNone];
        NSData *resultData = [_wrapper decryptWithKey:privateKeyRef cipherData:cipherData padding:kSecPaddingNone];
        
        NSAssert([resultData isEqualToData:biggerThanModuleData], @"公钥加密私钥解密失败");
    }
    
}

/*
 私钥加密公钥解密
 */
- (void)test_SecRef_PrivateKeyEncryptAndPubcliKeyDecrypt {
    SecKeyRef publicKeyRef = NULL;
    SecKeyRef privateKeyRef = NULL;
    
    for (NSInteger i = 0; i< 100; i ++) {
        BOOL result = [_wrapper generateSecKeyPairWithKeySize:1024 publicKeyRef:&publicKeyRef privateKeyRef:&privateKeyRef];
        NSAssert(result, @"生成密钥对失败");
        
        NSData *plainData = [_plainString dataUsingEncoding:NSUTF8StringEncoding];
        
        NSData *cipherData = [_wrapper encryptWithPrivateKey:privateKeyRef plainData:plainData];
        
        NSData *resultData = [_wrapper decryptWithPublicKey:publicKeyRef cipherData:cipherData];
        
        NSString *outputPlainString = [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
        
        NSAssert([outputPlainString isEqualToString:_plainString], @"私钥加密公钥解密失败");
    }

}

/*
 公钥加密私钥解密
 */
- (void)test_Openssl_PubcliKeyEncryptAndPrivateKeyDecrypt {
    for (NSInteger i = 0; i< 100; i ++) {
        RSA *publicKey = nil;
        RSA *privateKey = nil;
        
        BOOL result = [DDRSAWrapper generateRSAKeyPairWithKeySize:2048 publicKey:&publicKey privateKey:&privateKey];
        NSAssert(result, @"生成密钥对失败");
        
        NSData *plainData = [_plainString dataUsingEncoding:NSUTF8StringEncoding];
        
        NSData *cipherData = [DDRSAWrapper openssl_encryptWithPublicKey:publicKey
                                                              plainData:plainData
                                                                padding:RSA_PKCS1_PADDING];
        
        NSData *resultData = [DDRSAWrapper openssl_decryptWithPrivateKey:privateKey
                                                             cipherData:cipherData
                                                                padding:RSA_PKCS1_PADDING];
        
        NSString *outputPlainString = [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
        
        NSAssert([outputPlainString isEqualToString:_plainString], @"公钥加密私钥解密失败");
    }
}

/*
 私钥加密公钥解密
 */
- (void)test_Openssl_PrivateKeyEncryptAndPubcliKeyDecrypt {
    for (NSInteger i = 0; i< 100; i ++) {
        RSA *publicKey = nil;
        RSA *privateKey = nil;
        
        BOOL result = [DDRSAWrapper generateRSAKeyPairWithKeySize:1024 publicKey:&publicKey privateKey:&privateKey];
        NSAssert(result, @"生成密钥对失败");
        
        
        NSData *plainData = [_plainString dataUsingEncoding:NSUTF8StringEncoding];
        
        NSData *cipherData = [DDRSAWrapper openssl_encryptWithPrivateRSA:privateKey
                                                               plainData:plainData
                                                                 padding:RSA_PKCS1_PADDING];
        
        NSData *resultData = [DDRSAWrapper openssl_decryptWithPublicKey:publicKey
                                                            cipherData:cipherData
                                                               padding:RSA_PKCS1_PADDING];
        
        NSString *outputPlainString = [[NSString alloc] initWithData:resultData encoding:NSUTF8StringEncoding];
        
        NSAssert([outputPlainString isEqualToString:_plainString], @"公钥加密私钥解密失败");
    }
}



@end
