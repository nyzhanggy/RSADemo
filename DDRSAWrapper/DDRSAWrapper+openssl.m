//
//  DDRSAWrapper+openssl.m
//  RSADemo
//
//  Created by 张桂杨 on 2017/10/27.
//  Copyright © 2017年 Ive. All rights reserved.
//

#import "DDRSAWrapper+openssl.h"
#import <openssl/pem.h>

@implementation DDRSAWrapper (openssl)
#pragma mark ---生成密钥对
+ (BOOL)generateRSAKeyPairWithKeySize:(int)keySize publicKey:(RSA **)publicKey privateKey:(RSA **)privateKey {
    if (keySize == 512 || keySize == 1024 || keySize == 2048) {
        RSA *rsa = RSA_generate_key(keySize,RSA_F4,NULL,NULL);
        if (rsa) {
            *privateKey = RSAPrivateKey_dup(rsa);
            *publicKey = RSAPublicKey_dup(rsa);
            if (publicKey && privateKey) {
                return YES;
            }
        }
    }
    
    return NO;
}
#pragma mark ---密钥格式转换
+ (RSA *)openssl_publicKeyFromPEM:(NSString *)publicKeyPEM {
    const char *buffer = [publicKeyPEM UTF8String];
    
    BIO *bpubkey = BIO_new_mem_buf(buffer, (int)strlen(buffer));
    
    RSA *rsaPublic = PEM_read_bio_RSA_PUBKEY(bpubkey, NULL, NULL, NULL);
    
    BIO_free_all(bpubkey);
    return rsaPublic;
}

+ (RSA *)openssl_publicKeyFromBase64:(NSString *)publicKey {
    //格式化公钥
    NSMutableString *result = [NSMutableString string];
    [result appendString:@"-----BEGIN PUBLIC KEY-----\n"];
    int count = 0;
    for (int i = 0; i < [publicKey length]; ++i) {
        
        unichar c = [publicKey characterAtIndex:i];
        if (c == '\n' || c == '\r') {
            continue;
        }
        [result appendFormat:@"%c", c];
        if (++count == 64) {
            [result appendString:@"\n"];
            count = 0;
        }
    }
    [result appendString:@"\n-----END PUBLIC KEY-----"];
    
    return [self openssl_publicKeyFromPEM:result];
    
}

+ (RSA *)openssl_privateKeyFromBase64:(NSString *)privateKey {
    //格式化私钥
    const char *pstr = [privateKey UTF8String];
    int len = (int)[privateKey length];
    NSMutableString *result = [NSMutableString string];
    [result appendString:@"-----BEGIN RSA PRIVATE KEY-----\n"];
    int index = 0;
    int count = 0;
    while (index < len) {
        char ch = pstr[index];
        if (ch == '\r' || ch == '\n') {
            ++index;
            continue;
        }
        [result appendFormat:@"%c", ch];
        if (++count == 64) {
            
            [result appendString:@"\n"];
            count = 0;
        }
        index++;
    }
    [result appendString:@"\n-----END RSA PRIVATE KEY-----"];
    return [self openssl_privateKeyFromPEM:result];
    
}
+ (RSA *)openssl_privateKeyFromPEM:(NSString *)privatePEM {
    
    const char *buffer = [privatePEM UTF8String];
    
    BIO *bpubkey = BIO_new_mem_buf(buffer, (int)strlen(buffer));
    
    RSA *rsaPrivate = PEM_read_bio_RSAPrivateKey(bpubkey, NULL, NULL, NULL);
    BIO_free_all(bpubkey);
    return rsaPrivate;
}

+ (NSString *)base64EncodedStringPublicKey:(RSA *)publicKey {
    if (!publicKey) {
        return nil;
    }
    
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSA_PUBKEY(bio, publicKey);
    
    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    
    NSString *pemString = [NSString stringWithFormat:@"%s",bptr->data];
    BIO_set_close(bio, BIO_NOCLOSE); /* So BIO_free() leaves BUF_MEM alone */
    BIO_free(bio);
    return [self base64EncodedFromPEMFormat:pemString];
}


+ (NSString *)base64EncodedStringPrivateKey:(RSA *)privateKey {
    
    if (!privateKey) {
        return nil;
    }
    
    BIO *bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPrivateKey(bio, privateKey, NULL, NULL, 0, NULL, NULL);
    
    BUF_MEM *bptr;
    BIO_get_mem_ptr(bio, &bptr);
    
    NSString *pemString = [NSString stringWithFormat:@"%s",bptr->data];
    
    BIO_set_close(bio, BIO_NOCLOSE); /* So BIO_free() leaves BUF_MEM alone */
    BIO_free(bio);
    
    return [self base64EncodedFromPEMFormat:pemString];
}

+ (NSString *)base64EncodedFromPEMFormat:(NSString *)PEMFormat
{
    return [[PEMFormat componentsSeparatedByString:@"-----"] objectAtIndex:2];
}

#pragma mark ---加解密
+ (NSData *)openssl_encryptWithPublicKey:(RSA *)publicKey plainData:(NSData *)plainData padding:(int)padding{
    int paddingSize = 0;
    if (padding == RSA_PKCS1_PADDING) {
        paddingSize = RSA_PKCS1_PADDING_SIZE;
    }
    
    int publicRSALength = RSA_size(publicKey);
    double totalLength = [plainData length];
    int blockSize = publicRSALength - paddingSize;
    int blockCount = ceil(totalLength / blockSize);
    size_t publicEncryptSize = publicRSALength;
    NSMutableData *encryptDate = [NSMutableData data];
    for (int i = 0; i < blockCount; i++) {
        NSUInteger loc = i * blockSize;
        int dataSegmentRealSize = MIN(blockSize, totalLength - loc);
        NSData *dataSegment = [plainData subdataWithRange:NSMakeRange(loc, dataSegmentRealSize)];
        char *publicEncrypt = malloc(publicRSALength);
        memset(publicEncrypt, 0, publicRSALength);
        const unsigned char *str = [dataSegment bytes];
        int r = RSA_public_encrypt(dataSegmentRealSize,str,(unsigned char*)publicEncrypt,publicKey,padding);
        if (r < 0) {
            free(publicEncrypt);
            return nil;
        }
        NSData *encryptData = [[NSData alloc] initWithBytes:publicEncrypt length:publicEncryptSize];
        [encryptDate appendData:encryptData];
        
        free(publicEncrypt);
    }
    return encryptDate;
    
    
    
}

+ (NSData *)openssl_decryptWithPrivateKey:(RSA *)privateKey cipherData:(NSData *)cipherData padding:(int)padding{
    
    if (!privateKey) {
        return nil;
    }
    if (!cipherData) {
        return nil;
    }
    int privateRSALenght = RSA_size(privateKey);
    double totalLength = [cipherData length];
    int blockSize = privateRSALenght;
    int blockCount = ceil(totalLength / blockSize);
    NSMutableData *decrypeData = [NSMutableData data];
    for (int i = 0; i < blockCount; i++) {
        NSUInteger loc = i * blockSize;
        long dataSegmentRealSize = MIN(blockSize, totalLength - loc);
        NSData *dataSegment = [cipherData subdataWithRange:NSMakeRange(loc, dataSegmentRealSize)];
        const unsigned char *str = [dataSegment bytes];
        unsigned char *privateDecrypt = malloc(privateRSALenght);
        memset(privateDecrypt, 0, privateRSALenght);
        int ret = RSA_private_decrypt(privateRSALenght,str,privateDecrypt,privateKey,padding);
        if(ret >=0){
            NSData *data = [[NSData alloc] initWithBytes:privateDecrypt length:ret];
            [decrypeData appendData:data];
        }
        free(privateDecrypt);
    }
    
    return decrypeData;
    
    
    
}

+ (NSData *)openssl_encryptWithPrivateRSA:(RSA *)privateKey plainData:(NSData *)plainData padding:(int)padding{
    
    if (!privateKey) {
        return nil;
    }
    if (!plainData) {
        return nil;
    }
    int paddingSize = 0;
    if (padding == RSA_PKCS1_PADDING) {
        paddingSize = RSA_PKCS1_PADDING_SIZE;
    }
    
    int privateRSALength = RSA_size(privateKey);
    double totalLength = [plainData length];
    int blockSize = privateRSALength - paddingSize;
    int blockCount = ceil(totalLength / blockSize);
    size_t privateEncryptSize = privateRSALength;
    NSMutableData *encryptDate = [NSMutableData data];
    for (int i = 0; i < blockCount; i++) {
        NSUInteger loc = i * blockSize;
        int dataSegmentRealSize = MIN(blockSize, totalLength - loc);
        NSData *dataSegment = [plainData subdataWithRange:NSMakeRange(loc, dataSegmentRealSize)];
        char *privateEncrypt = malloc(privateRSALength);
        memset(privateEncrypt, 0, privateRSALength);
        const unsigned char *str = [dataSegment bytes];
        int r = RSA_private_encrypt(dataSegmentRealSize,str,(unsigned char*)privateEncrypt,privateKey,padding);
        if (r < 0) {
            free(privateEncrypt);
            return nil;
        }
        
        NSData *encryptData = [[NSData alloc] initWithBytes:privateEncrypt length:privateEncryptSize];
        [encryptDate appendData:encryptData];
        
        free(privateEncrypt);
    }
    return encryptDate;
    
}

+ (NSData *)openssl_decryptWithPublicKey:(RSA *)publicKey cipherData:(NSData *)cipherData padding:(int)padding{
    if (!publicKey) {
        return nil;
    }
    if (!cipherData) {
        return nil;
    }
    
    int publicRSALenght = RSA_size(publicKey);
    double totalLength = [cipherData length];
    int blockSize = publicRSALenght;
    int blockCount = ceil(totalLength / blockSize);
    NSMutableData *decrypeData = [NSMutableData data];
    for (int i = 0; i < blockCount; i++) {
        NSUInteger loc = i * blockSize;
        long dataSegmentRealSize = MIN(blockSize, totalLength - loc);
        NSData *dataSegment = [cipherData subdataWithRange:NSMakeRange(loc, dataSegmentRealSize)];
        const unsigned char *str = [dataSegment bytes];
        unsigned char *publicDecrypt = malloc(publicRSALenght);
        memset(publicDecrypt, 0, publicRSALenght);
        int ret = RSA_public_decrypt(publicRSALenght,str,publicDecrypt,publicKey,padding);
        if(ret < 0){
            free(publicDecrypt);
            return nil ;
        }
        NSData *data = [[NSData alloc] initWithBytes:publicDecrypt length:ret];
        if (padding == RSA_NO_PADDING) {
            Byte flag[] = {0x00};
            NSData *startData = [data subdataWithRange:NSMakeRange(0, 1)];
            if ([[startData description] isEqualToString:@"<00>"]) {
                NSRange startRange = [data rangeOfData:[NSData dataWithBytes:flag length:1] options:NSDataSearchBackwards range:NSMakeRange(0, data.length)];
                NSUInteger s = startRange.location + startRange.length;
                if (startRange.location != NSNotFound && s < data.length) {
                    data = [data subdataWithRange:NSMakeRange(s, data.length - s)];
                }
            }
        }
        [decrypeData appendData:data];
        
        free(publicDecrypt);
    }
    return decrypeData;
}



#pragma mark - 指数模数 与 公钥 转换
+ (RSA *)openssl_publicKeyFormMod:(NSString *)mod exp:(NSString *)exp {
    
    RSA * rsa_pub = RSA_new();
    
    const char *N=[mod UTF8String] ;
    const char *E=[exp UTF8String];
    
    if (!BN_hex2bn(&rsa_pub->n, N)) {
        return nil;
    }
    
    if (!BN_hex2bn(&rsa_pub->e, E)) {
        return nil;
    }
    return rsa_pub;
}

+ (char *)openssl_expFromPublicKey:(RSA *)publicKey {
    return  BN_bn2hex(publicKey->e);
}
+ (char *)openssl_modFromPublicKey:(RSA *)publicKey {
    return  BN_bn2hex(publicKey->n);
}
@end
