//
//  ViewController.m
//  RSADemo


#import "ViewController.h"
#import "DDRSAWrapper.h"
#import "DDRSAWrapper+openssl.h"

@interface ViewController (){
	
	RSA *publicKey;
	RSA *privateKey;
	
	SecKeyRef publicKeyRef;
	SecKeyRef privateKeyRef;
	
	NSString *_publicKeyBase64;
	NSString *_privateKeyBase64;
	
	NSString *_plainString;
	NSString *_cipherString;
	
	NSData *_modData;
	NSData *_expData;
    
    
    DDRSAWrapper *_wrapper;
    
}
@property (weak, nonatomic) IBOutlet UITextView *logTextView;


@end

@implementation ViewController
- (void)viewDidLoad {
	[super viewDidLoad];
    
    _wrapper = [[DDRSAWrapper alloc] init];
    

    _plainString = @"中文dsakdskahdskah中文dksahdkjashdsadjsajdlsajkl123890210890%&*(*()_@#$%^&*()*&^%$hjdksakdhksjhkfhjsk0.164103201中文3dsakdskahdskahdksahdkjashdsadjsajdlsajkl123890210890%&*(*()_@#$%^&*()*&^%$hjdksakdhksjhkfhjsk0.1641032013dsakdska中文hdskahdksahdkjashdsadjsajdlsajkl123890210890%&*(*()_@#$%^&*()*&^%$hjdksakdhksjhkfhjsk0.1641032013dsakdskahdskahd中文sahdkjashdsadjsajdlsajkl123890210890%&*(*()_@#$%^&*()*&^%$hjdksakdhksjhkfhjsk0.164103201中文3dsakdskahdskahdksahdkjashdsadjsajdlsajkl123890210890%&*(*()_@#$%^&*()*&^%$hjdksakdhksjhkfhjsk0.1641032013中文dsakdskahdskahdk中文sahdkjashdsadjsajdlsajkl123890210890%&*(*()_@#$%^&*()*&^%$hjdksakdhksjhkfhjsk0.1641032013dsakdskahdskahdksa中文hdkjashdsadjsajdlsajkl123890210890%&*(*()_@#$%^&*()*&^%$hjdksakdhksjhkfhjsk0.1641032013dsakdskahdskahdksahdkjashdsad中文jsajdlsajkl12389021中文0890%&*(*()_@#$%^&*()*&^%$hjdksakdhksjhkfhjsk0.1641032013";
    
}



- (IBAction)resetAll:(id)sender {

	publicKey = nil;
	privateKey = nil;
	
	publicKeyRef = nil;
	privateKeyRef = nil;
	
	_publicKeyBase64 = nil;
	_privateKeyBase64 = nil;
	
	_cipherString = nil;
	
	_modData = nil;
	_expData = nil;
	self.logTextView.text = nil;
    
    
  
}
#pragma mark - SecKeyRef
#pragma mark ---生成密钥对
- (IBAction)SecKeyGenerate {
	if ([_wrapper generateSecKeyPairWithKeySize:1024 publicKeyRef:&publicKeyRef privateKeyRef:&privateKeyRef]) {
		NSData *publicKeyData = [_wrapper publicKeyBitsFromSecKey:publicKeyRef];
		NSData *privateKeyData = [_wrapper privateKeyBitsFromSecKey:privateKeyRef];
		NSString *logText = [NSString stringWithFormat:@"SecKey 生成密钥成功!\npublicKeyData:\n%@\nprivateKeyData:\n%@\n",publicKeyData,privateKeyData];
		[self addlogText:logText];
		
		_modData = [_wrapper getPublicKeyMod:publicKeyData];
		_expData = [_wrapper getPublicKeyExp:publicKeyData];
	}
}
#pragma mark ---读取密钥对
- (IBAction)SecKeyReadPublicKeyPEM {
    if(!_publicKeyBase64) {
        NSString *logText = [NSString stringWithFormat:@"%@\n 无PEM信息\n",self.logTextView.text];
        self.logTextView.text = logText;
        return;
    }
    
    NSData *data = [[NSData alloc] initWithBase64EncodedString:_publicKeyBase64 options:NSDataBase64DecodingIgnoreUnknownCharacters];
    publicKeyRef = [_wrapper publicSecKeyFromKeyBits:data];
    if (publicKeyRef) {
        NSString *logText = [NSString stringWithFormat:@"SecKey 读出公钥pem成功\n%@",publicKeyRef];
        [self addlogText:logText];
        NSData *publicKeyData = [_wrapper publicKeyBitsFromSecKey:publicKeyRef];
        _modData = [_wrapper getPublicKeyMod:publicKeyData];
        _expData = [_wrapper getPublicKeyExp:publicKeyData];
    }
    
}

- (IBAction)SecKeyReadPrivateKeyPEM{
    if(!_privateKeyBase64) {
        [self addlogText:@"无PEM信息"];
        return;
    }
    NSData *data = [[NSData alloc] initWithBase64EncodedString:_privateKeyBase64 options:NSDataBase64DecodingIgnoreUnknownCharacters];
    privateKeyRef = [_wrapper privateSecKeyFromKeyBits:data];
    if (privateKeyRef) {
        NSString *logText = [NSString stringWithFormat:@"SecKey 读出公钥pem成功\n%@",privateKeyRef];
        [self addlogText:logText];
    }
}

#pragma mark ---指数模数生成公钥
- (IBAction)SecKeyCreatPublcKey {
    publicKeyRef = [_wrapper publicKeyDataWithMod:_modData exp:_expData];
    if (publicKeyRef) {
        NSString *logText = [NSString stringWithFormat:@"模指生成SecKey公钥%@",publicKeyRef];
        [self addlogText:logText];
    } else {
        NSString *logText = [NSString stringWithFormat:@"模指生成SecKey公钥失败"];
        [self addlogText:logText];
    }
}

#pragma mark ---公钥加密 && 私钥解密
- (IBAction)SecRefPubcliKeyEncrypt {
    if(!publicKeyRef) {
        [self addlogText:@"无SecKey公钥"];
        return;
    }
    if (!_plainString) {
        [self addlogText:@"无明文数据"];
        return;
    }
    
    NSData *plainData = [_plainString dataUsingEncoding:NSUTF8StringEncoding];
    NSData *cipherData = [_wrapper encryptWithKey:publicKeyRef plainData:plainData padding:kSecPaddingPKCS1];
    _cipherString = [cipherData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    NSString *logText = [NSString stringWithFormat:@"SecKey 公钥加密：\n%@",_cipherString];
    [self addlogText:logText];
    
}
- (IBAction)SecRefPrivateKeyDecrypt {
    if(!privateKeyRef) {
        [self addlogText:@"无SecKey私钥"];
        return;
    }
    if (!_cipherString) {
        [self addlogText:@"无密文数据"];
        return;
    }
    
    NSData *cipherData = [[NSData alloc] initWithBase64EncodedString:_cipherString options:NSDataBase64DecodingIgnoreUnknownCharacters];
    NSData *plainData = [_wrapper decryptWithKey:privateKeyRef cipherData:cipherData padding:kSecPaddingPKCS1];
    
    NSString *outputPlainString = [[NSString alloc] initWithData:plainData encoding:NSUTF8StringEncoding];
    if ([outputPlainString isEqualToString:_plainString]) {
        NSString *logText = [NSString stringWithFormat:@"SecKey 私钥解密成功：\n%@",outputPlainString];
        [self addlogText:logText];
    } else {
        NSString *logText = [NSString stringWithFormat:@"SecKey 私钥解密失败"];
        [self addlogText:logText];
    }
}

#pragma mark ---私钥加密&公钥解密

- (IBAction)SecRefPrivateEncrypt:(id)sender {
    
    if(!privateKeyRef) {
        [self addlogText:@"无SecKey私钥"];
        return;
    }

    if (!_plainString) {
        [self addlogText:@"无明文数据"];
        return;
    }
    
    NSData *plainData = [_plainString dataUsingEncoding:NSUTF8StringEncoding];
    
    NSData *cipherData = [_wrapper encryptWithPrivateKey:privateKeyRef plainData:plainData];
    _cipherString = [cipherData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    NSString *logText = [NSString stringWithFormat:@"SecKey 私钥加密：\n%@",_cipherString];
    [self addlogText:logText];
    
}

- (IBAction)SecRefPublicKeyDecrypt:(id)sender {
    if(!publicKeyRef) {
        [self addlogText:@"无SecKey公钥"];
        return;
    }
    if (!_cipherString) {
        [self addlogText:@"无密文数据"];
        return;
    }
    NSData *cipherData = [[NSData alloc] initWithBase64EncodedString:_cipherString options:NSDataBase64DecodingIgnoreUnknownCharacters];
    
    NSData *plainData = [_wrapper decryptWithPublicKey:publicKeyRef cipherData:cipherData];
    
    NSString *outputPlainString = [[NSString alloc] initWithData:plainData encoding:NSUTF8StringEncoding];
    if ([outputPlainString isEqualToString:_plainString]) {
        NSString *logText = [NSString stringWithFormat:@"SecKey 公钥解密成功：\n%@",outputPlainString];
        [self addlogText:logText];
    } else {
        NSString *logText = [NSString stringWithFormat:@"SecKey 公钥解密失败"];
        [self addlogText:logText];
    }
    
}

#pragma mark - openssl
#pragma mark ---生成密钥对
- (IBAction)opensslGenerate{
    if ([DDRSAWrapper generateRSAKeyPairWithKeySize:2048 publicKey:&publicKey privateKey:&privateKey]) {
        
        char * m = [DDRSAWrapper openssl_modFromKey:publicKey];
        char * e = [DDRSAWrapper openssl_expFromPublicKey:publicKey];
        char * d = [DDRSAWrapper openssl_expFromPrivateKey:privateKey];
        
        _publicKeyBase64 = [DDRSAWrapper base64EncodedStringPublicKey:publicKey];
        _privateKeyBase64 = [DDRSAWrapper base64EncodedStringPrivateKey:privateKey];
        NSLog(@"%@",_publicKeyBase64);
        NSLog(@"%@",_privateKeyBase64);
        
        NSString *logText = [NSString stringWithFormat:@"openssl 生成密钥成功！\n模数：%s\n公钥指数：%s\n私钥指数：%s",m,e,d];
        [self addlogText:logText];
    }
}
#pragma mark ---读取密钥对
- (IBAction)opensslReadPublicKeyPEM {
	if(!_publicKeyBase64) {
		NSString *logText = [NSString stringWithFormat:@"%@\n 无PEM信息\n",self.logTextView.text];
		self.logTextView.text = logText;
		return;
	}
	publicKey = [DDRSAWrapper openssl_publicKeyFromBase64:_publicKeyBase64];
	
	if (publicKey ) {
		[self addlogText:@"openssl 读出公钥pem成功"];
	}
}

- (IBAction)opensslReadPrivateeyPEM {
	if(!_privateKeyBase64) {
		[self addlogText:@"无PEM信息"];
		return;
	}
	privateKey = [DDRSAWrapper openssl_privateKeyFromBase64:_privateKeyBase64];
	if (privateKey ) {
		
		[self addlogText:@"openssl 读出私钥pem成功"];
	}
}

#pragma mark ---指数模数生成公钥
- (IBAction)opensslCreatPublcKey {
	
	publicKey = [DDRSAWrapper openssl_publicKeyFormMod:[self stringFromData:_modData] exp:[self stringFromData:_expData]];
	if (publicKey) {
		NSString *logText = [NSString stringWithFormat:@"模指生成RSA公钥成功"];
		[self addlogText:logText];
	} else {
		NSString *logText = [NSString stringWithFormat:@"模指生成RSA公钥失败"];
		[self addlogText:logText];
	}
}


#pragma mark ---公钥加密 && 私钥解密
- (IBAction)opensslPubcliKeyEncrypt {
	if(!publicKey) {
		[self addlogText:@"无RSA公钥"];
		return;
	}
	if (!_plainString) {
		[self addlogText:@"无明文数据"];
		return;
	}
	
	NSData *plainData = [_plainString dataUsingEncoding:NSUTF8StringEncoding];
    
	NSData *cipherData = [DDRSAWrapper openssl_encryptWithPublicKey:publicKey
                                                          plainData:plainData
                                                            padding:RSA_PKCS1_PADDING];
    
	_cipherString = [cipherData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
	NSString *logText = [NSString stringWithFormat:@"openssl 公钥加密：\n%@",_cipherString];
	[self addlogText:logText];
	
	
}

- (IBAction)opensslPrivateKeyDecrypt {
	if(!privateKey) {
		[self addlogText:@"无RSA私钥"];
		return;
	}
	if (!_cipherString) {
		[self addlogText:@"无密文数据"];
		return;
	}
	
	NSData *cipherData = [[NSData alloc] initWithBase64EncodedString:_cipherString options:NSDataBase64DecodingIgnoreUnknownCharacters];
    
	NSData *plainData = [DDRSAWrapper openssl_decryptWithPrivateKey:privateKey
                                                         cipherData:cipherData
                                                            padding:RSA_PKCS1_PADDING];
    
	NSString *outputPlainString = [[NSString alloc] initWithData:plainData encoding:NSUTF8StringEncoding];
	
	if ([outputPlainString isEqualToString:_plainString]) {
		NSString *logText = [NSString stringWithFormat:@"openssl 私钥解密：\n%@",outputPlainString];
		[self addlogText:logText];
	} else {
		NSString *logText = [NSString stringWithFormat:@"openssl 私钥解密失败"];
		[self addlogText:logText];
	}
}

#pragma mark ---私钥加密 && 公钥解密
- (IBAction)opensslPrivateEncrypt:(id)sender {
    if(!privateKey) {
        [self addlogText:@"无RSA私钥"];
        return;
    }
    
    if (!_plainString) {
        [self addlogText:@"无明文数据"];
        return;
    }
    NSData *plainData = [_plainString dataUsingEncoding:NSUTF8StringEncoding];
    
    NSData *cipherData = [DDRSAWrapper openssl_encryptWithPrivateRSA:privateKey
                                                           plainData:plainData
                                                             padding:RSA_PKCS1_PADDING];
    
    _cipherString = [cipherData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    NSString *logText = [NSString stringWithFormat:@"openssl 私钥加密：\n%@",_cipherString];
    [self addlogText:logText];

}
- (IBAction)opensslPublicKeyDecrypt:(id)sender {

    if(!publicKey) {
        [self addlogText:@"无RSA公钥"];
        return;
    }
    
    if (!_cipherString) {
        [self addlogText:@"无密文数据"];
        return;
    }
    
    NSData *cipherData = [[NSData alloc] initWithBase64EncodedString:_cipherString options:NSDataBase64DecodingIgnoreUnknownCharacters];
    
    NSData *plainData = [DDRSAWrapper openssl_decryptWithPublicKey:publicKey
                                                        cipherData:cipherData
                                                           padding:RSA_PKCS1_PADDING];
    
    NSString *outputPlainString = [[NSString alloc] initWithData:plainData encoding:NSUTF8StringEncoding];
    if ([outputPlainString isEqualToString:_plainString]) {
        NSString *logText = [NSString stringWithFormat:@"openssl 公钥解密成功：\n%@",outputPlainString];
        [self addlogText:logText];
    } else {
        NSString *logText = [NSString stringWithFormat:@"openssl 公钥解密失败"];
        [self addlogText:logText];
    }
    
}
#pragma mark - help method
- (void)addlogText:(NSString *)text {
	NSString *logText = [NSString stringWithFormat:@"%@\n%@\n",self.logTextView.text,text];
	self.logTextView.text = logText;
	[self scrollsToBottomAnimated:YES];
}

- (void)scrollsToBottomAnimated:(BOOL)animated {
	
	[_logTextView scrollRangeToVisible:NSMakeRange(_logTextView.text.length, 1)];
}

- (NSString *)stringFromData:(NSData *)data {
	return  [[[[data description] stringByReplacingOccurrencesOfString: @"<" withString: @""]
			  stringByReplacingOccurrencesOfString: @">" withString: @""]
			 stringByReplacingOccurrencesOfString: @" " withString: @""];
}

- (NSData *)convertHexStrToData:(NSString *)str {
    if (!str || [str length] == 0) {
        return nil;
    }
    
    NSMutableData *hexData = [[NSMutableData alloc] initWithCapacity:8];
    NSRange range;
    if ([str length] % 2 == 0) {
        range = NSMakeRange(0, 2);
    } else {
        range = NSMakeRange(0, 1);
    }
    for (NSInteger i = range.location; i < [str length]; i += 2) {
        unsigned int anInt;
        NSString *hexCharStr = [str substringWithRange:range];
        NSScanner *scanner = [[NSScanner alloc] initWithString:hexCharStr];
        
        [scanner scanHexInt:&anInt];
        NSData *entity = [[NSData alloc] initWithBytes:&anInt length:1];
        [hexData appendData:entity];
        
        range.location += range.length;
        range.length = 2;
    }
    return hexData;
}

@end
