//
//  ViewController.m
//  RSADemo


#import "ViewController.h"
#import "DDRSAWrapper.h"

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
    
}
@property (weak, nonatomic) IBOutlet UITextView *logTextView;


@end

@implementation ViewController
- (void)viewDidLoad {
	[super viewDidLoad];
	
	
	_plainString = @"电视剧1234567890qwertyuiop[]asdfghjkl;'zxcvbnm,./`!@#$%^&*()_+=-";
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

- (IBAction)opensslGenerate{
	if ([DDRSAWrapper generateRSAKeyPairWithKeySize:2048 publicKey:&publicKey privateKey:&privateKey]) {
		NSString *publicKeyPem = [DDRSAWrapper PEMFormatPublicKey:publicKey];
		NSString *privateKeyPem = [DDRSAWrapper PEMFormatPrivateKey:privateKey];
		_publicKeyBase64 = [DDRSAWrapper base64EncodedFromPEMFormat:publicKeyPem];
		_privateKeyBase64 = [DDRSAWrapper base64EncodedFromPEMFormat:privateKeyPem];
		NSString *logText = [NSString stringWithFormat:@"openssl 生成密钥成功！\npublickKeyPem:\n%@\nprivateKeyPem:\n%@\n",publicKeyPem,privateKeyPem];
		[self addlogText:logText];
	}
	
}


- (IBAction)SecKeyGenerate {
	if ([DDRSAWrapper generateSecKeyPairWithKeySize:2048 publicKeyRef:&publicKeyRef privateKeyRef:&privateKeyRef]) {
		NSData *publicKeyData = [DDRSAWrapper publicKeyBitsFromSecKey:publicKeyRef];
		NSData *privateKeyData = [DDRSAWrapper privateKeyBitsFromSecKey:privateKeyRef];
		NSString *logText = [NSString stringWithFormat:@"SecKey 生成密钥成功!\npublicKeyData:\n%@\nprivateKeyData:\n%@\n",publicKeyData,privateKeyData];
		[self addlogText:logText];
		
		
		_modData = [DDRSAWrapper getPublicKeyMod:publicKeyData];
		_expData = [DDRSAWrapper getPublicKeyExp:publicKeyData];
	}
}

- (IBAction)opensslReadPublicKeyPEM {
	if(!_publicKeyBase64) {
		NSString *logText = [NSString stringWithFormat:@"%@\n 无PEM信息\n",self.logTextView.text];
		self.logTextView.text = logText;
		return;
	}
	publicKey = [DDRSAWrapper RSAPublicKeyFromBase64:_publicKeyBase64];
	
	if (publicKey ) {
		[self addlogText:@"openssl 读出公钥pem成功"];
	}
}

- (IBAction)SecKeyReadPublicKeyPEM {
	if(!_publicKeyBase64) {
		NSString *logText = [NSString stringWithFormat:@"%@\n 无PEM信息\n",self.logTextView.text];
		self.logTextView.text = logText;
		return;
	}
	
	NSData *data = [[NSData alloc] initWithBase64EncodedString:_publicKeyBase64 options:NSDataBase64DecodingIgnoreUnknownCharacters];
	publicKeyRef = [DDRSAWrapper publicSecKeyFromKeyBits:data];
	if (publicKeyRef) {
		NSString *logText = [NSString stringWithFormat:@"SecKey 读出公钥pem成功\n%@",publicKeyRef];
		[self addlogText:logText];
		NSData *publicKeyData = [DDRSAWrapper publicKeyBitsFromSecKey:publicKeyRef];
		_modData = [DDRSAWrapper getPublicKeyMod:publicKeyData];
		_expData = [DDRSAWrapper getPublicKeyExp:publicKeyData];
	}
	
}

- (IBAction)opensslReadPrivateeyPEM {
	if(!_privateKeyBase64) {
		[self addlogText:@"无PEM信息"];
		return;
	}
	privateKey = [DDRSAWrapper RSAPrivateKeyFromBase64:_privateKeyBase64];
	if (privateKey ) {
		
		[self addlogText:@"openssl 读出私钥pem成功"];
	}
}
- (IBAction)SecKeyReadPrivateKeyPEM{
	if(!_privateKeyBase64) {
		[self addlogText:@"无PEM信息"];
		return;
	}
	NSData *data = [[NSData alloc] initWithBase64EncodedString:_privateKeyBase64 options:NSDataBase64DecodingIgnoreUnknownCharacters];
	privateKeyRef = [DDRSAWrapper privateSecKeyFromKeyBits:data];
	if (privateKeyRef) {
		NSString *logText = [NSString stringWithFormat:@"SecKey 读出公钥pem成功\n%@",privateKeyRef];
		[self addlogText:logText];
	}
}

- (IBAction)opensslCreatPublcKey {
	
	publicKey = [DDRSAWrapper publicKeyFormMod:[self stringFromData:_modData] exp:[self stringFromData:_expData]];
	if (publicKey) {
		NSString *logText = [NSString stringWithFormat:@"模指生成RSA公钥成功"];
		[self addlogText:logText];
	} else {
		NSString *logText = [NSString stringWithFormat:@"模指生成RSA公钥失败"];
		[self addlogText:logText];
	}
}

- (IBAction)SecKeyCreatPublcKey {
	NSData *publickData = [DDRSAWrapper publicKeyDataWithMod:_modData exp:_expData];
	publicKeyRef = [DDRSAWrapper publicSecKeyFromKeyBits:publickData];
	if (publicKeyRef) {
		NSString *logText = [NSString stringWithFormat:@"模指生成SecKey公钥%@",publicKeyRef];
		[self addlogText:logText];
	} else {
		NSString *logText = [NSString stringWithFormat:@"模指生成SecKey公钥失败"];
		[self addlogText:logText];
	}
}

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
	NSData *cipherData = [DDRSAWrapper encryptWithPublicKey:publicKey plainData:plainData];
	_cipherString = [cipherData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
	NSString *logText = [NSString stringWithFormat:@"openssl 公钥加密：\n%@",_cipherString];
	[self addlogText:logText];
	
	
}
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
	NSData *cipherData = [DDRSAWrapper encryptwithPublicKeyRef:publicKeyRef plainData:plainData];
	_cipherString = [cipherData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
	NSString *logText = [NSString stringWithFormat:@"SecKey 公钥加密：\n%@",_cipherString];
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
	NSData *plainData = [DDRSAWrapper decryptWithPrivateKey:privateKey cipherData:cipherData];
	NSString *outputPlainString = [[NSString alloc] initWithData:plainData encoding:NSUTF8StringEncoding];
	
	if ([outputPlainString isEqualToString:_plainString]) {
		NSString *logText = [NSString stringWithFormat:@"openssl 私钥解密：\n%@",outputPlainString];
		[self addlogText:logText];
	} else {
		NSString *logText = [NSString stringWithFormat:@"openssl 私钥解密失败"];
		[self addlogText:logText];
	}
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
	NSData *plainData = [DDRSAWrapper decryptWithPrivateKeyRef:privateKeyRef cipherData:cipherData];
	NSString *outputPlainString = [[NSString alloc] initWithData:plainData encoding:NSUTF8StringEncoding];
	if ([outputPlainString isEqualToString:_plainString]) {
		NSString *logText = [NSString stringWithFormat:@"SecKey 私钥解密成功：\n%@",outputPlainString];
		[self addlogText:logText];
	} else {
		NSString *logText = [NSString stringWithFormat:@"SecKey 私钥解密失败"];
		[self addlogText:logText];
	}

}
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
    
    NSData *cipherData = [DDRSAWrapper encryptWithPrivateRSA:privateKey plainData:plainData];
    _cipherString = [cipherData base64EncodedStringWithOptions:NSDataBase64Encoding64CharacterLineLength];
    NSString *logText = [NSString stringWithFormat:@"SecKey 公钥加密：\n%@",_cipherString];
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
    NSData *plainData = [DDRSAWrapper decryptWithPublicKey:publicKey cipherData:cipherData];
    NSString *outputPlainString = [[NSString alloc] initWithData:plainData encoding:NSUTF8StringEncoding];
    if ([outputPlainString isEqualToString:_plainString]) {
        NSString *logText = [NSString stringWithFormat:@"SecKey 私钥解密成功：\n%@",outputPlainString];
        [self addlogText:logText];
    } else {
        NSString *logText = [NSString stringWithFormat:@"SecKey 私钥解密失败"];
        [self addlogText:logText];
    }
    
}

- (void)addlogText:(NSString *)text {
	NSString *logText = [NSString stringWithFormat:@"%@\n%@\n",self.logTextView.text,text];
	self.logTextView.text = logText;
	[self scrollsToBottomAnimated:YES];
}

- (void)scrollsToBottomAnimated:(BOOL)animated {
	CGFloat offset = self.logTextView.contentSize.height - self.logTextView.bounds.size.height;
	if (offset > 0)
	{
		[self.logTextView setContentOffset:CGPointMake(0, offset) animated:animated];
	}
}

- (NSString *)stringFromData:(NSData *)data {
	return  [[[[data description] stringByReplacingOccurrencesOfString: @"<" withString: @""]
			  stringByReplacingOccurrencesOfString: @">" withString: @""]
			 stringByReplacingOccurrencesOfString: @" " withString: @""];
}

@end
