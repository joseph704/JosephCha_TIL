//
//  MdmManager2.m
//  MultiviewMobile
//
//  Created by martin on 2022/06/20.
//  Copyright © 2022 hyh. All rights reserved.
//

#import <dlfcn.h>
#import <sys/types.h>
#include <unistd.h>
#include <sys/sysctl.h>
#include <string.h>
#import <CommonCrypto/CommonDigest.h>
#import "seedcbc.h"
#import "stscore.h"
#import "GlobalDefine.h"
#import "MVKeychainItemWrapper.h"
#import "KeychainManager.h"
#import "MVProxy.h"
#import "AlertManager.h"
#import "MdmManager2.h"


typedef enum {
    OneGuardResultCode_RESULT_CODE_SUCCESS                  = 0,              //요청API결과성공
    OneGuardResultCode_RESULT_CODE_FAIL                     = 1,              //요청API결과실패
    OneGuardResultCode_RESULT_CODE_EXIST_AGENT              = 2,              //원가드 Agent 설치
    OneGuardResultCode_RESULT_CODE_NOT_EXIST_DELEGATE       = 3,              //Delegate 콜백 미설정
    OneGuardResultCode_RESULT_CODE_UNKNOWN_EXCEPTION        = 4,              //알수없는오류
    OneGuardResultCode_RESULT_CODE_TIME_OUT                 = 5,              //통신 timeout 오류
    OneGuardResultCode_RESULT_CODE_NOT_SERVER_INFO          = 6,              //서버정보 미설정 오류
    OneGuardResultCode_RESULT_CODE_NOT_EXIST_AGENT          = 7,              //원가드 Agent 미설치 오류
    OneGuardResultCode_RESULT_CODE_NOT_EXIST_MDM_PROFILE    = 8,              //MDM 프로파일 삭제
    OneGuardResultCode_RESULT_CODE_NOT_LOGIN                = 9,              //원가드미로그인유저
    OneGuardResultCode_RESULT_CODE_DEVICE_LOST              = 10,              //분실된 단말
    OneGuardResultCode_RESULT_CODE_DEVICE_JAILBREAK         = 11,              //탈옥된 단말
    OneGuardResultCode_RESULT_CODE_INTERNAL_CONNECT_FAIL    = 12,              //원가드와 연결이 안되는 현상
    OneGuardResultCode_RESULT_CODE_MDM_NOT_LAST_VERSION     = 13,              //최신버전이 아닌 MDM
    OneGuardResultCode_RESULT_CODE_ERR_URL_CANCELLED        = 14,              //네트워크 에러: 비동기 로딩이 취소 됨
    OneGuardResultCode_RESULT_CODE_ERR_URL_BAD              = 15,              //네트워크 에러: 잘못된 URL 로 요청을 시작하지 못함
    OneGuardResultCode_RESULT_CODE_ERR_URL_TIMEOUT          = 16,              //네트워크 에러: 비동기 작업 시간이 초과 됨
    OneGuardResultCode_RESULT_CODE_ERR_URL_UNSUPPORTED      = 17,              //네트워크 에러: 처리할 수 없는 URL
    OneGuardResultCode_RESULT_CODE_ERR_URL_NOTCONNECT_HOST  = 18,              //네트워크 에러: 호스트 연결 시도 실패
    OneGuardResultCode_RESULT_CODE_ERR_URL_DATA_LENGTH      = 19,              //네트워크 에러: 리소스 데이터의 길이가 초과
    OneGuardResultCode_RESULT_CODE_ERR_URL_CONNECTION_LOST  = 20,              //네트워크 에러: 서버 통신 진행중 연결 끊김
    OneGuardResultCode_RESULT_CODE_ERR_URL_DNS_LOOKUP_FAIL  = 21,              //트워크 에러: DNS 조회를 통해 호스트 주소를 찾을 수 없음
    OneGuardResultCode_RESULT_CODE_ERR_URL_TOOMANY_REDIRECTS    = 22,              //네트워크 에러: 리다이렉션 임계 값 초과
    OneGuardResultCode_RESULT_CODE_ERR_URL_RESOURCE_UNAVAILABLE = 23,              //네트워크 에러: 요청 리소스 검색 실패
    OneGuardResultCode_RESULT_CODE_ERR_URL_NOTCONNECT_INTERNET  = 24,              //네트워크 에러: 인터넷 연결이 설정되어 있지 않음
    OneGuardResultCode_RESULT_CODE_ERR_URL_BAD_SERVER_RESPONSE  = 25,              //네트워크 에러: 서버에서 잘못된 데이타를 받음
    OneGuardResultCode_RESULT_CODE_ERR_URL_CANCELED_AUTHEN      = 26,              //네트워크 에러: 인증 요청이 사용자에 의해 취소
    OneGuardResultCode_RESULT_CODE_ERR_URL_REQUIRED_AUTHEN      = 27,              //트워크 에러: 리소스에 엑세스하려면 인증이 필요
    OneGuardResultCode_RESULT_CODE_ERR_URL_SECURE_CONNECTION_FAIL = 28,              //네트워크 에러: 보안 연결 실패
    
}OneGuardResultCode;

static MdmManager2 *sharedMdmManager = nil;
@implementation MdmManager2

+ (MdmManager2 *)sharedMdmManager{
#if __IPHONE_OS_VERSION_MAX_ALLOWED >= __IPHONE_4_0
    static dispatch_once_t pred;
    dispatch_once(&pred, ^{
        sharedMdmManager = [[self alloc] init];
    });
#else
    @synchronized(self)
    {
        if (sharedMdmManager == nil)
        {
            sharedMdmManager =  [[self alloc] init];
        }
    }
#endif
    
    return sharedMdmManager;
}
+ (BOOL) canOpenMdm{
    UIApplication *ourApllication = [UIApplication sharedApplication];
    
//    NSString *ourPath = [NSString stringWithFormat:@"mguard://mam"];
    NSURL *ourURL = [NSURL URLWithString:@"mguard://"];
    
    if  ([ourApllication canOpenURL:ourURL]){
        return YES;
    } else {
        [AlertManager.sharedObject showAlertWithTitle:@"error" message:@"MDM에 접근 할 수 없습니다." singleButton:@"OK" singleButtonBlock:^{
            [[MDMApi instance] RS_MDM_InstallAgent];
            exit(0);
            
        }];
    }
    return NO;
}

-(BOOL)initTestOneGuard{
    BOOL ret = NO;
    if (CustomManager.sharedObject.mdm2Scheme) {
        if([MdmManager2 canOpenMdm])
            ret = [[MDMApi instance] RS_MDM_LOAD_DATA_WITH_URLSCHEME:CustomManager.sharedObject.mdm2Scheme];
        //            ret = [[MDMApi instance] RS_MDM_Init_Test:CustomManager.sharedObject.mdm2Scheme];
    }
    DDLogDebug(@"\n[mdm] RS_MDM_Init_Test  = %d",ret);
    return ret;
}

-(void)checkOneGuardAfterInit:(int)resultCode{
    MDMApi *mdmApi = [MDMApi instance];
    
    if(resultCode == OneGuardResultCode_RESULT_CODE_SUCCESS){
        DDLogDebug(@"\n[mdm][1] MDM init success");
        DDLogDebug(@"\n[mdm][2] MDM Check ");
        [mdmApi RS_MDM_CheckAgent:@"mobileoffice" withSuccessBlock:^(int pid, NSDictionary *result) {
            OneGuardResultCode resultCode = [[result valueForKey:@"resultCode"] intValue];
            DDLogDebug(@"\n[mdm][2] MDM check [resultCode] %d", resultCode);
            NSString *errorMsg = @"";
            DDLogDebug(@"\n[mdm][2] MDM Check success");
            errorMsg = nil;
            //업무앱 버전체크
            NSString *officePkg = [[[NSBundle mainBundle] infoDictionary] objectForKey:@"CFBundleIdentifier"];
            [[MDMApi instance] RS_CheckOfficeUpdate:officePkg
                                      doProccess:^(int pid, NSDictionary *result, id<InstallAppCallback>callback) {
               if (pid == MG_JOB_PID_CHECK_OFFICE_VERSION) {
                   NSLog(@"pid: %d, checkOffice result: %@", pid, result);
                   NSString *plistInstallUrl = [result objectForKey:@"plistInstallUrl"];
                   // 설치 (설치 작업 custom시 result 정보 사용하여 앱 설치
                   [callback installApp:plistInstallUrl];
               }
            }
            withSuccessEvent:^(int pid, NSDictionary *result) {
                DDLogDebug(@"\n[mdm][3] MDM login");
                [self loginOneGuard];
            } withErrorBlock:^(int pid, NSDictionary *result) {
                [MdmManager2 showErrorBlockAPI:mdmApi withpid:pid withResult:result];
            }];
            
        } errorBlock:^(int pid, NSDictionary *result) {
            [MdmManager2 showErrorBlockAPI:mdmApi withpid:pid withResult:result];
        }];
    }
    else{
        NSString *errorMsg = nil;
        DDLogDebug(@"\n[mdm] MDM init fail");
        
        if(resultCode == OneGuardResultCode_RESULT_CODE_NOT_EXIST_MDM_PROFILE){
            [mdmApi RS_MDM_InstallMDMProfile];
        }
        else if(resultCode == OneGuardResultCode_RESULT_CODE_NOT_EXIST_AGENT){
            [mdmApi RS_MDM_InstallAgent];
        }
        else if(resultCode == OneGuardResultCode_RESULT_CODE_MDM_NOT_LAST_VERSION){
            errorMsg = @"최신버전이 아닙니다.";
        }
        else if(resultCode == OneGuardResultCode_RESULT_CODE_DEVICE_JAILBREAK){
            errorMsg = [CustomString stringKey:@"LANG_APPSUIT_ROOTING" withComment:@"탈옥이나 루팅을 통한 비정상 단말기기인 경우 지원하지 않습니다."];
        }
        else if(resultCode == OneGuardResultCode_RESULT_CODE_NOT_LOGIN){
            errorMsg = @"엠가드 로그아웃 상태입니다.";
        }
        else{
            errorMsg = [NSString stringWithFormat:@"init 에러 (OneGuard_%d)", resultCode];
        }
        
        if(errorMsg != nil && errorMsg.length > 0){
            [AlertManager.sharedObject showAlertWithTitle:nil message:errorMsg singleButton:@"OK" singleButtonBlock:^{
                if([errorMsg isEqualToString:@"최신버전이 아닙니다."]){
                    [mdmApi RS_MDM_InstallAgent];
                }
                else if([errorMsg isEqualToString:@"엠가드 로그아웃 상태입니다."]){
                    [mdmApi RS_MDM_GoMDMLogin];
                }
                else{
                    exit(0);
                }
            }];
        }
    }
}
+(void)showErrorBlockAPI:(MDMApi*)mdmApi withpid:(int)pid withResult:(NSDictionary *)result
{
    dispatch_async(dispatch_get_main_queue(), ^{
        OneGuardResultCode resultCode = [[result valueForKey:@"resultCode"] intValue];
        NSString *errorMsg = [NSString stringWithFormat:@"CheckAgent 에러 (OneGuard_%d)", resultCode];
        if(resultCode == OneGuardResultCode_RESULT_CODE_SUCCESS){
            return;
        }
        if(resultCode == OneGuardResultCode_RESULT_CODE_NOT_EXIST_MDM_PROFILE){
            [mdmApi RS_MDM_InstallMDMProfile];
        }
        else if(resultCode == OneGuardResultCode_RESULT_CODE_NOT_EXIST_AGENT){
            [mdmApi RS_MDM_InstallAgent];
        }
        else if(resultCode == OneGuardResultCode_RESULT_CODE_MDM_NOT_LAST_VERSION){
            errorMsg = @"최신버전이 아닙니다.";
        }
        else if(resultCode == OneGuardResultCode_RESULT_CODE_DEVICE_JAILBREAK){
            errorMsg = [CustomString stringKey:@"LANG_APPSUIT_ROOTING" withComment:@"탈옥이나 루팅을 통한 비정상 단말기기인 경우 지원하지 않습니다."];
        }
        else if(resultCode == OneGuardResultCode_RESULT_CODE_NOT_LOGIN){
            errorMsg = @"엠가드 로그아웃 상태입니다.";
        }
        else{
            errorMsg = [NSString stringWithFormat:@"알 수 없는 에러 (OneGuard_%d)", resultCode];
            NSString *message = [result valueForKey:@"message"];
            if(message.length > 0)
                errorMsg = message;
        }
        
        if(errorMsg != nil && errorMsg.length > 0){
            [AlertManager.sharedObject showAlertWithTitle:nil message:errorMsg singleButton:@"확인" singleButtonBlock:^{
                    if([errorMsg isEqualToString:@"최신버전이 아닙니다."]){
                        [mdmApi RS_MDM_InstallAgent];
                    }
                    else if([errorMsg isEqualToString:@"엠가드 로그아웃 상태입니다."]){
                        [mdmApi RS_MDM_GoMDMLogin];
                    }
                    else{
                        exit(0);
                    }
            }];
        }
    });
}

+(id)loadKeyChainData:(id)key
{
    DDLogDebug(@"\n[mdm] loadKeyChainData wrapper group bundleSeedID.%@", key);
//    KeychainManager *wrapper = [[KeychainManager alloc] initWithIdentifier:@"Account Number" accessGroup:[NSString stringWithFormat:@"BAWY5JMEX7.%@", key]];
    MVKeychainItemWrapper *wrapper = [[MVKeychainItemWrapper alloc] initWithIdentifier:@"Account Number" accessGroup:[NSString stringWithFormat:@"BAWY5JMEX7.%@", key]];
    DDLogDebug(@"\n[mdm] loadKeyChainData wrapper Address %@", wrapper);
    DDLogDebug(@"\n[mdm] loadKeyChainData wrapper.keychainItemData %@", wrapper.keychainItemData);
    DDLogDebug(@"\n[mdm] loadKeyChainData wrapper.genericPasswordQuery %@", wrapper.genericPasswordQuery);
    NSString *retString = [wrapper objectForKey:(NSString *)kSecValueData];
    NSString *retString2 = [wrapper.keychainItemData objectForKey:(NSString *)kSecValueData];
    NSString *retString3 = [wrapper.genericPasswordQuery objectForKey:(NSString *)kSecValueData];
    DDLogDebug(@"\n[mdm] checkOneGuard retString = %@ end", retString);
    DDLogDebug(@"\n[mdm] checkOneGuard retString(by.ItemData) = %@ end", retString2);
    DDLogDebug(@"\n[mdm] checkOneGuard retString(by.generic) = %@ end", retString3);
    return retString;
}
+(NSURLSession *)urlSession{
    NSURLSessionConfiguration *config = [NSURLSessionConfiguration ephemeralSessionConfiguration];
    NSURLSession *session = [NSURLSession sessionWithConfiguration:config delegate:self delegateQueue:[NSOperationQueue mainQueue]];
    
    return session;
}
- (void)loginOneGuard{
    DDLogDebug(@"\n[mdm] loginOneGuard in");
    MDMApi *mdmApi = [MDMApi instance];
    [mdmApi RS_MDM_LoginOffice:^(int pid, NSDictionary *result) {
        DDLogDebug(@"result: %@", result);
        OneGuardResultCode resultCode = [[result valueForKey:@"resultCode"] intValue];
        DDLogDebug(@"\n[mdm][3] MDM login [resultCode] %d", resultCode);
        switch(resultCode)
        {
            case OneGuardResultCode_RESULT_CODE_SUCCESS:{
                DDLogDebug(@"\n[mdm][3] MDM 7login Success");
            }
            break;
            default:
            {
                NSString *errorMsg = [NSString stringWithFormat:@"mdm로그인 에러 = %d", resultCode];
                [AlertManager.sharedObject showAlertWithTitle:nil message:errorMsg singleButton:@"확인" singleButtonBlock:^{
                            exit(0);
                }];
                return;

            }
            break;
        }

    } errorBlock:^(int pid, NSDictionary *result) {
        [MdmManager2 showErrorBlockAPI:mdmApi withpid:pid withResult:result];
    }];
}
- (void)logoutOneGuard{
    DDLogDebug(@"\n[mdm] logoutOneGuard in");
    
    [[MDMApi instance] RS_MDM_LogoutOffice];
}


@end
