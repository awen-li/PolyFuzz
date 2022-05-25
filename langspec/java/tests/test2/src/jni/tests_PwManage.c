#include <stdlib.h>
#include <memory.h>
#include <string.h>
#include "tests_PwManage.h"

#ifdef __cplusplus
extern "C" {
#endif

static char* PWD[] = {"123456789aqazwsxerfvtgbyhnikjjdfldjfhkshjfgkshgkshgfkshfgkhdg",
                      "0000000000000000000000001111111111111111111111111111111111111222222222222222222222222222222",
                      "44444444444444444444444444444444444444444444444444444444555555555555555555555555555555555555555555555555555566666666666666666",
                      "wwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwwttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttttthhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhhh",
                     };


jstring charTojstring(JNIEnv* env, const char* pat) 
{
    jclass strClass = (*env)->FindClass(env, "Ljava/lang/String;");

    jmethodID ctorID = (*env)->GetMethodID(env, strClass, "<init>", "([BLjava/lang/String;)V");
    jbyteArray bytes = (*env)->NewByteArray(env, strlen(pat));
    (*env)->SetByteArrayRegion(env, bytes, 0, strlen(pat), (jbyte*) pat);
    jstring encoding = (*env)->NewStringUTF(env, "GB2312");

    return (jstring) (*env)->NewObject(env, strClass, ctorID, bytes, encoding);
}


/*
 * Class:     tests_PwManage
 * Method:    NativePwd
 * Signature: (I)Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_tests_PwManage_NativePwd (JNIEnv * env, jclass jc, jint Key)
{
    int KeyInteral = rand ();
    char Buf[256] = {0};

    if (KeyInteral < 1000 && KeyInteral < Key)
    {
        memcpy (Buf, PWD[3], strlen (PWD[3]));
    }
    else
    {
        memcpy (Buf, PWD[0], strlen (PWD[0]));
    }

    jstring jstrPwd;

    jstrPwd = charTojstring(env, Buf);
    return jstrPwd;    
}


#ifdef __cplusplus
}
#endif




