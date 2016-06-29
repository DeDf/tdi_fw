#include"stdio.h"
#include<urlmon.h>
#pragma comment(lib, "urlmon.lib")
#include<iostream>
using namespace std;

int main(void)
{
    HRESULT hRet=URLDownloadToFileA(0,"http://www.baidu.com/img/baidu_sylogo1.gif","baidu.gif",0, NULL);
    if(hRet==S_OK) 
    {
        cout<<"Downloaded Successfully!"<<endl;
    }
    else 
    {
        cout<<"Downloaded Failed!"<<endl;
    }
    return 0;
}