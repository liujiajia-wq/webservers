#include"head.h"
#include"sqlite3.h"
#include <openssl/md5.h>

//创建结构体，用来保存解析完Http请求后提取出来的信息
typedef struct HttpRequest{
    char *pmethod; //指向请求方法字符串（GET/POST）
    char *purl;    //指向访问路径字符串（/index.html）
    char *pcontent; //指向POST提交的表单数据（请求体）
}HttpRequest_t;


//创建监听套接字，负责接受连接
int CreateListenSocket(int pPort)
{
    int sockfd = 0;
    struct sockaddr_in seraddr;
    int ret = 0;

    //创建TCP套接字，拿到fd
    sockfd = socket(AF_INET,SOCK_STREAM,0);
    if (-1 == sockfd)
    {
        perror("fail to socket");
        return -1;
    }

    //绑定8080端口，本机所有网卡上的设备都可以连接
    seraddr.sin_family = AF_INET;
    seraddr.sin_port = htons(pPort);
    seraddr.sin_addr.s_addr = INADDR_ANY;
    ret = bind(sockfd,(struct sockaddr *)&seraddr,sizeof(seraddr));
    if (-1 == ret)
    {
        perror("fail to bind");
        return -1;
    }

    //把socket设置为监听模式
    ret = listen(sockfd,10);
    if (-1 == ret)
    {
        perror("fail to listen");
        return -1;
    }

    return sockfd;
}

//接收浏览器发来的Http请求报文
int RecvHttpRequest(int confd,char *precvbuff,int maxlen)
{
    ssize_t nret;

    nret = recv(confd,precvbuff,maxlen,0);
    if (-1 == nret)
    {
        perror("fail to recv");
        return -1;
    }

    return nret;
}

//解析请求报文，提取请求方法，url路径，请求体内容（POST有请求体，GET无）
int PraseHttpRequest(char *precvbuff,HttpRequest_t *pTmpRequest) 
{
    char *p = NULL;

    p = strstr(precvbuff,"\r\n\r\n");

    if(p != NULL)
    {
        pTmpRequest->pcontent = p + 4;
    }
    else
    {
        pTmpRequest->pcontent = NULL;
    }

    pTmpRequest->pmethod = strtok(precvbuff," ");
    pTmpRequest->purl = strtok(NULL," ");

    return 0;
}

//发送HTTP响应头，根据文件类型告诉浏览器要返回什么数据
int SendHttpResponeHeader(int confd,char *pfilename)
{
    char tmpbuff[4096]={0};
    //定义一个字符串指针 content_type，默认认为服务器要发送的是 UTF-8 编码的 HTML 内容 然后根据文件类型修改它
    char *content_type="text/html; charset=utf-8";
    ssize_t nret;

    //先判断文件是否存在
    if(access(pfilename,F_OK)!=0)
    {
        // 文件不存在，返回404
        sprintf(tmpbuff,
            "HTTP/1.1 404 Not Found\r\n"
            "Server: TinyServer\r\n"
            "Content-Type: text/html; charset=utf-8\r\n"
            "Connection: close\r\n"
            "\r\n");
    }
    else
    {
        // 文件存在，再根据文件后缀判断文件类型
        //如果文件名中包含.jpg或者.jpeg，告诉浏览器这是JPEG图片
        if(strstr(pfilename,".jpg") || strstr(pfilename,".jpeg"))
        {
            content_type="image/jpeg";
        }
        //如果文件名中包含.png，告诉浏览器这是png图片
        else if(strstr(pfilename,".png"))
        {
            content_type="image/png";
        }
         //如果文件名中包含.gif，告诉浏览器这是gif图片
        else if(strstr(pfilename,".gif"))
        {
            content_type="image/gif";
        }

        // 返回200，并告诉浏览器文件类型
        sprintf(tmpbuff,
            "HTTP/1.1 200 OK\r\n"
            "Server: TinyServer\r\n"
            "Content-Type: %s\r\n"
            "Connection: close\r\n"
            "\r\n",
            content_type);
    }

    // 发送HTTP响应头
    nret=send(confd,tmpbuff,strlen(tmpbuff),0);
    if(-1 == nret)
    {
        perror("fail to send");
        return -1;
    }

    return 0;
}

//解析POST登陆表单，提取用户名、密码，加密，查询SQL数据库，校验帐号密码是否正确
int CheckUser(char *pcontent)
{
    char username[64]={0};  //保存解析出来的用户名
    char pwd[64]={0};       //保存用户提交的明文密码
    char md5_pwd[33]={0};   //存放MD5加密后32位的十六进制字符串
    char *p=NULL;

    //在POST数据中寻找Username=
    p=strstr(pcontent,"Username=");
    if(p==NULL)
    {
        printf("CheckUser: Username not found\n");
        return 0;
    }

    p+=strlen("Username=");
    //%63 指最多读取63个字符，还有一位预留给\0,[^&]读到&就停止,&是表单参数分隔符,把用户名存入username数组
    sscanf(p,"%63[^&]",username);

    //解析POST表单，提取密码
    p=strstr(pcontent,"loginPwd=");
    if(p==NULL)
    {
        printf("CheckUser: loginPwd not found\n");
        return 0;
    }
    p+=strlen("loginPwd=");
    //把明文密码存入pwd数组
    sscanf(p,"%63[^&]",pwd);
    printf("CheckUser: username='%s', password='%s'\n",username,pwd);

    //MD5加密明文密码
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((unsigned char *)pwd,strlen(pwd),digest);
    for(int i=0;i<MD5_DIGEST_LENGTH;i++)
    {
        sprintf(&md5_pwd[i*2],"%02x",digest[i]);
    }
    printf("CheckUser: md5 password = %s\n",md5_pwd);

    //打开SQLite数据库
    sqlite3 *db=NULL;
    if(sqlite3_open("./123.db",&db)!=SQLITE_OK)  //打开数据库文件123.db，返回不等于SQLITE_OK代表打开失败
    {
        printf("CheckUser: sqlite3_open failed: %s\n",sqlite3_errmsg(db));
        sqlite3_close(db);
        return 0;
    }

    //打开SQL，查询users表，根据用户名查询记录
    const char *sql="SELECT user_id,user_name,password FROM users WHERE user_name=?;";
    sqlite3_stmt *stmt=NULL;
    int rc=sqlite3_prepare_v2(db,sql,-1,&stmt,NULL);

    if(rc!=SQLITE_OK){
        printf("CheckUser: sqlite3_prepare_v2 failed: %s\n",sqlite3_errmsg(db));
        sqlite3_close(db);
        return 0;
    }

    //绑定参数，执行查询
    sqlite3_bind_text(stmt,1,username,-1,SQLITE_TRANSIENT);
    rc=sqlite3_step(stmt);

    //判断查询结果
    if(rc==SQLITE_ROW){
        const char *db_username=(const char *)sqlite3_column_text(stmt,1);
        const char *db_password=(const char *)sqlite3_column_text(stmt,2);

        printf("CheckUser: database username = %s\n",db_username);
        printf("CheckUser: database password = %s\n",db_password);

        //比较用户输入密码加密后的md5_pwd和数据库存的密码字符串,相等登陆成功，不相等密码错误
        if(strcmp(md5_pwd,db_password)==0)  
        {
            printf("CheckUser: login success\n");
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return 1;
        }
        else printf("CheckUser: password incorrect\n");
    }
    else printf("CheckUser: user not found\n");

    //无论密码错误还是账号不存在，最后都关闭数据库，返回0代表登陆失败
    sqlite3_finalize(stmt);
    sqlite3_close(db);
    return 0;
}

//处理POST注册表单，解析用户名、密码，密码加密，检测新用户是否存在，把新用户插入users数据库表
int RegisterUser(char *pcontent)
{
    char username[64]={0};      //保存解析出来的用户名
    char pwd[64]={0};           //保存用户提交的明文密码
    char md5_pwd[33]={0};       //存放MD5加密后32位的十六进制字符串
    char *p=NULL;

    //在POST数据中寻找Username=
    p=strstr(pcontent,"Username=");
    if(p==NULL) 
    {
        return 0;
    }
    p+=strlen("Username=");
    //%63 指最多读取63个字符，还有一位预留给\0,[^&]读到&就停止,&是表单参数分隔符,把用户名存入username数组
    sscanf(p,"%63[^&\r\n]",username);

    //解析POST表单，提取密码
    p=strstr(pcontent,"loginPwd=");
    if(p==NULL) 
    {
        return 0;
    }
    p+=strlen("loginPwd=");
    //把明文密码存入pwd数组
    sscanf(p,"%63[^&\r\n]",pwd);

    printf("RegisterUser: username='%s', password='%s'\n",username,pwd);

    //MD5加密明文密码
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5((unsigned char *)pwd,strlen(pwd),digest);
    for(int i=0;i<MD5_DIGEST_LENGTH;i++)
    {
        sprintf(&md5_pwd[i*2],"%02x",digest[i]);
    }
    printf("RegisterUser: md5 password = %s\n",md5_pwd);

    //打开SQLite数据库
    sqlite3 *db=NULL;
    int rc=sqlite3_open("./123.db",&db);    //打开数据库文件123.db，打开失败打印错误，关闭数据库返回0
    if(rc!=SQLITE_OK)
    {
        printf("RegisterUser: sqlite3_open failed: %s\n",sqlite3_errmsg(db));
        sqlite3_close(db);
        return 0;
    }
    //检查用户名是否存在
    const char *sql_check="SELECT user_id FROM users WHERE user_name=?;";
    sqlite3_stmt *stmt=NULL;

    rc=sqlite3_prepare_v2(db,sql_check,-1,&stmt,NULL);
    if(rc!=SQLITE_OK)
    {
        printf("RegisterUser: prepare check failed: %s\n",sqlite3_errmsg(db));
        sqlite3_close(db);
        return 0;
    }

    sqlite3_bind_text(stmt,1,username,-1,SQLITE_TRANSIENT);

    if(sqlite3_step(stmt)==SQLITE_ROW)   //用户名存在，释放资源
    {
        printf("RegisterUser: username '%s' already exists\n",username);
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        return 2;
    }
    sqlite3_finalize(stmt);

    //自动生成新用户id
    const char *sql_id="SELECT IFNULL(MAX(user_id),0)+1 FROM users;";
    sqlite3_stmt *id_stmt=NULL;

    rc=sqlite3_prepare_v2(db,sql_id,-1,&id_stmt,NULL);
    if(rc!=SQLITE_OK)
    {
        printf("RegisterUser: prepare user_id failed: %s\n",sqlite3_errmsg(db));
        sqlite3_close(db);
        return 0;
    }

    if(sqlite3_step(id_stmt)!=SQLITE_ROW)
    {
        printf("RegisterUser: get new user_id failed\n");
        sqlite3_finalize(id_stmt);
        sqlite3_close(db);
        return 0;
    }

    int new_user_id=sqlite3_column_int(id_stmt,0);
    sqlite3_finalize(id_stmt);
    printf("RegisterUser: new user_id = %d\n",new_user_id);

    char email[128]={0};
    snprintf(email,sizeof(email),"%s@shop.com",username);

    //构造INSERT插入SQL语句
    const char *sql_insert=
        "INSERT INTO users("
        "user_id,email,user_name,password,question,answer,sex,birthday,"
        "user_money,frozen_money,pay_points,rank_points,address_id,reg_time,"
        "last_login,last_time,last_ip,visit_count,user_rank,is_special,"
        "ec_salt,salt,parent_id,flag,alias,msn,qq,office_phone,"
        "home_phone,mobile_phone,is_validated,credit_line"
        ") VALUES("
        "?,?,?,?,'','',0,'',0,0,0,0,0,?,0,'','0.0.0.0',0,0,0,"
        "'','',0,0,'','','','','','',0,0);";

    sqlite3_stmt *insert_stmt=NULL;

    rc=sqlite3_prepare_v2(db,sql_insert,-1,&insert_stmt,NULL);
    if(rc!=SQLITE_OK)
    {
        printf("RegisterUser: prepare insert failed: %s\n",sqlite3_errmsg(db));
        sqlite3_close(db);
        return 0;
    }

    printf("RegisterUser: SQL parameter count = %d\n",
           sqlite3_bind_parameter_count(insert_stmt));

    //绑定5个参数到INSERT语句
    sqlite3_bind_int(insert_stmt,1,new_user_id);
    sqlite3_bind_text(insert_stmt,2,email,-1,SQLITE_TRANSIENT);
    sqlite3_bind_text(insert_stmt,3,username,-1,SQLITE_TRANSIENT);
    sqlite3_bind_text(insert_stmt,4,md5_pwd,-1,SQLITE_TRANSIENT);
    sqlite3_bind_int64(insert_stmt,5,(sqlite3_int64)time(NULL));

    //执行插入
    rc=sqlite3_step(insert_stmt);

    if(rc!=SQLITE_DONE){
        printf("RegisterUser: insert failed: %s\n",sqlite3_errmsg(db));
        sqlite3_finalize(insert_stmt);
        sqlite3_close(db);
        return 0;
    }

    //注册成功，释放资源返回1
    printf("RegisterUser: user '%s' registered successfully\n",username);

    sqlite3_finalize(insert_stmt);
    sqlite3_close(db);
    return 1;
}

//URL解码，将编码后的字符串还原成原始字符串
void UrlDecode(char *src,char *dest)
{
    char *p=src;
    int i=0;

    while(*p)
    {
        if(*p=='%' && p[1] && p[2])
        {
            char hex[3]={p[1],p[2],'\0'};
            dest[i++]=(char)strtol(hex,NULL,16);
            p+=3;
        }
        else if(*p=='+')
        {
            dest[i++]=' ';
            p++;
        }
        else
        {
            dest[i++]=*p;
            p++;
        }
    }
    dest[i]='\0';
}

//商品搜索，前段网页传入搜索关键词，后端解析，数据库查询
int SearchGoods(int confd,char *pcontent)
{
    char key[128]={0};              //存放URL编码后的原始搜索关键词
    char keyword[128]={0};          //存放解码后的真实中文关键词
    char *p=NULL;                   
    char like_key[256]={0};         //存放SQL模糊查询匹配串
    sqlite3 *db=NULL;
    sqlite3_stmt *stmt=NULL;
    char json[16384]={0};           //最终返回给浏览器的JSON数组字符串
    int rc,count=0;

    //提取搜索关键词
    p=strstr(pcontent,"key=");
    if(p==NULL) 
    {
        return 0;
    }
    p+=4;
    sscanf(p,"%127[^\r\n&]",key);       //提取关键词存入key，遇到&或回车换行符终止
    UrlDecode(key,keyword);             //URL解码，处理中文，空格编码，解码后的真实中文关键词存放keyword

    printf("SearchGoods: key='%s'\n",key);
    printf("SearchGoods: keyword='%s'\n",keyword);

    //构造模糊查询的匹配串，%关键词%代表包含该关键词
    snprintf(like_key,sizeof(like_key),"%%%s%%",keyword);

    //打开数据库
    rc=sqlite3_open("./123.db",&db);
    if(rc!=SQLITE_OK)
    {
        printf("SearchGoods: sqlite3_open failed: %s\n",sqlite3_errmsg(db));
        return 0;
    }

    //构造SELECT查询SQL
    const char *sql=
        "SELECT goods_id,goods_name,shop_price,goods_number,"
        "goods_thumb,original_img "
        "FROM goods "
        "WHERE goods_name LIKE ? "
        "AND is_delete=0 "
        "AND is_on_sale=1 "
        "ORDER BY goods_id;";

    rc=sqlite3_prepare_v2(db,sql,-1,&stmt,NULL);
    if(rc!=SQLITE_OK){
        printf("SearchGoods: prepare failed: %s\n",sqlite3_errmsg(db));
        sqlite3_close(db);
        return 0;
    }
    //绑定参数执行查询
    sqlite3_bind_text(stmt,1,like_key,-1,SQLITE_TRANSIENT);

    strcat(json,"[");

    //循环读取每一行商品记录
    while(sqlite3_step(stmt)==SQLITE_ROW)
    {
        int goods_id=sqlite3_column_int(stmt,0);
        const char *name=(const char *)sqlite3_column_text(stmt,1);
        double price=sqlite3_column_double(stmt,2);
        int number=sqlite3_column_int(stmt,3);
        const char *thumb=(const char *)sqlite3_column_text(stmt,4);
        const char *original=(const char *)sqlite3_column_text(stmt,5);

        if(name==NULL) name="";
        if(thumb==NULL) thumb="";
        if(original==NULL) original="";

        const char *img=thumb[0]!='\0'?thumb:original;

        char item[2048]={0};

        snprintf(item,sizeof(item),
            "%s{\"id\":%d,\"name\":\"%s\",\"price\":%.2f,\"stock\":%d,\"img\":\"%s\"}",
            count>0?",":"",
            goods_id,name,price,number,img);

        strncat(json,item,sizeof(json)-strlen(json)-1);
        count++;
    }

    strcat(json,"]");

    //释放资源数据库
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    char header[1024]={0};

    //构造HTTP响应头，发送给浏览器
    sprintf(header,
        "HTTP/1.1 200 OK\r\n"
        "Server: TinyServer\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        "Connection: close\r\n"
        "\r\n");

    send(confd,header,strlen(header),0);
    send(confd,json,strlen(json),0);

    return 1;
}

//根据商品id，查询单个商品完整详情
int GoodsDetailData(int confd,int goods_id)
{
    sqlite3 *db=NULL;
    sqlite3_stmt *stmt=NULL;
    char header[1024]={0};
    int rc;

    //打开数据库
    rc=sqlite3_open("./123.db",&db);
    if(rc!=SQLITE_OK)
    {
        printf("GoodsDetailData: sqlite3_open failed: %s\n",sqlite3_errmsg(db));
        return 0;
    }

    //按goods_id查询商品
    const char *sql=
        "SELECT goods_id,goods_name,shop_price,goods_number,"
        "goods_sn,goods_thumb,original_img,goods_desc "
        "FROM goods "
        "WHERE goods_id=? AND is_delete=0;";

    rc=sqlite3_prepare_v2(db,sql,-1,&stmt,NULL);
    if(rc!=SQLITE_OK)
    {
        printf("GoodsDetailData: prepare failed: %s\n",sqlite3_errmsg(db));
        sqlite3_close(db);
        return 0;
    }

    sqlite3_bind_int(stmt,1,goods_id);

    //读取数据库一行数据
    char *json=NULL;

    if(sqlite3_step(stmt)==SQLITE_ROW)
    {
        int id=sqlite3_column_int(stmt,0);
        const char *name=(const char *)sqlite3_column_text(stmt,1);
        double price=sqlite3_column_double(stmt,2);
        int stock=sqlite3_column_int(stmt,3);
        const char *sn=(const char *)sqlite3_column_text(stmt,4);
        const char *thumb=(const char *)sqlite3_column_text(stmt,5);
        const char *original=(const char *)sqlite3_column_text(stmt,6);
        const char *desc=(const char *)sqlite3_column_text(stmt,7);

        if(name==NULL) name="";
        if(sn==NULL) sn="";
        if(thumb==NULL) thumb="";
        if(original==NULL) original="";
        if(desc==NULL) desc="";

        const char *img=thumb[0]!='\0'?thumb:original;

        //计算需要的JSON总大小
        size_t len_name=strlen(name);
        size_t len_sn=strlen(sn);
        size_t len_img=strlen(img);
        size_t len_desc=strlen(desc);

        size_t json_size=
            len_name*2+
            len_sn*2+
            len_img*2+
            len_desc*2+
            1024;

        json=(char *)malloc(json_size);

        if(json==NULL)
        {
            printf("GoodsDetailData: malloc failed\n");
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return 0;
        }

        char *p=json;

        p+=sprintf(p,"{\"id\":%d,\"name\":\"",id);

        //循环处理name字符串：JSON转义
        for(const char *q=name;*q;q++)
        {
            if(*q=='"' || *q=='\\')
                *p++='\\';
            else if(*q=='\r' || *q=='\n' || *q=='\t')
            {
                *p++='\\';
                if(*q=='\r') *p++='r';
                else if(*q=='\n') *p++='n';
                else *p++='t';
                continue;
            }
            *p++=*q;
        }

        p+=sprintf(p,"\",\"price\":%.2f,\"stock\":%d,\"sn\":\"",price,stock);

        for(const char *q=sn;*q;q++)
        {
            if(*q=='"' || *q=='\\')
                *p++='\\';
            else if(*q=='\r' || *q=='\n' || *q=='\t')
            {
                *p++='\\';
                if(*q=='\r') *p++='r';
                else if(*q=='\n') *p++='n';
                else *p++='t';
                continue;
            }
            *p++=*q;
        }

        p+=sprintf(p,"\",\"img\":\"");

        for(const char *q=img;*q;q++)
        {
            if(*q=='"' || *q=='\\')
                *p++='\\';
            else if(*q=='\r' || *q=='\n' || *q=='\t')
            {
                *p++='\\';
                if(*q=='\r') *p++='r';
                else if(*q=='\n') *p++='n';
                else *p++='t';
                continue;
            }
            *p++=*q;
        }

        p+=sprintf(p,"\",\"desc\":\"");

        for(const char *q=desc;*q;q++)
        {
            if(*q=='"' || *q=='\\')
                *p++='\\';
            else if(*q=='\r' || *q=='\n' || *q=='\t')
            {
                *p++='\\';
                if(*q=='\r') *p++='r';
                else if(*q=='\n') *p++='n';
                else *p++='t';
                continue;
            }
            *p++=*q;
        }

        *p++='"';
        *p++='}';
        *p='\0';

        printf("GoodsDetailData: goods_id=%d\n",id);
        printf("GoodsDetailData: desc length=%lu\n",(unsigned long)len_desc);
        printf("GoodsDetailData: json length=%lu\n",(unsigned long)strlen(json));
    }
    //如果没有查询到商品（goods_id不存在）
    else
    {
        json=(char *)malloc(3);

        if(json==NULL)
        {
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return 0;
        }

        strcpy(json,"{}");

        printf("GoodsDetailData: goods_id=%d not found\n",goods_id);
    }

    //释放数据库资源
    sqlite3_finalize(stmt);
    sqlite3_close(db);

    //构造HTTP响应头，发送数据
    sprintf(header,
        "HTTP/1.1 200 OK\r\n"
        "Server: TinyServer\r\n"
        "Content-Type: application/json; charset=utf-8\r\n"
        "Connection: close\r\n\r\n");

    send(confd,header,strlen(header),0);
    send(confd,json,strlen(json),0);

    free(json);

    return 1;
}

//接收所有发来的HTTP请求，判断是GET还是POST，再看访问的URL，再决定返回网页？查商品？登陆？注册？
int SendHttpRespone(int confd,HttpRequest_t *pTmpRequest)
{
    char tmpbuff[4096]={0};
    char filename[256]={0};
    int fd=0;
    int ret=0;
    ssize_t nret;

    //处理GET请求
    if(strcmp(pTmpRequest->pmethod,"GET")==0)
    {
        //访问根路径，返回首页index.html
        if(strcmp(pTmpRequest->purl,"/")==0)
        {
            sprintf(filename,"./index.html");
        }
        //网站图标，不用处理，直接返回
        else if(strcmp(pTmpRequest->purl,"/favicon.ico")==0)
        {
            return 0;
        }
        //商品列表页，url前20字节是 /goodslist.html?key=  ,返回商品列表页面
        else if(strncmp(pTmpRequest->purl,"/goodslist.html?key=",20)==0)
        {
            sprintf(filename,"./goodslist.html");
        }
        //商品详情html页面，/goods.html?id=  ，返回商品详情页面
        else if(strncmp(pTmpRequest->purl,"/goods?id=",10)==0)
        {
            sprintf(filename,"./goods.html");
        }
        //获取商品详情JSON数据，url：/goodsdata?id=14,从第14位开始是数字id
        else if(strncmp(pTmpRequest->purl,"/goodsdata?id=",14)==0)
        {
            int goods_id=atoi(pTmpRequest->purl+14);
            return GoodsDetailData(confd,goods_id);
        }
        //搜索商品接口，url = /dosearch？key=  
        else if(strncmp(pTmpRequest->purl,"/doserarch?key=",15)==0)
        {
            char content[512]={0};
            sprintf(content,"key=%s",pTmpRequest->purl+15);
            //调用SearchGoods
            return SearchGoods(confd,content);
        }
        //普通路径，直接把url拼接到前面当地本地文件夹
        else
        {
            sprintf(filename,".%s",pTmpRequest->purl);
        }
    }
    //处理POST请求
    else if(strcmp(pTmpRequest->pmethod,"POST")==0)
    {
        //登陆接口POST/login
        if(strcmp(pTmpRequest->purl,"/login")==0)
        {
            //CheckUser解析content里的帐号密码，校验用户
            ret=CheckUser(pTmpRequest->pcontent);

            if(ret==1)
                sprintf(filename,"./search.html");   //成功登陆跳转搜索页面
            else
                sprintf(filename,"./index.html");    //失败返回主页
        }
        //搜索的POST版本 POST/dosearch
        else if(strcmp(pTmpRequest->purl,"/doserarch")==0)
        {
            return SearchGoods(confd,pTmpRequest->pcontent);
        }
        //注册接口 POST/register
        else if(strcmp(pTmpRequest->purl,"/register")==0)
        {
            //往user表插入用户
            ret=RegisterUser(pTmpRequest->pcontent);
            if(ret==1)          //成功
            {
                sprintf(tmpbuff,
                    "HTTP/1.1 200 OK\r\n"
                    "Server: TinyServer\r\n"
                    "Content-Type: text/plain; charset=utf-8\r\n"
                    "Connection: close\r\n\r\n"
                    "注册成功");

                send(confd,tmpbuff,strlen(tmpbuff),0);
                return 0;
            }
            else if(ret==2)         //用户名存在
            {
                sprintf(tmpbuff,
                    "HTTP/1.1 200 OK\r\n"
                    "Server: TinyServer\r\n"
                    "Content-Type: text/plain; charset=utf-8\r\n"
                    "Connection: close\r\n\r\n"
                    "用户名已存在");

                send(confd,tmpbuff,strlen(tmpbuff),0);
                return 0;
            }
            else        //其他错误
            {
                sprintf(tmpbuff,
                    "HTTP/1.1 500 Internal Server Error\r\n"
                    "Server: TinyServer\r\n"
                    "Content-Type: text/plain; charset=utf-8\r\n"
                    "Connection: close\r\n\r\n"
                    "注册失败");

                send(confd,tmpbuff,strlen(tmpbuff),0);
                return 0;
            }
        }
    }

    //没有被return截走的请求都会走到这里：打开本地html文件,读取内容发给浏览器
    SendHttpResponeHeader(confd,filename);

    fd=open(filename,O_RDONLY);

    if(fd==-1)
    {
        perror("fail to open");
        return -1;
    }

    while(1)
    {
        memset(tmpbuff,0,sizeof(tmpbuff));

        nret=read(fd,tmpbuff,sizeof(tmpbuff));

        if(nret<=0)
            break;

        if(send(confd,tmpbuff,nret,0)==-1)
        {
            perror("fail to send content");
            close(fd);
            return -1;
        }
    }

    close(fd);

    return 0;
}


int main(void)
{
    int sockfd = 0;
    int confd = 0;
    char recvbuff[4096] = {0};
    HttpRequest_t TmpRequest;

    sockfd = CreateListenSocket(8080);

    while(1)
    {
        confd = accept(sockfd,NULL,NULL);

        if (-1 == confd)
        {
            perror("fail to accept");
            return -1;
        }

        /* 每次接收新的 HTTP 请求前清空缓冲区 */
        memset(recvbuff, 0, sizeof(recvbuff));

        int recv_len = RecvHttpRequest(
            confd,
            recvbuff,
            sizeof(recvbuff) - 1
        );

        if (recv_len <= 0)
        {
            close(confd);
            continue;
        }

        /* 确保字符串以 '\0' 结尾 */
        recvbuff[recv_len] = '\0';


        // 把接受的浏览器发来的Http请求报文打印出来
        printf("===============================recv============================\n");
        printf("%s\n",recvbuff);
        printf("===============================================================\n");


        PraseHttpRequest(recvbuff,&TmpRequest);


        SendHttpRespone(confd,&TmpRequest);


        close(confd);
    }

    return 0;
}