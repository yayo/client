
/*

gcc -O3 -Wall -Wextra -std=c++11 -pthread client.cpp -lstdc++ -lboost_system -lboost_regex -lboost_iostreams -lcrypto -lssl -o client

cat test_2.txt | ./client | md5sum | grep de032b1da0a64c051538eb568f68afba
cat test_3.txt | ./client | wc

*/

#include <cstdlib>
#include <iostream>
#include <boost/bind.hpp>
#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/lexical_cast.hpp>
#include <boost/property_tree/ptree.hpp>
#include <boost/property_tree/json_parser.hpp>
#include <boost/date_time/local_time/local_time.hpp>
#include <boost/algorithm/string.hpp>
#include <boost/algorithm/string/case_conv.hpp>
#include <iterator>
#include <boost/regex.hpp>
#include <boost/iostreams/filtering_streambuf.hpp>
#include <boost/iostreams/filter/gzip.hpp>
#include <boost/iostreams/copy.hpp>

class proxy_t
 {public:
   enum type_t {none=0,http,socks5};
   static const std::map<std::string,type_t> atoi;
   type_t type;
   std::string remote_host;
   uint16_t remote_port;
   proxy_t() : type(none) {}
   proxy_t(const type_t &type,const std::string &remote_host,const uint16_t &remote_port) : type(type),remote_host(remote_host),remote_port(remote_port) {}
 };
const std::map<std::string,proxy_t::type_t> proxy_t::atoi={{"none",none},{"http",http},{"socks5",socks5}};

class smtp_auth_password
 {public:
   std::string password;
 };

class smtp_auth_xoauth2
 {public:
   enum token_type_t {Bearer=1,Mac=2};
   token_type_t token_type;
   std::string access_token;
   time_t expires;
 };

class smtp_auth_xoauth2_refresh : public smtp_auth_xoauth2
 {public:
   std::string url;
   std::string client_id;
   std::string client_secret;
   std::string refresh_token;
 };

class smtp_t : public smtp_auth_password, public smtp_auth_xoauth2_refresh
 {public:
   enum auth_type_t {AUTO=0,PLAIN,LOGIN,XOAUTH2};
   std::string email;
 };

typedef boost::asio::ip::tcp::tcp::socket tcp ;
typedef boost::asio::ssl::stream<boost::asio::ip::tcp::socket> ssl ;

template <class SOCKET,class PROTO> class client;

class http_t
 {public:
   const std::string &method;
   const std::string &path;
   const std::map<std::string,std::string> &request_headers;
   const std::string &request_body;
   http_t(const std::string &method,const std::string &path,const std::map<std::string,std::string> &request_headers,const std::string &request_body) : method(method),path(path),request_headers(request_headers),request_body(request_body) {}
   template <class SOCKET> void write_request(client<SOCKET,http_t>*)const ;
 };

template <class SOCKET,class PROTO> class client
 {private:
   tcp *next_layer=NULL;
   boost::iostreams::gzip_decompressor *gzip=NULL;
   enum return_flag {PASS_END_OF_CONTENT_LENGTH=0x1,CONNECTION_CLOSED_WITHOUT_LENGTH_HINT=0x2,CHUNK_HEAD_SYNC_FAILED=0x4};
   uint64_t return_code=0;
   proxy_t proxy;
   static const boost::regex chunk_head_patten;
   std::map<std::string,std::string> response_headers;
   boost::asio::streambuf response;
   size_t chunk_size;
   uint8_t chunk_body_crlf_pendding_to_read;
   std::ostream response_body;
   std::stringstream json;
   std::streambuf *json_out;
   size_t Transferred_Length;
   const PROTO *http=NULL;
   const PROTO *smtp=NULL;
  public:
   SOCKET *socket;
   ~client() {delete socket; socket=NULL; if(NULL!=gzip) delete gzip; }
   client(SOCKET *socket,boost::asio::ip::tcp::resolver::iterator hosts,const proxy_t &proxy,const PROTO *proto,std::streambuf *out,bool insecure=false) : proxy(proxy),response_body(out),socket(socket)
    {set_proto(proto);
     connect(socket,hosts,insecure);
    }
   void set_proto(const http_t* proto) {http=proto;}
   void set_proto(const smtp_t* proto) {smtp=proto;}
   void connect(tcp *socket,boost::asio::ip::tcp::resolver::iterator hosts,__attribute__((unused)) const bool insecure=true)
    {boost::asio::async_connect(socket->lowest_layer(),hosts,boost::bind(&client::handle_connect,this,boost::asio::placeholders::error));
    }
   void connect(ssl *socket,boost::asio::ip::tcp::resolver::iterator hosts,bool insecure=false)
    {next_layer=&(socket->next_layer());
     if(insecure)
      socket->set_verify_mode(boost::asio::ssl::verify_none);
     else
      {socket->set_verify_mode(boost::asio::ssl::verify_peer);
       socket->set_verify_callback(boost::bind(&client::verify_certificate,this,_1,_2));
      }
     connect(next_layer,hosts,insecure);
    }
    bool verify_certificate(bool preverified,boost::asio::ssl::verify_context& ctx)
     {char subject_name[256];
      X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
      X509_NAME_oneline(X509_get_subject_name(cert), subject_name,256);
      //std::cerr<<"Verifying "<<subject_name<<"\n";
      return(preverified);
     }
    void connect_http_proxy()
     {std::string connect("CONNECT "+proxy.remote_host+':'+boost::lexical_cast<std::string>(proxy.remote_port)+" HTTP/1.1\r\n\r\n");
      std::cerr<<connect;
      boost::asio::async_write(*(NULL==next_layer?(tcp*)socket:next_layer),boost::asio::buffer(connect,connect.size()),boost::bind(&client::handle_write,this,boost::asio::placeholders::error));
     }
    void connect_socks5_proxy()
     {static const char c[]={0x05,0x01,0x00};
       boost::asio::async_write(*(NULL==next_layer?(tcp*)socket:next_layer),boost::asio::buffer(c,sizeof(c)),boost::bind(&client::write_socks5_auth,this,boost::asio::placeholders::error,boost::asio::placeholders::bytes_transferred));
     }
    void write_socks5_auth(const boost::system::error_code &error,size_t bytes_transferred)
     {if(error)
       {std::cerr<<bytes_transferred<<"write_socks5_auth failed:\t"<<error.message()<<"\n";
       }
      else
       {assert(3==bytes_transferred);
        boost::asio::async_read(*(NULL==next_layer?(tcp*)socket:next_layer),response,boost::asio::transfer_at_least(2),boost::bind(&client::read_socks5_auth,this,boost::asio::placeholders::error,boost::asio::placeholders::bytes_transferred));
       }
     }
    void read_socks5_auth(const boost::system::error_code &error,size_t bytes_transferred)
     {if(error)
       {std::cerr<<bytes_transferred<<"read_socks5_auth failed:\t"<<error.message()<<"\n";
       }
      else
       {assert(2==bytes_transferred);
        assert(2==response.in_avail());
        const uint8_t *s=boost::asio::buffer_cast<const uint8_t*>(response.data());
        assert(0x05==s[0]);
        const uint8_t r=s[1];
        response.consume(2);
        uint8_t *c;
        switch(r)
         {case 0x00:
           c=(uint8_t*)alloca(5+proxy.remote_host.size()+2+1);
           memcpy(c,"\x05\x01\x00\x03",4);
           c[4]=(uint8_t)proxy.remote_host.size();
           memcpy(c+5,proxy.remote_host.c_str(),c[4]);
           *(uint16_t*)(c+5+c[4])=htons(proxy.remote_port);
           boost::asio::async_write(*(NULL==next_layer?(tcp*)socket:next_layer),boost::asio::buffer(c,5+c[4]+2),boost::bind(&client::write_socks5_cmd,this,boost::asio::placeholders::error));
           break;
          default:
           std::cerr<<"Unsupported Socks5 Server Authentication:"<<std::hex<<s[1]<<"\n";
         }
       }
     }
    void write_socks5_cmd(const boost::system::error_code &error)
     {if(error)
       {std::cerr<<"write_socks5_cmd failed:\t"<<error.message()<<"\n";
       }
      else
       {boost::asio::async_read(*(NULL==next_layer?(tcp*)socket:next_layer),response,boost::asio::transfer_at_least(4),boost::bind(&client::read_socks5_cmd,this,boost::asio::placeholders::error,boost::asio::placeholders::bytes_transferred));
       }
     }
    void read_socks5_cmd(const boost::system::error_code &error,size_t bytes_transferred)
     {if(error)
       {std::cerr<<bytes_transferred<<"read_socks5_cmd failed:\t"<<error.message()<<"\n";
       }
      else
       {const uint8_t *s=boost::asio::buffer_cast<const uint8_t*>(response.data());
        assert(10==bytes_transferred);
        assert(10==response.in_avail());
        assert(0x05==s[0]);
        assert(0==memcmp("\x00\x01\x00\x00\x00\x00\x00\x00",s+2,8));
        const uint8_t c=s[1];
        response.consume(10);
        if(0x00==c)
         {proxy.type=proxy_t::none;
          after_connected(socket);
         }
        else
         {std::cerr<<"Socks5 Failed:\t";
          static const std::map<uint8_t,std::string> e={ {0x01,"general failure"}, {0x02,"connection not allowed by ruleset"}, {0x03,"network unreachable"}, {0x04,"host unreachable"}, {0x05,"connection refused by destination host"}, {0x06,"TTL expired"}, {0x07,"command not supported or protocol error"}, {0x08,"address type not supported"} };
          std::map<uint8_t,std::string>::const_iterator i=e.find(c);
          std::cerr<<(e.end()==i?"unknown failure":i->second)<<"\n";
         }
       }
     }
    void handle_connect(const boost::system::error_code &error)
     {std::cerr<<socket->lowest_layer().remote_endpoint().address().to_string()<<"\n";
      if(error)
       {std::cerr<<"HTTP Connect failed:\t"<<error.message()<<"\n";
       }
      else
       {switch(proxy.type)
         {default:
           assert(0==proxy.type);
           return;
          case proxy_t::socks5:
           connect_socks5_proxy();
           return;
          case proxy_t::http:
           connect_http_proxy();
           return;
          case proxy_t::none:
           after_connected(socket);
           return;
         }
       }
     }
    void after_connected(ssl *socket)
     {socket->async_handshake(boost::asio::ssl::stream_base::client,boost::bind(&client::handle_handshake,this,boost::asio::placeholders::error));
     }
    void handle_handshake(const boost::system::error_code &error)
     {if(error)
       {std::cerr<<"Handshake failed:\t"<<error.message()<<"\n";
       }
      else
       {after_connected(next_layer);
       }
     }
    void after_connected(__attribute__((unused)) tcp *socket)
     {if(NULL!=http) http->write_request(this);
      if(NULL!=smtp) smtp->write_request(this);
     }
    void handle_write(const boost::system::error_code &error)
     {if(error)
       {std::cerr<<"Writen failed:\t"<<error.message()<<"\n";
       }
      else
       {if(proxy_t::http==proxy.type&&NULL!=next_layer)
         {boost::asio::async_read_until(*next_layer,response,"\r\n",boost::bind(&client::handle_read_status_line,this,boost::asio::placeholders::error));
         }
        else
         {boost::asio::async_read_until(*socket,response,"\r\n",boost::bind(&client::handle_read_status_line,this,boost::asio::placeholders::error));
         }
       }
     }
    void handle_read_status_line(const boost::system::error_code &error)
     {if(error)
       {std::cerr<<"Read Status failed:\t"<<error.message()<<"\n"; /* End of file => C:http <> S:https */
       }
      else
       {std::istream s(&response);
        std::string h;
        std::getline(s,h);
        if(proxy_t::http==proxy.type)
         {if("HTTP/1.0 200 Connection established\r"!=h)
           {std::cerr<<"Proxy Connect Error:\t"<<h<<std::endl;
           }
          else
           {std::getline(s,h);
            assert("\r"==h);
            proxy.type=proxy_t::none;
            after_connected(socket);
           }
         }
        else
         {if("HTTP/1.1 200 OK\r"!=h)
           {std::cerr<<"Status Error:\t"<<h<<std::endl;
           }
          else
           {boost::asio::async_read_until(*socket,response,"\r\n\r\n",boost::bind(&client::handle_read_headers,this,boost::asio::placeholders::error));
           }
         }
       }
     }
    void handle_read_headers(const boost::system::error_code &error)
     {if(error)
       {std::cerr<<"Read Headers failed:\t"<<error.message()<<"\n";
       }
      else
       {std::istream s(&response);
        std::string h;
        for(;std::getline(s,h)&&"\r"!=h;)
         {std::cerr<<h<<std::endl;
          size_t comma=h.find(':');
          assert(':'==h[comma]&&' '==h[comma+1]&&'\r'==h[h.size()-1]);
          /* // save all response headers for consequent requests
          static const std::set<std::string> favorite_headers={ "Content-Encoding", "Content-Length", "Content-Type", "Transfer-Encoding", };
          if(favorite_headers.end()!=favorite_headers.find(h.substr(0,comma)))
          */
           response_headers.insert(std::pair<std::string,std::string>(h.substr(0,comma),h.substr(comma+2,h.size()-comma-2-1)));
         }
        std::cerr<<std::endl;
        std::string t=response_headers.find("Content-Type")->second;
        size_t c=t.find(";");
        if("application/json"==t.substr(0,c)&&(t.size()<=c||boost::regex_match(t.substr(c),boost::regex(".*charset=UTF-{0,1}8.*",boost::regex::icase))))
         {json.str(std::string());
          json_out=response_body.rdbuf();
          response_body.rdbuf(json.rdbuf());
         }
        Transferred_Length=0;
        if("gzip"==response_headers.find("Content-Encoding")->second)
         {gzip=new boost::iostreams::gzip_decompressor();
         }
        if("chunked"==response_headers.find("Transfer-Encoding")->second)
         {chunk_body_crlf_pendding_to_read=0;
          boost::asio::async_read_until(*socket,response,boost::regex("[0-9a-f]{1,}\r\n"),boost::bind(&client::handle_read_chunk_size,this,boost::asio::placeholders::error));
         }
        else
         {boost::asio::async_read(*socket,response,boost::asio::transfer_at_least(1),boost::bind(&client::handle_read_body,this,boost::asio::placeholders::error,boost::asio::placeholders::bytes_transferred));
         }
       }
     }
    void handle_read_chunk_size(const boost::system::error_code &error)
     {if(error)
       {std::cerr<<"Read chunk size failed:\t"<<error.message()<<"\n";
       }
      else
       {assert((3+chunk_body_crlf_pendding_to_read)<=response.in_avail());
        std::istream s(&response);
        switch(chunk_body_crlf_pendding_to_read)
         {default:
           assert(2>=chunk_body_crlf_pendding_to_read);
          case 2:
           assert('\r'==s.get());
           chunk_body_crlf_pendding_to_read--;
          case 1:
           assert('\n'==s.get());
           chunk_body_crlf_pendding_to_read--;
          case 0:;
         }
        char c;
        std::string h;
        std::getline(s,h);
        size_t l;
        assert(2<=h.size()&&2==sscanf(h.c_str(),"%lx%c",&l,&c)&&'\r'==c);
         {if(0!=l)
           {chunk_size=l;
            boost::asio::async_read(*socket,response,boost::asio::transfer_at_least((size_t)response.in_avail()>=chunk_size?0:1),boost::bind(&client::handle_read_chunk_data,this,boost::asio::placeholders::error));
           }
          else
           {s.get(c);
            assert('\r'==c);
            s.get(c);
            assert('\n'==c);
            assert(0==response.in_avail());
            process_body();
           }
         }
       }
     }
    void append_body(size_t size)
     {std::ostreambuf_iterator<char> b(response_body.rdbuf());
      if(NULL==gzip)
       {std::istreambuf_iterator<char> begin(&response);
        std::copy_n(begin,size,b);
         {/* WHY "std::copy_n" does NOT consume the last byte but "std::copy" do ?
            // http://cplusplus.github.io/LWG/lwg-active.html#2471
          begin=std::istreambuf_iterator<char>(&response);
          char c=*begin;
          assert(c==body[body.size()-1]);
          begin++;
          */
         }
       }
      else
       {// WHOLE GZIP BODY
        // {boost::asio::buffers_iterator<boost::asio::streambuf::const_buffers_type> begin = boost::asio::buffers_iterator<boost::asio::streambuf::const_buffers_type>::begin(response.data());
        //  gzip.push(boost::make_iterator_range(begin,begin+size));
        //  boost::iostreams::copy(gzip,back_inserter(body));
        // }
        const char *begin=boost::asio::buffer_cast<const char*>(response.data());
        std::stringstream o;
        gzip->write(o,begin,size);
        std::copy(std::istreambuf_iterator<char>(o.rdbuf()),std::istreambuf_iterator<char>(),b);
        response.consume(size);
       }
      Transferred_Length+=size;

     }
    void handle_read_chunk_data(const boost::system::error_code &error)
     {if(error)
       {std::cerr<<"Read chunk body failed:\t"<<error.message()<<"\n";
       }
      else
       {size_t v=response.in_avail();
        size_t l=(v<chunk_size?v:chunk_size);
        append_body(l);
        if(v<chunk_size)
         {chunk_size-=v;
          boost::asio::async_read(*socket,response,boost::asio::transfer_at_least(1),boost::bind(&client::handle_read_chunk_data,this,boost::asio::placeholders::error));
         }
        else
         {chunk_body_crlf_pendding_to_read=2;
          boost::asio::async_read_until(*socket,response,chunk_head_patten,boost::bind(&client::handle_read_chunk_size,this,boost::asio::placeholders::error));
         }
       }
     }
    void handle_read_body(const boost::system::error_code &error,size_t bytes_transferred)
     {if(error)
       {if(
           0==bytes_transferred
           &&
           (
            (
             boost::asio::error::get_ssl_category()==error.category()
             &&
             ERR_PACK(ERR_LIB_SSL,0,SSL_R_SHORT_READ)==error.value()
            )
            /*
            ||
            (
             response_headers.end()!=response_headers.find("Content-Length")
             &&
             body.size()==boost::lexical_cast<size_t>(response_headers["Content-Length"])
            )
            */
           )
          )
         {process_body();
         }
        else
         {process_body();
          std::cerr<<"Read failed:\t"<<error.message()<<"\n";
         }
       }
      else
       {append_body(response.in_avail());
        if(response_headers.end()!=response_headers.find("Content-Length")&&Transferred_Length>=boost::lexical_cast<size_t>(response_headers["Content-Length"]))
         {if(Transferred_Length>boost::lexical_cast<size_t>(response_headers["Content-Length"]))
           {return_code|=PASS_END_OF_CONTENT_LENGTH;}
          process_body();
         }
        else
         {boost::asio::async_read(*socket,response,boost::asio::transfer_at_least(1),boost::bind(&client::handle_read_body,this,boost::asio::placeholders::error,boost::asio::placeholders::bytes_transferred));
         }
       }
     }
    void process_body()
     {if(0!=json.str().size())
       {boost::property_tree::ptree j;
        boost::property_tree::read_json(json,j);
        if(j.not_found()!=j.find("expires_in"))
         {int64_t e=j.get<int64_t>("expires_in");
          time_t now=time(NULL);
          if(e+60*24*24+2<now)
           {j.put("expires_at",now+e);
            j.erase("expires_in");
           }
         }
        std::ostream o(json_out);
        boost::property_tree::write_json(o,j);
       }
      else
       {//std::cout<<body.rdbuf();
       }
     }

static std::map<std::string,std::string> &parse_headers(std::string in,std::map<std::string,std::string> &out)
 {boost::algorithm::replace_all(in,"\\r","\r");
  boost::algorithm::replace_all(in,"\\n","\n");
  std::vector<std::string> h;
  boost::algorithm::split(h,in,boost::algorithm::is_any_of("\r\n"));
  std::vector<std::string>::const_iterator t;
  for(t=h.begin();t!=h.end();t++)
   {if(4<=t->size())
     {char patten[]=": ";
      size_t p=t->find(patten);
      if(0<p&&p<(t->size()-2))
       {out.insert(std::pair<std::string,std::string>(t->substr(0,p),t->substr(p+sizeof(patten)-sizeof('\0'))));
       }
     }
   }
  return(out);
 }

static std::map<std::string,std::string> &map_headers(const std::string &method,const std::string &host,const uint16_t &port,const std::string &body,std::map<std::string,std::string> &out)
 {std::map<std::string,std::string>::const_iterator i;
  if(out.end()==out.find("Host"))
   out.insert(std::pair<std::string,std::string>("Host",host+':'+boost::lexical_cast<std::string>(port)));
  if(out.end()==out.find("Connection"))
   out.insert(std::pair<std::string,std::string>("Connection","keep-alive"));
  out["Accept-Encoding"]="gzip";
  if("GET"==method) {}
  else if("POST"==method)
   {if(out.end()==out.find("Content-Length"))
     out.insert(std::pair<std::string,std::string>("Content-Length",boost::lexical_cast<std::string>(body.size())));
    if(0!=body.size())
     {if(out.end()==out.find("Content-Type"))
       out.insert(std::pair<std::string,std::string>("Content-Type","application/x-www-form-urlencoded"));
     }
   }
  else {}
  return(out);
 }

 };
template <class SOCKET,class PROTO> const boost::regex client<SOCKET,PROTO>::chunk_head_patten("\r\n[0-9a-f]{1,}\r\n");

template <class SOCKET> void http_t::write_request(client<SOCKET,http_t> *c)const
 {std::string request=method+" "+path+" HTTP/1.1\r\n";
  std::map<std::string,std::string>::const_iterator i;
  for(i=request_headers.begin();i!=request_headers.end();i++) request+=i->first+": "+i->second+"\r\n";
  request+="\r\n"+request_body;
  std::cerr<<request<<"\n";
  boost::asio::async_write(*(c->socket),boost::asio::buffer(request,request.size()),boost::bind(&client<SOCKET,http_t>::handle_write,c,boost::asio::placeholders::error));
 }

int main(int argc,char *argv[])
 {if(1>argc)
   {std::cerr<<argv[0]<<"\n";
    return(-1);
   }
  else
   {try
     {boost::property_tree::ptree j;
      boost::property_tree::read_json(std::cin,j);
      std::map<std::string,std::string> h;
      //std::string proto=j.get<std::string>("proto");
      //boost::algorithm::to_lower(proto);
      const std::string &method=j.get<std::string>("method");
      //http_t http(method);
      std::string host=j.get<std::string>("host");
      uint16_t port=j.get<uint16_t>("port");
      const std::string &path=j.get<std::string>("path");
      std::string body;
      if(j.not_found()!=j.find("body"))
       {body=j.get<std::string>("body");
        j.erase("body");
       }
      // client<void>::parse_headers("",h); // You may process command line HTTP_HEADERS here.
      boost::property_tree::ptree::const_assoc_iterator e;
      e=j.find("headers");
      if(j.not_found()!=e) 
       {const boost::property_tree::ptree &n=e->second;
        if(!n.empty()&&n.data().empty())
         {boost::property_tree::ptree::const_iterator i;
          for(i=n.begin();i!=n.end();i++)
           {h.insert(std::pair<std::string,std::string>(i->first,i->second.data()));
           }
         }
        else if(n.empty()&&!n.data().empty())
         {client<void,void>::parse_headers(n.data(),h);
         }
       }
      client<void,void>::map_headers(method,host,port,body,h);
      proxy_t proxy;
      e=j.find("proxy");
      if(j.not_found()!=e) 
       {std::map<std::string,proxy_t::type_t>::const_iterator i=proxy_t::atoi.find(e->second.get<std::string>("type"));
        if(proxy_t::atoi.end()!=i&&proxy_t::none!=i->second)
         {proxy.type=i->second;
          proxy.remote_host=host;
          proxy.remote_port=port;
          host=e->second.get<std::string>("host");
          port=e->second.get<uint16_t>("port");
         }
       }
      http_t http(method,path,h,body);
      boost::asio::io_service io_service;
      boost::asio::ip::tcp::resolver resolver(io_service);
      boost::asio::ip::tcp::resolver::query *query;
      query=new boost::asio::ip::tcp::resolver::query(host,boost::lexical_cast<std::string>(port));
      boost::asio::ip::tcp::resolver::iterator iterator=resolver.resolve(*query);
      boost::asio::ssl::context *ctx=NULL;
      client<tcp,http_t> *socket_tcp=NULL;
      client<ssl,http_t> *socket_ssl=NULL;
      if(j.get<bool>("ssl"))
       {ctx=new boost::asio::ssl::context(boost::asio::ssl::context::sslv23);
        ctx->load_verify_file("/etc/ssl/certs/ca-certificates.crt");
        socket_ssl=new client<ssl,http_t>((new ssl(io_service,*ctx)),iterator,proxy,&http,std::cout.rdbuf(),false);
       }
      else
       {socket_tcp=new client<tcp,http_t>((new tcp(io_service)),iterator,proxy,&http,std::cout.rdbuf(),true);
       }
      io_service.run();
      if(NULL!=ctx) delete ctx;
      if(NULL!=socket_tcp) delete socket_tcp;
      if(NULL!=socket_ssl) delete socket_ssl;
      delete query;
      return(0);
     }
    catch(std::exception& e)
     {std::cerr<<"Error:\t"<<e.what()<<std::endl;
      return(-4);
     }
   }
 }
