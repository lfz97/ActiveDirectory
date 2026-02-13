package ActiveDirectory

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"

	"github.com/go-ldap/ldap/v3"
)

type ActiveDirectory struct {
	domain         string
	ldapUrl        string
	samAccountName string
	bindPwd        string
	conn_p         *ldap.Conn
}

func (ad_ptr *ActiveDirectory) Bind(username string, password string) error {

	//建立ldap连接对象，设置tls为不验证
	DialOption := ldap.DialWithTLSDialer(&tls.Config{InsecureSkipVerify: true}, &net.Dialer{Timeout: time.Duration(3) * time.Second})
	ldap_conn_p, err := ldap.DialURL((*ad_ptr).ldapUrl, DialOption)
	if err != nil {

		return err
	}

	//用账号密码启用连接
	_, err = ldap_conn_p.SimpleBind(&ldap.SimpleBindRequest{
		Username: username + "@" + (*ad_ptr).domain,
		Password: password,
	})
	if err != nil {

		return err
	}
	//更新连接对象到ActiveDirectory结构体
	return nil
}

/*
查询某个用户
samAccountName ：用户名
searchBaseDn：搜索起始Dn
attributes：选定搜索属性
*/
func (ad_ptr *ActiveDirectory) SearchUser(samAccountName string, searchBaseDn string, attributes []string) (*[]SearchResult, error) {

	filter := fmt.Sprintf("(samAccountName=%s)", samAccountName)

	resultObjects_ptr, err := ad_ptr.SearchObject(filter, searchBaseDn, attributes)
	if err != nil {
		return nil, err
	}

	return resultObjects_ptr, nil

}

/*
查询AD对象
filter：ldap search filter语法
searchBaseDn：搜索起始Dn
attributes：选定搜索属性
*/
func (ad_ptr *ActiveDirectory) SearchObject(filter string, searchBaseDn string, attributes []string) (*[]SearchResult, error) {
	//根据filter和attrubutes执行搜索
	Result_ptr, err := (*ad_ptr).conn_p.Search(ldap.NewSearchRequest(searchBaseDn, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, 0, false, filter, attributes, nil))
	if err != nil {
		return nil, err
	}

	resultObjects := []SearchResult{}
	for _, entry := range (*Result_ptr).Entries {

		//定义Object结构体存放搜索到的结果
		//将搜寻结果中Entries的各项属性抽取到UserObject的Attributes map中
		Object := SearchResult{
			//map的零值是nil，而不是空map，所以要显式初始化空map
			Attributes: map[string][]string{},
		}
		Object.DN = (*entry).DN
		for _, attribute := range (*entry).Attributes {
			Object.Attributes[(*attribute).Name] = (*attribute).Values

		}
		resultObjects = append(resultObjects, Object)
	}

	return &resultObjects, nil
}

func (ad_ptr *ActiveDirectory) Close()  {
	(*ad_ptr).conn_p.Close()
	
}



// 初始化AD连接
func Init(domain string, ldapUrl string, samAccountName string, bindPwd string) (*ActiveDirectory, error) {

	AD_ptr := &ActiveDirectory{
		domain:         domain,
		ldapUrl:        ldapUrl,
		samAccountName: samAccountName,
		bindPwd:        bindPwd,
	}
	DialOption := ldap.DialWithTLSDialer(&tls.Config{InsecureSkipVerify: true}, &net.Dialer{Timeout: time.Duration(3) * time.Second})
	ldap_conn_p, err := ldap.DialURL((*AD_ptr).ldapUrl, DialOption)
	if err != nil {

		return nil, err
	}

	//用账号密码启用连接
	_, err = ldap_conn_p.SimpleBind(&ldap.SimpleBindRequest{
		Username: (*AD_ptr).samAccountName + "@" + (*AD_ptr).domain,
		Password: (*AD_ptr).bindPwd})
	if err != nil {

		return nil, err
	}
	//更新连接对象到ActiveDirectory结构体
	(*AD_ptr).conn_p = ldap_conn_p

	return AD_ptr, nil
}
