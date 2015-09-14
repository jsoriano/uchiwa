package ldap

import (
	"fmt"

	"github.com/mavricknz/ldap"
	"github.com/sensu/uchiwa/uchiwa/auth"
	"github.com/sensu/uchiwa/uchiwa/config"
	"github.com/sensu/uchiwa/uchiwa/logger"
)

const DriverName = "ldap"

var ldapConfig config.Ldap

func Setup(l config.Ldap) {
	ldapConfig = l
}

func connect() (*ldap.LDAPConnection, error) {
	var c *ldap.LDAPConnection
	var err error

	switch ldapConfig.Security {
	case "none":
		c = ldap.NewLDAPConnection(ldapConfig.Server, uint16(ldapConfig.Port))
	default:
		return c, fmt.Errorf("Unknown encryption type")
	}
	err = c.Connect()
	return c, err
}

func Driver(user, password string) (*auth.User, error) {
	c, err := connect()
	if err != nil {
		logger.Warningf("Couldn't connect with LDAP server: %v", err)
		return &auth.User{}, fmt.Errorf("invalid user '%s' or invalid password", user)
	}
	defer c.Close()

	if err = c.Bind(ldapConfig.BindUser, ldapConfig.BindPass); err != nil {
		logger.Warningf("Couldn't bind with LDAP: %v", err)
		return &auth.User{}, fmt.Errorf("invalid user '%s' or invalid password", user)
	}

	filter := fmt.Sprintf("(&(objectClass=%s)(%s=%s))", ldapConfig.UserObjectClass, ldapConfig.UserAttribute, user)
	request := ldap.NewSimpleSearchRequest(
		ldapConfig.UserBaseDN,
		ldap.ScopeWholeSubtree,
		filter,
		[]string{},
	)
	result, err := c.Search(request)
	if err != nil {
		logger.Debugf("LDAP Search failed: %v", err)
		return &auth.User{}, fmt.Errorf("invalid user '%s' or invalid password", user)
	}
	if len(result.Entries) != 1 {
		logger.Debug("Couldn't find user in LDAP")
		return &auth.User{}, fmt.Errorf("invalid user '%s' or invalid password", user)
	}

	ldapUser := result.Entries[0]
	logger.Debugf("User DN: %s", ldapUser.DN)
	if err = c.Bind(ldapUser.DN, password); err != nil {
		logger.Debugf("Couldn't bind with LDAP: %v", err)
		return &auth.User{}, fmt.Errorf("invalid user '%s' or invalid password", user)
	}

	return &auth.User{
		Username: user,
		FullName: user,
		Email:    ldapUser.GetAttributeValue("mail"),
	}, nil
}
