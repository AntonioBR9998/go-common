package ldap

import (
	"context"
	"fmt"

	"github.com/AntonioBR9998/go-common/errors"
	"github.com/go-ldap/ldap/v3"
	log "github.com/sirupsen/logrus"
)

type RequestData interface {
	Search(ctx context.Context, request ldap.SearchRequest) ([]*ldap.Entry, error)
	GetDNByObjectGUID(ctx context.Context, objectGUID string) (*string, error)
}

// It returns a []*ldap.Entry object
// The filter should be in the format of a valid LDAP filter, for example: "(&(objectClass=user)(whenChanged>=20220101000000.0Z))"
// Controls can be used to add additional options to the search, for example: []ldap.Control{ldap.NewControlString(ldap.ControlTypeMicrosoftShowDeleted, true, "")}
func (c *ldapClient) Search(ctx context.Context, request ldap.SearchRequest) ([]*ldap.Entry, error) {
	log.Infof("Using filter: %s", request.Filter)

	// Checking LDAP connection
	err := c.checkLDAPConnection(ctx)
	if err != nil {
		log.Error("LDAP connection failed: ", err)
		return nil, err
	}

	sr, err := c.conn.Search(&request)
	if err != nil {
		log.Error("LDAP search failed: ", err)
		return nil, err
	}

	allEntries := sr.Entries
	log.Infof("Search total objects: %d", len(allEntries))

	return allEntries, nil
}

func (c *ldapClient) GetDNByObjectGUID(ctx context.Context, objectGUID string) (*string, error) {
	log.Info("Getting DN for objectGUID: ", objectGUID)

	searchRequest := ldap.NewSearchRequest(
		c.Cfg.BaseDN,
		ldap.ScopeWholeSubtree,
		ldap.NeverDerefAliases,
		1,     // max results
		0,     // timeout
		false, // typesOnly
		fmt.Sprintf("(objectGUID=%s)", ldap.EscapeFilter(objectGUID)),
		[]string{"dn"},
		nil,
	)

	// Checking LDAP connection
	err := c.checkLDAPConnection(ctx)
	if err != nil {
		log.Error("LDAP connection failed: ", err)
		return nil, err
	}

	result, err := c.conn.Search(searchRequest)
	if err != nil {
		log.Error("LDAP search failed: ", err)
		return nil, err
	}

	if len(result.Entries) == 0 {
		log.Warn("No entries found for objectGUID = ", objectGUID)
		return nil, errors.NewNotFoundError("objectGUID", objectGUID)
	}

	dn := result.Entries[0].DN
	if dn == "" {
		return nil, errors.NewNotFoundError("objectGUID", objectGUID)
	}

	return &dn, nil
}
